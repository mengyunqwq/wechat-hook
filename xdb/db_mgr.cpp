#include "db_mgr.h"
#include <atomic>
#include <chrono>
#include "xwechat_offsets.h"
#include "SundaySearch.h"
#include "global.h"
#include "tools.h"
#include "MinHook.h"

// ══════════════════════════════════════════════════════════════════
//  数据库句柄登记表（修复"靠扫内存找句柄"的脆弱做法）
//
//  原来：扫内存找"指向 VFS 的指针值"当候选句柄，再用 errcode 验证。
//        实测命中数会在 219 / 225 / 3 之间跳 —— 一跳就一个库都找不到，
//        表现就是"机器人突然不回复了"（收消息依赖数据库轮询）。
//
//  现在：把 sqlite3_api_routines 的 open_v2 换成我们的 detour，
//        微信每打开一个数据库就记下 {句柄 → 文件名}，直接用真实记录。
//        记录为空时仍回退到原来的扫描（保证老库也能发现）。
// ══════════════════════════════════════════════════════════════════
namespace db_registry {
    std::mutex g_mtx;
    std::map<LPVOID, std::string> g_opened;      // 句柄 → 文件名
    typedef int (*open_v2_t)(const char*, sqlite3**, int, const char*);
    open_v2_t g_origOpenV2 = nullptr;
    bool g_installed = false;
    // 置 true 时 searchDatabases 会跳过登记表、强制做一次真实扫描。
    // 用途：getDatabaseHandle 发现某个库不在缓存里时（微信的库是懒加载的）
    //       需要真的重扫一次，不能又被登记表挡住。
    bool g_forceRescan = false;

    // 从完整路径取文件名（如 ...\message_0.db → message_0.db）
    inline std::string baseName(const std::string& p) {
        auto pos = p.find_last_of("\\/");
        return pos == std::string::npos ? p : p.substr(pos + 1);
    }

    // 我们的 open_v2：先调原函数，成功就把句柄记下来
    int detourOpenV2(const char* filename, sqlite3** ppDb, int flags, const char* zVfs) {
        int rc = g_origOpenV2 ? g_origOpenV2(filename, ppDb, flags, zVfs) : 1 /*SQLITE_ERROR*/;
        if (rc == 0 && ppDb != nullptr && *ppDb != nullptr && filename != nullptr && *filename != '\0') {
            std::lock_guard<std::mutex> lg(g_mtx);
            g_opened[(LPVOID)*ppDb] = baseName(std::string(filename));
        }
        return rc;
    }


    // ── 方式三（应该能真正生效）：hook prepare ────────────────────────
    // prepare 是每次查询都必走的路径，因此一定能拿到 sqlite3* 句柄。
    // 拿到句柄后用 db_filename 问出文件名（只对没登记过的句柄做，之后零开销）。
    typedef int (*prepare_t)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
    prepare_t g_origPrepare = nullptr;
    bool g_installedPrepare = false;
    std::map<LPVOID, std::string> g_unknownHandles;   // 查不到文件名的句柄（避免反复查）

    sqlite3_api_routines* g_api = nullptr;

    void noteHandle(sqlite3* db, sqlite3_api_routines* api) {
        if (db == nullptr || api == nullptr || api->db_filename == nullptr) return;
        {
            std::lock_guard<std::mutex> lg(g_mtx);
            if (g_opened.count((LPVOID)db) || g_unknownHandles.count((LPVOID)db)) return;
        }
        const char* fn = api->db_filename(db, "main");   // 第二个参数是连接内的库名（默认库 "main"）
        std::lock_guard<std::mutex> lg(g_mtx);
        if (fn != nullptr && *fn != '\0') {
            g_opened[(LPVOID)db] = baseName(std::string(fn));
        } else {
            g_unknownHandles[(LPVOID)db] = "";   // 记下来，别再查
        }
    }

    int detourPrepare(sqlite3* db, const char* sql, int n, sqlite3_stmt** stmt, const char** tail) {
        int rc = g_origPrepare ? g_origPrepare(db, sql, n, stmt, tail) : 1;
        // 只在成功且句柄未知时才登记（noteHandle 内部会先查表，开销可忽略）
        if (db != nullptr) {
            noteHandle(db, g_api);
        }
        return rc;
    }

    void installPrepare(sqlite3_api_routines* api) {
        if (g_installedPrepare || api == nullptr || api->prepare == nullptr) return;
        g_installedPrepare = true;
        g_api = api;
        MH_STATUS st = MH_Initialize();
        if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) { g_installedPrepare = false; return; }
        void* target = (void*)api->prepare;
        if (MH_CreateHook(target, (LPVOID)&detourPrepare, (LPVOID*)&g_origPrepare) != MH_OK) {
            OutputDebugStringA("[db_registry] MH_CreateHook(prepare) 失败\n");
            g_installedPrepare = false;
            return;
        }
        if (MH_EnableHook(target) != MH_OK) {
            OutputDebugStringA("[db_registry] MH_EnableHook(prepare) 失败\n");
            g_installedPrepare = false;
            return;
        }
        OutputDebugStringA("[db_registry] prepare 钩子已安装（句柄按真实查询记录）\n");
    }

    // ── 方式二（真正生效的那个）：直接 hook open_v2 的函数代码 ──────────
    // 实测：微信核心开库时**不走** API 表（那张表是给扩展用的），
    //       所以改表没用。但 api->open_v2 本身就是"真实函数的地址"，
    //       直接 hook 这段代码即可。用 MinHook（自带指令边界处理，不会把指令截断）。
    bool g_installedCode = false;
    void installCode(sqlite3_api_routines* api) {
        if (g_installedCode || api == nullptr || api->open_v2 == nullptr) return;
        g_installedCode = true;
        MH_STATUS st = MH_Initialize();
        if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
            OutputDebugStringA("[db_registry] MH_Initialize 失败，退回扫描方式\n");
            g_installedCode = false;
            return;
        }
        void* target = (void*)api->open_v2;
        if (MH_CreateHook(target, (LPVOID)&detourOpenV2, (LPVOID*)&g_origOpenV2) != MH_OK) {
            OutputDebugStringA("[db_registry] MH_CreateHook(open_v2) 失败，退回扫描方式\n");
            g_installedCode = false;
            return;
        }
        if (MH_EnableHook(target) != MH_OK) {
            OutputDebugStringA("[db_registry] MH_EnableHook(open_v2) 失败，退回扫描方式\n");
            g_installedCode = false;
            return;
        }
        OutputDebugStringA("[db_registry] open_v2 代码钩子已安装（数据库句柄按真实打开记录）\n");
    }

    // 安装：把 API 表里的 open_v2 指向 detour（表在 .rdata，需要临时改页保护）
    void install(sqlite3_api_routines* api) {
        if (g_installed || api == nullptr || api->open_v2 == nullptr) return;
        g_installed = true;
        g_origOpenV2 = (open_v2_t)api->open_v2;

        DWORD oldProt = 0;
        void** slot = (void**)&api->open_v2;
        if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
            *slot = (void*)&detourOpenV2;
            DWORD tmp = 0;
            VirtualProtect(slot, sizeof(void*), oldProt, &tmp);
            OutputDebugStringA("[db_registry] open_v2 钩子已安装（数据库句柄将按真实打开记录）\n");
        } else {
            OutputDebugStringA("[db_registry] open_v2 钩子安装失败（继续用扫描方式）\n");
            g_origOpenV2 = nullptr;
            g_installed = false;
        }
    }

    // 取一份当前有效的记录（顺便剔除已被关闭的句柄）
    std::map<std::string, LPVOID> snapshot(sqlite3_api_routines* api) {
        std::map<std::string, LPVOID> out;
        std::lock_guard<std::mutex> lg(g_mtx);
        for (auto it = g_opened.begin(); it != g_opened.end(); ) {
            if (api == nullptr || IsBadReadPtr(it->first, sizeof(LPVOID)) || api->errcode(it->first) == SQLITE_MISUSE) {
                it = g_opened.erase(it);      // 已关闭，剔除
                continue;
            }
            out[it->second] = it->first;
            ++it;
        }
        return out;
    }
}


static void codec_get_key(sqlite3CodecGetKey func, sqlite3* db, int index, void** pKey, int* pLen) {
	__try {
		func(db, index, pKey, pLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		//这里输出异常调试信息 
	}
}

namespace xmgr {

	static std::string toHexString(const std::string& str)
	{
		static const char hex[] = "0123456789ABCDEF";
		std::string out;
		out.reserve(str.size() * 2);

		for (size_t i = 0; i < str.size(); ++i)
		{
			out.push_back(hex[(unsigned char)str[i] >> 4]);
			out.push_back(hex[(unsigned char)str[i] & 0x0F]);
		}
		return out;
	}

	DatabaseMgr::DatabaseMgr() {
		size_t module_base = (size_t)g_hWeixinDll;
		m_sqlite3Rountines = (sqlite3_api_routines*)(module_base + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
		m_sqlcipherRountines = (sqlcipher_api_routines*)(module_base + XWECHAT_SQLCIPHER_API_ROUTINES_OFFSET);
		m_codecGetKey = (sqlite3CodecGetKey)(module_base + XWECHAT_SQLITE3_CODEC_GET_KEY_FUNC);
		// 安装 open_v2 钩子：以后微信打开的每个数据库都会被登记（见文件开头 db_registry）。
		// 这样就不必再靠"扫内存找指针值"——那种方式实测命中数会从 219 跳到 3，一跳就全废。
		db_registry::install(m_sqlite3Rountines);        // 改 API 表（对走扩展的库有效）
		db_registry::installCode(m_sqlite3Rountines);    // 直接 hook 函数代码（主路径）
		db_registry::installPrepare(m_sqlite3Rountines); // hook prepare：每次查询必走，最可靠
		LPVOID patchAddress = (LPVOID)((size_t)m_sqlite3Rountines->backup_init + 0xAD);
		std::vector<BYTE> nopData(14, 0x90);
		m_backupAsmCode.resize(nopData.size(), 0);
		ReadProcessMemory(GetCurrentProcess(), patchAddress, m_backupAsmCode.data(), m_backupAsmCode.size(), nullptr);
		WriteProcessMemory(GetCurrentProcess(), patchAddress, (LPCVOID)nopData.data(), nopData.size(), 0);
	}

	DatabaseMgr::~DatabaseMgr() {
		if (m_sqlite3Rountines != nullptr && m_backupAsmCode.size() != 0) {
			LPVOID patchAddress = (LPVOID)((size_t)m_sqlite3Rountines->backup_init + 0xAD);
			WriteProcessMemory(GetCurrentProcess(), patchAddress, (LPCVOID)m_backupAsmCode.data(), m_backupAsmCode.size(), 0);
			m_backupAsmCode.resize(0);
		}
	}

	nlohmann::ordered_json DatabaseMgr::execute(sqlite3* db, const std::string& sql)
	{
		nlohmann::ordered_json rdata = { {"status",0},{"desc",""} };
		if (db == nullptr) {
			rdata["status"] = -1;
			rdata["desc"] = "input db handle is nullptr";
			return rdata;
		}
		sqlite3_stmt* stmt = nullptr;
		int rc = m_sqlite3Rountines->prepare((LPVOID)db, sql.c_str(), -1, &stmt, 0);
		if (rc != SQLITE_OK) {
			rdata["status"] = rc;
			rdata["desc"] = format_string("execute %s failed", "sqlite3_prepare");
			return rdata;
		}
		nlohmann::ordered_json items = nlohmann::ordered_json::array();
		while (m_sqlite3Rountines->step(stmt) == SQLITE_ROW)
		{
			int col_count = m_sqlite3Rountines->column_count(stmt);
			nlohmann::ordered_json item;
			for (int i = 0; i < col_count; i++)
			{
				const char* ColName = m_sqlite3Rountines->column_name(stmt, i);
				int nType = m_sqlite3Rountines->column_type(stmt, i);
				const void* pReadBlobData = m_sqlite3Rountines->column_blob(stmt, i);
				int nLength = m_sqlite3Rountines->column_bytes(stmt, i);
				std::string key(ColName);
				std::string value;
				switch (nType)
				{
				case SQLITE_BLOB:
				{
					value = toHexString(std::string((char*)pReadBlobData, nLength));
					break;
				}
				default:
				{
					value = std::string((char*)pReadBlobData, nLength);
					break;
				}
				}
				item[key] = value;
			}
			items.push_back(item);
		}
		m_sqlite3Rountines->finalize(stmt);
		rdata["data"] = items;
		return rdata;
	}

	nlohmann::ordered_json DatabaseMgr::execute(const std::string& dbname, const std::string& sql)
	{
		nlohmann::ordered_json rdata = { {"status",0},{"desc",""} };
		LPVOID dbHandle = getDatabaseHandle(dbname);
		if (dbHandle == nullptr) {
			rdata["status"] = -1;
			rdata["desc"] = format_string("get database handle which named %s failed", dbname);
			return rdata;
		}
		rdata = execute((sqlite3*)dbHandle, sql);
		return rdata;
	}

	std::string DatabaseMgr::codec_get_key(const std::string& dbname) {
		LPVOID dbHandle = getDatabaseHandle(dbname);
		if (dbHandle == nullptr)
			return "";
		return codec_get_key((sqlite3*)dbHandle);
	}

	std::string DatabaseMgr::codec_get_key(sqlite3* db) {
		char* pKey = nullptr;
		int iLen = 0;
		std::string szKey;
		return szKey;
		if (m_codecGetKey == nullptr)
			return szKey;
		nlohmann::ordered_json queryResult = execute(db, std::string("PRAGMA cipher_store_pass"));
		if (queryResult["data"][0]["cipher_store_pass"] == 0) {
			return szKey;
		}
		::codec_get_key(m_codecGetKey, db, 0, (void**)&pKey, &iLen);
		if (pKey == nullptr)
			return szKey;
		szKey = std::string(pKey, iLen);
		return szKey;
	}

	void DatabaseMgr::backup_xprogress(int remaining, int pagecount) {
		//LL_DEBUG("backup process: %d/%d\n", pagecount - remaining, pagecount);
		//OutputDebugStringA("[backup process]\n");
	}

	int DatabaseMgr::backup(sqlite3* db, const std::string& out_path)
	{
		int rc = SQLITE_OK;
		if (db == nullptr) {
			return -1;
		}
		sqlite3* pNewDbHandle = nullptr;
		sqlite3_backup* pBackupHandle = nullptr;
		rc = m_sqlite3Rountines->open(out_path.c_str(), &pNewDbHandle);
		if (rc == SQLITE_OK) {
			pBackupHandle = m_sqlite3Rountines->backup_init(pNewDbHandle, (const char*)"main", db, (const char*)"main");
			if (pBackupHandle) {
				do {
					rc = m_sqlite3Rountines->backup_step(pBackupHandle, 5);
					backup_xprogress(
						m_sqlite3Rountines->backup_remaining(pBackupHandle),
						m_sqlite3Rountines->backup_pagecount(pBackupHandle)
					);
					if (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
						m_sqlite3Rountines->sleep(50);
					}
				} while (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
				(void)m_sqlite3Rountines->backup_finish(pBackupHandle);
			}
			rc = m_sqlite3Rountines->errcode(pNewDbHandle);
		}
		(void)m_sqlite3Rountines->close(pNewDbHandle);
		return rc;
	}

	int DatabaseMgr::backup(const std::string& dbname, const std::string& out_path)
	{
		int rc = SQLITE_OK;
		sqlite3* pExistDbHandle = (sqlite3*)getDatabaseHandle(dbname);
		if (pExistDbHandle == nullptr) {
			return -1;
		}
		return backup(pExistDbHandle, out_path);
	}

	const std::map<std::string, LPVOID>& DatabaseMgr::searchDatabases() {
		std::lock_guard<std::mutex> lg(m_searchDbMtx);
		// ── 修复上游 bug ──────────────────────────────────────────────
		// 原版：if (!g_IsLogin) { m_dbs.clear(); return m_dbs; }
		// 但全项目**没有任何地方把 g_IsLogin 置 1**（AfterLoginInitThread 定义了却从未被调用），
		// 于是 QueryDB 永远返回空 —— 表现就是 GetAllDBName 返回 []、
		// execute 报 "get database handle which named MicroDB.db failed"。
		// 改成自愈：不靠这个标志，直接扫描；扫到数据库就反推"已登录"。
		if (m_dbs.size() > 0) {
			for (auto& it : m_dbs) {
				if (!IsReadableRegion(it.second, 0x1000) || m_sqlite3Rountines->errcode(it.second) == SQLITE_MISUSE) {
					m_dbs.clear();
					break;
				}
			}
			if (m_dbs.size() > 0) {
				g_IsLogin = 1;      // 句柄还有效 → 已登录
				return m_dbs;
			}
		}
		// ── 优先：用 open_v2 钩子登记的真实句柄 ──────────────────────
		// 这条路不依赖任何内存布局假设，稳定得多（原扫描方式实测命中数会从 219 跳到 3）。
		{
			std::map<std::string, LPVOID> reg = db_registry::snapshot(m_sqlite3Rountines);
			if (!reg.empty() && !db_registry::g_forceRescan) {
				m_dbs = reg;
				g_IsLogin = 1;
				OutputDebugStringA("[db_mgr] 用 open_v2 登记表拿到数据库列表\n");
				return m_dbs;
			}
		}

		// ── 兜底：登记表为空（钩子没装上，或库都是钩子安装前打开的）→ 走原来的扫描 ──
		std::vector<LPVOID> results;
		size_t vfs_addr = (size_t)g_hWeixinDll + XWECHAT_SQLITE3_VFS_OFFSET;
		ScanPattern(GetCurrentProcess(), (BYTE*)&vfs_addr, sizeof(LPVOID), results);
		for (size_t i = 0; i < results.size(); i++) {
			auto result = results[i];
			// 只探测一个指针大小远远不够：sqlite 会深入解引用，假句柄会踩到未映射页
			if (IsReadableRegion(result, 0x1000)) {
				int rc = m_sqlite3Rountines->errcode(result);
				if (rc == SQLITE_OK) {
					nlohmann::ordered_json queryResult = execute(result, "PRAGMA database_list");
					// 加固：候选句柄里大多数不是真数据库，data 可能是空数组/null，
					// 原来直接 ["data"][0]["file"].get<string>() 会抛异常，把整个扫描打断。
					if (!queryResult.contains("data") || !queryResult["data"].is_array() || queryResult["data"].empty())
						continue;
					auto& row = queryResult["data"][0];
					if (!row.contains("file") || !row["file"].is_string())
						continue;
					std::string dbpath = row["file"].get<std::string>();
					if (dbpath.empty())
						continue;
					auto pos = dbpath.find_last_of("\\");
					std::string dbname = dbpath.substr(pos + 1);
					m_dbs[dbname] = result;
				}
			}
		}
		// 扫到任何数据库就说明已经登录了（自愈，见上面的说明）
		if (m_dbs.size() > 0) {
			g_IsLogin = 1;
			// 把扫描结果补进登记表：下次直接命中，不用再扫
			{
				std::lock_guard<std::mutex> lg(db_registry::g_mtx);
				for (auto& kv : m_dbs) db_registry::g_opened[kv.second] = kv.first;
			}
		}
		return m_dbs;
	}

	LPVOID DatabaseMgr::getDatabaseHandle(const std::string& dbname)
	{
		auto& dbs = searchDatabases();
		if (m_dbs.find(dbname) != m_dbs.end())
			return m_dbs[dbname];

		// 微信的数据库是**懒加载**的：message_0.db 只有在收发过消息之后才会被打开。
		// 首次扫描时它还不存在，缓存里自然没有 → 原来这里直接返回 nullptr，
		// 结果"轮询收消息"永远起不来。改为：找不到就清缓存重扫一次。
		// 重扫是**全内存扫描**（较慢），所以做 30 秒节流，避免被高频调用时反复扫。
		static std::atomic<long long> lastRescan{ 0 };
		long long now = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count();
		long long prev = lastRescan.load();
		if (now - prev > 30000 && lastRescan.compare_exchange_strong(prev, now)) {
			OutputDebugStringA("[db_mgr] 缓存里没有目标库，触发重扫\n");
			m_dbs.clear();
			// 关键：强制走真实扫描 —— 否则会被"登记表"挡住，永远发现不了新打开的库
			db_registry::g_forceRescan = true;
			searchDatabases();
			db_registry::g_forceRescan = false;
			if (m_dbs.find(dbname) != m_dbs.end())
				return m_dbs[dbname];
		}
		return nullptr;
	}

	nlohmann::ordered_json DatabaseMgr::getDatabaseInfo() {
		nlohmann::ordered_json jdbs = nlohmann::ordered_json::array();
		// 原版这里有 if (!g_IsLogin) return jdbs; —— 但 g_IsLogin 永远为 0，
		// 首次调用必然返回空。去掉这个门（扫描本身会判断有没有数据库）。

		//OutputDebugStringA("[getDatabaseInfo] 用户已登录\n");

		m_dbs.clear();
		auto& dbs = searchDatabases();
		for (auto& db : dbs) {
			nlohmann::json jdb = { {"dbName",db.first},{"dbHandle",(size_t)db.second} };
			
			//std::string debugMsg = "[getDatabaseInfo] dbName " + db.first + "\n";
			//OutputDebugStringA(debugMsg.c_str());

			// jdb["dbKey"] = codec_get_key(db.second);
			jdbs.push_back(jdb);
		}
		return jdbs;
	}
}