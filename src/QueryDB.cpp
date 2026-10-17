#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include "tools.h"
#include "global.h"
#include "db_mgr.h"
#include "SundaySearch.h"

#include "QueryDB.h"
#include "wx_send.h"


using json = nlohmann::json;

// ── 调试辅助（用 IsBadReadPtr 守卫，不用 SEH：__try 不能和带析构的 C++ 对象共存）──
static size_t SafeModuleSize(size_t base)
{
    if (IsBadReadPtr((LPVOID)base, sizeof(IMAGE_DOS_HEADER))) return 0;
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (IsBadReadPtr((LPVOID)(base + dos->e_lfanew), sizeof(IMAGE_NT_HEADERS))) return 0;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

static int SafeCountPtrsInModule(size_t base, size_t modSize, uint64_t* out8)
{
    const size_t addr = base + XWECHAT_SQLITE3_API_ROUTINES_OFFSET;
    if (IsBadReadPtr((LPVOID)addr, 8 * sizeof(void*))) return -1;
    auto** p = (void**)addr;
    int inMod = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t v = (uint64_t)p[i];
        out8[i] = v;
        if (modSize && v > base && v < base + modSize) inMod++;
    }
    return inMod;
}

// ScanPattern 内部用 ReadProcessMemory（读不了就跳过），本身是安全的
static int SafeScanHits(size_t base)
{
    std::vector<LPVOID> hits;
    size_t vfsVal = base + XWECHAT_SQLITE3_VFS_OFFSET;
    ScanPattern(GetCurrentProcess(), (BYTE*)&vfsVal, sizeof(LPVOID), hits);
    return (int)hits.size();
}
//static xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();

static std::string BytesToHex(const uint8_t* data, size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);

    for (size_t i = 0; i < len; ++i)
    {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}


void Route_QueryDB(httplib::Server& svr)
{
    svr.Post("/QueryDB/execute", [](const httplib::Request& req, httplib::Response& res)
        {
            json reqJson;
            json resp;

            try
            {
                reqJson = json::parse(req.body);
            }
            catch (...)
            {
                resp["ret"] = -1;
                resp["msg"] = "invalid json";
                res.set_content(resp.dump(), "application/json");
                return;
            }


            //初始化数据库管理器
            //OutputDebugStringA("[QueryDB] 初始化数据库管理器\n");
            xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");


            std::string optDbName = reqJson.value("optDbName", "");         // MicroMsg.db
            std::string sql = reqJson.value("SQL", "");                     // 查询语句   SELECT * FROM ChatRoom LIMIT 10

            auto result = g_dbMgr.execute(optDbName, sql);


            // 使用临界区保护数据库访问
            /*
            EnterCriticalSection(&g_dbMgrCriticalSection);
            try {
                auto start = std::chrono::high_resolution_clock::now();
                auto result = g_dbMgr.execute(optDbName, sql);
                auto end = std::chrono::high_resolution_clock::now();

                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                resp["ret"] = result.value("status", 0);
                resp["msg"] = result.value("desc", "");
                resp["data"] = result.value("data", json::array());
                resp["duration_ms"] = duration.count();

                // 慢查询日志
                if (duration.count() > 1000) {
                    OutputDebugStringA(format_string("Slow query: %lldms - %s", duration.count(), sql.substr(0, 100)).c_str());
                }

            }
            catch (const std::exception& e) {
                resp["ret"] = -500;
                resp["msg"] = std::string("Database error: ") + e.what();
            }
            LeaveCriticalSection(&g_dbMgrCriticalSection);
            */


            res.set_content(result.dump(4, ' ', false), "application/json");


            //res.set_content(resp.dump(), "application/json");
        });
    svr.Post("/QueryDB/GetAllDBName", [](const httplib::Request& req, httplib::Response& res)
        {
            json reqJson;
            json resp;

            try
            {
                reqJson = json::parse(req.body);
            }
            catch (...)
            {
                resp["ret"] = -1;
                resp["msg"] = "invalid json";
                res.set_content(resp.dump(), "application/json");
                return;
            }


            //初始化数据库管理器
            //OutputDebugStringA("[QueryDB] 初始化数据库管理器\n");
            xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");

            // 方式2：获取所有数据库信息
            auto dbInfo = g_dbMgr.getDatabaseInfo();
            // 返回：{"dbName":"MicroMsg.db","dbHandle":140736870540544}

            res.set_content(dbInfo.dump(4, ' ', false), "application/json");


            //res.set_content(resp.dump(), "application/json");
        });

    // 添加状态查询接口
    svr.Get("/QueryDB/status", [](const httplib::Request&, httplib::Response& res) {
        json resp;
        resp["IsLogin"] = g_IsLogin;
        resp["hWeixin"] = (uint64_t)g_hWeixinDll;
        res.set_content(resp.dump(4, ' ', false), "application/json");
        });

    // ── 调试路由：判断偏移对不对、扫描能不能命中 ──────────────────
    // 用来定位 "GetAllDBName 返回 []" 的根因：是偏移错了，还是扫描没命中，
    // 还是客户端根本没打开数据库。
	// 结构体布局自动校验报告（发送路径的 TextMessage / WeixinString）
	// 布局一旦被微信改掉，这里会显示 probeOk=false / liveOk=false，便于第一时间发现。
	svr.Get("/Debug/StructCheck", [](const httplib::Request&, httplib::Response& res) {
		res.set_content(WeixinSend::StructCheckReportJson(), "application/json");
		});

    svr.Get("/QueryDB/debug", [](const httplib::Request&, httplib::Response& res) {
        json j;
        const size_t base = (size_t)g_hWeixinDll;
        j["base"] = (uint64_t)base;
        j["IsLogin"] = g_IsLogin;

        const size_t modSize = SafeModuleSize(base);
        j["module_size"] = (uint64_t)modSize;

        // ① 校验 sqlite3_api_routines 偏移：结构体开头是一串函数指针，
        //    偏移正确的话它们应该全部落在 Weixin.dll 代码段内。
        const size_t rtAddr = base + XWECHAT_SQLITE3_API_ROUTINES_OFFSET;
        j["api_routines_addr"] = (uint64_t)rtAddr;
        uint64_t ptrs[8] = { 0 };
        const int inMod = SafeCountPtrsInModule(base, modSize, ptrs);
        json jp = json::array();
        for (int i = 0; i < 8; i++) jp.push_back(ptrs[i]);
        j["api_first_ptrs"] = jp;
        j["api_ptrs_in_module"] = inMod;          // 期望 8

        // ② VFS 偏移处的值
        const size_t vfsAddr = base + XWECHAT_SQLITE3_VFS_OFFSET;
        j["vfs_addr"] = (uint64_t)vfsAddr;
        j["vfs_value"] = IsBadReadPtr((LPVOID)vfsAddr, sizeof(void*)) ? 0 : (uint64_t)*(void**)vfsAddr;

        // ③ 实跑一遍扫描，看命中多少候选
        j["scan_hits"] = SafeScanHits(base);

        // ③b 逐个候选查详情：是假命中，还是真句柄但取不到数据库名
        {
            json detail = json::array();
            auto* rt = xmgr::DatabaseMgr::getInstance().getSqlite3Rountines();
            std::vector<LPVOID> hits;
            size_t vfsVal = base + XWECHAT_SQLITE3_VFS_OFFSET;
            ScanPattern(GetCurrentProcess(), (BYTE*)&vfsVal, sizeof(LPVOID), hits);
            int n = 0;
            for (auto h : hits) {
                if (n++ >= 8) break;
                json d;
                d["handle"] = (uint64_t)h;
                const bool bad = IsBadReadPtr(h, sizeof(void*)) != 0;
                d["bad_ptr"] = bad;
                if (!bad && rt) {
                    d["errcode"] = rt->errcode(h);
                    sqlite3_stmt* stmt = nullptr;
                    int rc = rt->prepare(h, "PRAGMA database_list", -1, &stmt, 0);
                    d["prepare_rc"] = rc;
                    if (rc == SQLITE_OK && stmt) {
                        json rows = json::array();
                        int guard = 0;
                        while (rt->step(stmt) == SQLITE_ROW && guard++ < 20) {
                            const unsigned char* t0 = rt->column_text(stmt, 0);
                            const unsigned char* t1 = rt->column_text(stmt, 1);
                            rows.push_back(std::string(t0 ? (const char*)t0 : "") + "|" + std::string(t1 ? (const char*)t1 : ""));
                        }
                        rt->finalize(stmt);
                        d["rows"] = rows;
                    }
                }
                detail.push_back(d);
            }
            j["scan_detail"] = detail;
        }

        // ④ 扫描结果里的数据库
        j["dbs"] = xmgr::DatabaseMgr::getInstance().getDatabaseInfo();
        res.set_content(j.dump(2, ' ', false), "application/json");
        });


}
