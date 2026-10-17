#include "db_mgr.h"
#include <atomic>
#include <chrono>
#include <set>
#include <string>
#include <cstring>
#include <cstdio>
#include <intrin.h>   // _ReturnAddress()：识别 SQL 入口的调用来源
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

    // 探针前置声明（实现在下面的 probe 命名空间里，这里只是让 open_v2 detour 能用）
    namespace probe { inline void onOpen(const char* filename, int rc, void* db); }

    // 我们的 open_v2：先调原函数，成功就把句柄记下来
    int detourOpenV2(const char* filename, sqlite3** ppDb, int flags, const char* zVfs) {
        int rc = g_origOpenV2 ? g_origOpenV2(filename, ppDb, flags, zVfs) : 1 /*SQLITE_ERROR*/;
        if (rc == 0 && ppDb != nullptr && *ppDb != nullptr && filename != nullptr && *filename != '\0') {
            std::lock_guard<std::mutex> lg(g_mtx);
            g_opened[(LPVOID)*ppDb] = baseName(std::string(filename));
        }
        // 探针：记录"这个 sqlite 实例打开过哪些库"（封顶 100 行）。
        // 用途：判断 message_0.db 是不是同一个实例打开的 —— 这是区分"入口不同"和"另一个实例"的关键。
        probe::onOpen(filename, rc, (ppDb != nullptr) ? (void*)*ppDb : nullptr);
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

    // ══════════════════════════════════════════════════════════════════
    //  探针（第一轮：只观察不接管；第二轮：广谱 + 多入口 + 来源识别）
    //
    //  第一轮实测结论：消息写库**不经过** api->prepare（sqlite3_prepare_v2）——
    //  PROBE-MSG / PROBE-WRITE 都是 0 条，但 prepare 钩子确实活着。
    //  第二轮要回答：写库到底走哪个 SQL 入口，还是根本是另一个 sqlite 实例。
    //
    //  因此第二轮加三件事：
    //    ① 调用来源识别（self=我们自己的 QueryDB / wx=Weixin.dll / other）。
    //       没有这个，广谱日志根本读不了：bridge 轮询**本身就在查 message_0.db 的 Msg_ 表**
    //       （`SELECT name FROM sqlite_master ... LIKE 'Msg_%'`、
    //        `SELECT MAX(local_id) FROM Msg_xxx`、`SELECT ... FROM Msg_xxx ORDER BY local_id`），
    //       所以"看到 SELECT ... Msg_"极可能是我方流量，不能当成"微信在读消息表"。
    //    ② 广谱特征：前 40 条互不相同的语句（不管类型），带来源 + 入口名 + 目标表。
    //    ③ 补齐其它 SQL 入口：prepare16_v2 / prepare_v3 / prepare16_v3 / exec
    //       —— 全部来自同一张 g_api 表（sqlite3.h:164/336/338/146），同一套 MinHook 手法。
    //       exec 内部会调 prepare_v2（SQLite legacy.c），所以 exec 与 prepare 会各记一行，属正常。
    //
    //  约束不变：不拦截、不改 rc/出参/控制流、不阻塞。
    //  未命中路径的成本：一次 _ReturnAddress + 一次计数器自增 + O(1) 首词读取。
    // ══════════════════════════════════════════════════════════════════
    namespace probe {

        enum class Kw { Other, Insert, Update, Delete, Replace };

        // 日志出口：OutputDebugStringA + 追加到 <Weixin.exe 所在目录>\hook-probe.log
        inline void sink(const std::string& line) {
            OutputDebugStringA(line.c_str());
            static std::mutex logMtx;
            static HANDLE hLog = INVALID_HANDLE_VALUE;
            static bool logTried = false;      // 开不了就只试一次，别每次重试
            std::lock_guard<std::mutex> lg(logMtx);
            if (hLog == INVALID_HANDLE_VALUE) {
                if (logTried) return;
                logTried = true;
                std::string path = "D:\\wxhook\\hook-probe.log";
                char exe[MAX_PATH] = { 0 };
                if (GetModuleFileNameA(nullptr, exe, MAX_PATH) > 0) {
                    std::string s(exe);
                    auto p = s.find_last_of("\\/");
                    if (p != std::string::npos) path = s.substr(0, p + 1) + "hook-probe.log";
                }
                hLog = CreateFileA(path.c_str(), FILE_APPEND_DATA,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hLog == INVALID_HANDLE_VALUE) return;
                DWORD w = 0;
                std::string hdr = "[probe] ---- session ---- log file = " + path + "\r\n";
                WriteFile(hLog, hdr.data(), (DWORD)hdr.size(), &w, nullptr);
            }
            DWORD w = 0;
            WriteFile(hLog, line.data(), (DWORD)line.size(), &w, nullptr);
        }

        inline std::string stamp() {
            SYSTEMTIME st;
            GetLocalTime(&st);
            char b[64];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "%02d:%02d:%02d.%03d",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            return std::string(b);
        }

        inline std::string clip(const char* s, int len, size_t cap) {
            if (s == nullptr) return "<null>";
            std::string t(s, len < 0 ? strlen(s) : (size_t)len);
            if (t.size() > cap) {
                t.resize(cap);
                t += "...<truncated>";
            }
            return t;
        }

        // ── 调用来源识别 ────────────────────────────────────────────────
        // 我们自己的模块范围 / Weixin.dll 范围，在 arm() 里一次性算好，
        // 热路径上只读这几个全局（无锁、无 API 调用）。
        uint64_t g_selfBase = 0, g_selfEnd = 0, g_wxBase = 0, g_wxEnd = 0;

        inline uint64_t peImageSize(uint64_t base) {
            if (base == 0 || IsBadReadPtr((LPVOID)base, sizeof(IMAGE_DOS_HEADER))) return 0;
            auto dos = (IMAGE_DOS_HEADER*)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
            uint64_t ntAddr = base + (uint64_t)dos->e_lfanew;
            if (IsBadReadPtr((LPVOID)ntAddr, sizeof(IMAGE_NT_HEADERS))) return 0;
            auto nt = (IMAGE_NT_HEADERS*)ntAddr;
            if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
            return (uint64_t)nt->OptionalHeader.SizeOfImage;
        }

        // caller = detour 入口处的 _ReturnAddress()（MinHook 用 jmp 进入 detour，
        // 所以栈上的返回地址就是"原来那个调用者"）。off：self/wx 时是模块内偏移。
        inline const char* callerClass(void* caller, uint64_t& off) {
            uint64_t a = (uint64_t)caller;
            if (g_selfEnd > g_selfBase && a >= g_selfBase && a < g_selfEnd) { off = a - g_selfBase; return "self"; }
            if (g_wxEnd > g_wxBase && a >= g_wxBase && a < g_wxEnd) { off = a - g_wxBase; return "wx"; }
            off = a;
            return "other";
        }

        std::atomic<long long> g_cSelf{ 0 }, g_cWx{ 0 }, g_cOther{ 0 }, g_cTotal{ 0 };

        // step 探针用的"最近见过的 stmt 指针"环形缓存（无锁、无分配）。
        // step 是最热的函数，命中时只有一次 load + 比较，绝不做哈希/加锁/分配。
        const size_t kStmtRing = 4096;
        std::atomic<void*> g_stmtRing[kStmtRing];
        inline bool stmtSeen(void* stmt) {
            size_t idx = (((size_t)stmt) >> 4) % kStmtRing;
            void* cur = g_stmtRing[idx].load(std::memory_order_relaxed);
            if (cur == stmt) return true;
            g_stmtRing[idx].store(stmt, std::memory_order_relaxed);
            return false;
        }

        // 里程碑计数：每类第 1 次必记，另外 10/100/1000/... 各记一次；
        // 再每 1000 次总调用打一行心跳。日志量有界，但"wx 到底有没有涨"绝不会漏。
        inline void countCaller(const char* cls) {
            long long n;
            if (cls[0] == 's')      n = ++g_cSelf;
            else if (cls[0] == 'w') n = ++g_cWx;
            else                    n = ++g_cOther;
            long long total = ++g_cTotal;
            bool milestone = (n == 1 || n == 10 || n == 100 || n == 1000 || n == 10000 || n == 100000);
            bool heartbeat = (total % 1000 == 0);
            if (milestone || heartbeat) {
                char b[288];
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "[PROBE-SUM] %s 累计 SQL 入口调用 self=%lld wx=%lld other=%lld（%s 第 %lld 次%s）\r\n",
                            stamp().c_str(), g_cSelf.load(), g_cWx.load(), g_cOther.load(), cls, n,
                            milestone ? "" : "，心跳");
                sink(b);
            }
        }

        // ── 极简 SQL 词法（只用来做"语句特征"，不做完整解析）──────────
        inline bool identCh(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_' || c == '$';
        }
        inline std::string upperOf(std::string s) {
            for (auto& c : s) if (c >= 'a' && c <= 'z') c = (char)(c - 32);
            return s;
        }
        // 读 i 处的标识符（支持 "t" [t] `t`）；i 前进；读不到返回空且 i 不动
        inline std::string readIdent(const char* sql, int limit, int& i) {
            while (i < limit && (sql[i] == ' ' || sql[i] == '\t' || sql[i] == '\r' || sql[i] == '\n')) ++i;
            if (i >= limit) return "";
            char c = sql[i];
            if (c == '"' || c == '[' || c == '`') {
                char close = (c == '[') ? ']' : c;
                ++i;
                size_t st = (size_t)i;
                while (i < limit && sql[i] != close) ++i;
                std::string r(sql + st, (size_t)i - st);
                if (i < limit) ++i;
                return r;
            }
            size_t st = (size_t)i;
            while (i < limit && identCh(sql[i])) ++i;
            return std::string(sql + st, (size_t)i - st);
        }
        // 找关键字（词边界、大小写不敏感）后面那个标识符
        inline std::string findAfterKeyword(const char* sql, int limit, const char* kw) {
            size_t klen = strlen(kw);
            for (int i = 0; i + (int)klen <= limit; ++i) {
                bool ok = true;
                for (size_t k = 0; k < klen; ++k) {
                    char a = sql[i + k];
                    if (a >= 'a' && a <= 'z') a = (char)(a - 32);
                    if (a != kw[k]) { ok = false; break; }
                }
                if (!ok) continue;
                if (i > 0 && identCh(sql[i - 1])) continue;
                int j = i + (int)klen;
                if (j < limit && identCh(sql[j])) continue;
                return readIdent(sql, limit, j);
            }
            return "";
        }

        // 从写语句里取出目标表名（不做完整 SQL 解析，够用即可；取不到返回空串）。
        // 认 INSERT [OR ...] INTO t / REPLACE INTO t / UPDATE t / DELETE FROM t，
        // 支持 "库名.表名"（取表名）、"t"/[t]/`t` 三种引号。
        inline std::string targetTable(const char* sql, int n, Kw kw) {
            if (sql == nullptr) return "";
            int limit = (n < 0) ? 512 : (n < 512 ? n : 512);
            int i = 0;
            auto isWs = [&](int k) {
                return k < limit && (sql[k] == ' ' || sql[k] == '\t' || sql[k] == '\r' || sql[k] == '\n');
            };
            auto skipWs = [&]() { while (isWs(i)) ++i; };
            auto isIdent = [&](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_' || c == '$';
            };
            auto word = [&]() -> std::string {
                size_t s = (size_t)i;
                while (i < limit && isIdent(sql[i])) ++i;
                return std::string(sql + s, (size_t)i - s);
            };
            auto ident = [&]() -> std::string {
                skipWs();
                if (i >= limit) return "";
                char c = sql[i];
                if (c == '"' || c == '[' || c == '`') {
                    char close = (c == '[') ? ']' : c;
                    ++i;
                    size_t s = (size_t)i;
                    while (i < limit && sql[i] != close) ++i;
                    std::string r(sql + s, (size_t)i - s);
                    if (i < limit) ++i;
                    return r;
                }
                return word();
            };
            auto upper = [](std::string s) {
                for (auto& c : s) if (c >= 'a' && c <= 'z') c = (char)(c - 32);
                return s;
            };
            (void)word();
            if (kw == Kw::Update) {
                skipWs();
                if (upper(word()) == "OR") { (void)word(); }   // UPDATE OR REPLACE t
            } else {
                skipWs();
                std::string w = upper(word());
                if (w == "OR") { (void)word(); skipWs(); w = upper(word()); }
                if (w != "INTO" && w != "FROM") return "";     // 形状不认识，放弃
            }
            std::string t = ident();
            skipWs();
            if (i < limit && sql[i] == '.') { ++i; t = ident(); }   // 库名.表名 → 取表名
            return t;
        }

        inline bool isMsgTable(const std::string& t) {
            if (t.size() < 4) return false;
            return (t[0] == 'M' || t[0] == 'm') && (t[1] == 'S' || t[1] == 's') &&
                   (t[2] == 'G' || t[2] == 'g') && t[3] == '_';
        }

        // 目标库名：句柄登记表里有就用，没有写 unknown（绝不主动去查库）
        inline std::string dbName(sqlite3* db) {
            if (db == nullptr) return "null-db";
            std::lock_guard<std::mutex> lg(g_mtx);
            auto it = g_opened.find((LPVOID)db);
            if (it != g_opened.end() && !it->second.empty()) return it->second;
            if (g_unknownHandles.count((LPVOID)db)) return "unknown";
            return "unknown";
        }

        inline size_t countParams(const char* sql, int n) {
            if (sql == nullptr) return 0;
            size_t limit = (n < 0) ? strlen(sql) : (size_t)n;
            size_t c = 0;
            for (size_t k = 0; k < limit; ++k) if (sql[k] == '?') ++c;
            return c;
        }

        // 语句特征：首个关键字 + 第二个关键字 + 尽力解析出的目标表
        struct Sig { std::string kw1, kw2, table; };

        inline Sig makeSig(const char* sql, int n) {
            Sig g;
            if (sql == nullptr) return g;
            int limit = (n < 0) ? (int)strlen(sql) : n;
            if (limit > 512) limit = 512;      // 只看前 512 字节，代价有界
            if (limit <= 0) return g;
            int i = 0;
            g.kw1 = upperOf(readIdent(sql, limit, i));
            g.kw2 = upperOf(readIdent(sql, limit, i));
            const std::string& k1 = g.kw1;
            if (k1 == "INSERT" || k1 == "REPLACE" || k1 == "UPDATE" || k1 == "DELETE") {
                Kw kw = (k1 == "INSERT")  ? Kw::Insert
                      : (k1 == "UPDATE")  ? Kw::Update
                      : (k1 == "DELETE")  ? Kw::Delete
                                          : Kw::Replace;
                g.table = targetTable(sql, limit, kw);   // 复用第一轮写好的解析
            } else if (k1 == "SELECT" || k1 == "WITH" || k1 == "EXPLAIN") {
                g.table = findAfterKeyword(sql, limit, "FROM");
            } else if (k1 == "PRAGMA") {
                g.table = g.kw2;                          // PRAGMA database_list / table_info
            } else if (k1 == "CREATE" || k1 == "DROP" || k1 == "ALTER") {
                g.table = findAfterKeyword(sql, limit, "TABLE");
                if (g.table.empty()) g.table = findAfterKeyword(sql, limit, "INDEX");
                if (g.table.empty()) g.table = findAfterKeyword(sql, limit, "VIEW");
                if (upperOf(g.table) == "IF") g.table = findAfterKeyword(sql, limit, "EXISTS");
            }
            auto dot = g.table.find('.');
            if (dot != std::string::npos) g.table = g.table.substr(dot + 1);   // 库名.表名 → 表名
            return g;
        }

        // 所有 SQL 入口（prepare / prepare16_v2 / prepare_v3 / prepare16_v3 / exec）汇到这里。
        // 只读、只记日志；不改 rc / 出参 / 控制流。
        inline void onSql(sqlite3* db, const char* sql, int n, int rc, sqlite3_stmt** stmt,
                          const char* via, void* caller) {
            uint64_t off = 0;
            const char* cls = callerClass(caller, off);
            countCaller(cls);

            // ① 一次性存活证明：区分"没命中"和"钩子没挂上"
            static std::atomic<bool> firstCall{ true };
            if (firstCall.exchange(false)) {
                char b[256];
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "[probe] %s 首个 SQL 入口被调用 via=%s from=%s+0x%llX sql=",
                            stamp().c_str(), via, cls, (unsigned long long)off);
                sink(std::string(b) + clip(sql, n, 160) + "\r\n");
            }

            Sig g = makeSig(sql, n);

            // ② 广谱：前 40 条互不相同的语句特征（来源不同算不同条）
            {
                static std::mutex seenMtx;
                static std::set<std::string> seen;
                bool fresh = false;
                {
                    std::lock_guard<std::mutex> lg(seenMtx);
                    std::string key = std::string(cls) + "|" + g.kw1 + "|" + g.kw2 + "|" + g.table;
                    if (seen.size() < 40 && seen.insert(key).second) fresh = true;
                }
                if (fresh) {
                    char b[320];
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "[PROBE-SIG] %s from=%s+0x%llX via=%s kw1=%s kw2=%s table=%s rc=%d db=%s sql=",
                                stamp().c_str(), cls, (unsigned long long)off, via,
                                g.kw1.c_str(), g.kw2.c_str(),
                                (g.table.empty() ? "-" : g.table.c_str()), rc, dbName(db).c_str());
                    sink(std::string(b) + clip(sql, n, 120) + "\r\n");
                }
            }

            // ③ 任何写语句都记（封顶 300 行）—— "写发生在这个实例上吗"的直接证据
            if (g.kw1 == "INSERT" || g.kw1 == "UPDATE" || g.kw1 == "DELETE" || g.kw1 == "REPLACE") {
                static std::atomic<long long> wcount{ 0 };
                long long wn = ++wcount;
                if (wn <= 300) {
                    char b[320];
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "[PROBE-WRITE#%lld] %s from=%s+0x%llX via=%s db=%s table=%s rc=%d sql=",
                                wn, stamp().c_str(), cls, (unsigned long long)off, via,
                                dbName(db).c_str(), (g.table.empty() ? "-" : g.table.c_str()), rc);
                    sink(std::string(b) + clip(sql, n, 400) + "\r\n");
                }
            }

            // ④ 第一轮那一类：INSERT + Msg_*（保留语义，封顶 500）
            if (g.kw1 == "INSERT" && isMsgTable(g.table)) {
                static std::atomic<long long> mcount{ 0 };
                long long mn = ++mcount;
                if (mn <= 500) {
                    char b[256];
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "[PROBE-MSG#%lld] %s from=%s+0x%llX via=%s db=%s table=%s rc=%d stmt=0x%p ph=%zu sql=",
                                mn, stamp().c_str(), cls, (unsigned long long)off, via,
                                dbName(db).c_str(), g.table.c_str(), rc,
                                (void*)((stmt && *stmt) ? *stmt : nullptr), countParams(sql, n));
                    sink(std::string(b) + clip(sql, n, 900) + "\r\n");
                }
            }
        }

        // UTF-16 入口（prepare16_v2 / prepare16_v3）：先转 UTF-8，再走同一套判定
        inline void onSql16(sqlite3* db, const void* sql16, int n, int rc, sqlite3_stmt** stmt,
                            const char* via, void* caller) {
            if (sql16 == nullptr) { onSql(db, nullptr, -1, rc, stmt, via, caller); return; }
            int wchars;
            if (n < 0) {                                   // NUL 结尾：自己数，但封顶（不做无界扫描）
                wchars = 0;
                while (wchars < 4096 && ((const wchar_t*)sql16)[wchars] != 0) ++wchars;
            } else {
                wchars = n / 2;                            // n 是 UTF-16 的字节数
            }
            if (wchars > 512) wchars = 512;                // 只转前 512 个宽字符
            if (wchars <= 0) { onSql(db, "", 0, rc, stmt, via, caller); return; }
            char buf[2048] = { 0 };
            int got = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)sql16, wchars,
                                          buf, (int)sizeof(buf) - 1, nullptr, nullptr);
            if (got < 0) got = 0;
            buf[got] = '\0';
            onSql(db, buf, got, rc, stmt, via, caller);
        }

        // prepare（sqlite3_prepare_v2）入口
        inline void onPrepare(sqlite3* db, const char* sql, int n, int rc, sqlite3_stmt** stmt, void* caller) {
            onSql(db, sql, n, rc, stmt, "prepare", caller);
        }

        // open_v2 探针：这个 sqlite 实例打开过哪些库（封顶 100 行）
        inline void onOpen(const char* filename, int rc, void* db) {
            if (filename == nullptr || *filename == '\0') return;
            static std::atomic<long long> n{ 0 };
            long long k = ++n;
            if (k > 100) return;
            std::string p(filename);
            auto pos = p.find_last_of("\\/");
            std::string base = (pos == std::string::npos) ? p : p.substr(pos + 1);
            char b[256];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "[PROBE-OPEN#%lld] %s rc=%d handle=0x%p file=%s\r\n",
                        k, stamp().c_str(), rc, db, base.c_str());
            sink(b);
        }

        // 安装时喊一声：把来源识别范围算好（热路径上只读全局，无锁无 API 调用）
        // ── step 探针（对付"语句被缓存"这个坑）──────────────────────────
        // 为什么要它：WCDB 会把 prepare 好的语句**缓存起来反复用**
        // （SQLITE_PREPARE_PERSISTENT）。如果那条 INSERT 是在我们挂钩之前就 prepare 好的，
        // 那么无论我们挂多少个 prepare 入口都永远看不到它 —— 但它的 step 一定会被我们撞上。
        // 所以这里用 api->sql(stmt) 反查"正在执行的语句"的 SQL 原文：
        // 与 prepare 时机无关，是"写库到底在不在这台 sqlite 上"最直接的证据。
        // 调用方来源（self/wx）同时给出 Weixin.dll 里的调用点 RVA —— 万一路线 B 要逆向，这就是入口。
        inline void onStep(sqlite3_stmt* stmt, int rc, void* caller) {
            if (g_api == nullptr || g_api->sql == nullptr || stmt == nullptr) return;
            const char* sql = g_api->sql(stmt);
            if (sql == nullptr || *sql == '\0') return;
            uint64_t off = 0;
            const char* cls = callerClass(caller, off);
            Sig g = makeSig(sql, -1);
            // 去重：同一 (来源,语句特征) 只记一次（封顶 60）
            static std::mutex m;
            static std::set<std::string> seen;
            bool fresh = false;
            {
                std::lock_guard<std::mutex> lg(m);
                std::string key = std::string(cls) + "|" + g.kw1 + "|" + g.kw2 + "|" + g.table;
                if (seen.size() < 60 && seen.insert(key).second) fresh = true;
            }
            if (!fresh) return;
            bool isWrite = (g.kw1 == "INSERT" || g.kw1 == "UPDATE" ||
                            g.kw1 == "DELETE" || g.kw1 == "REPLACE");
            const char* tag = (g.kw1 == "INSERT" && isMsgTable(g.table))
                            ? "-MSG" : (isWrite ? "-W" : "");
            sqlite3* db = (g_api->db_handle != nullptr) ? (sqlite3*)g_api->db_handle(stmt) : nullptr;
            char b[352];
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "[PROBE-STEP%s] %s from=%s+0x%llX kw1=%s kw2=%s table=%s rc=%d stmt=0x%p db=%s sql=",
                        tag, stamp().c_str(), cls, (unsigned long long)off,
                        g.kw1.c_str(), g.kw2.c_str(), (g.table.empty() ? "-" : g.table.c_str()),
                        rc, (void*)stmt, dbName(db).c_str());
            sink(std::string(b) + clip(sql, -1, 300) + "\r\n");
        }

        inline void arm() {
            if (g_hModule) {
                g_selfBase = (uint64_t)g_hModule;
                g_selfEnd = g_selfBase + peImageSize(g_selfBase);
            }
            if (g_hWeixinDll) {
                g_wxBase = (uint64_t)g_hWeixinDll;
                g_wxEnd = g_wxBase + peImageSize(g_wxBase);
            }
            char b[320];
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "[probe] %s 来源识别就绪 self=[0x%llX,0x%llX) wx=[0x%llX,0x%llX)\r\n",
                        stamp().c_str(),
                        (unsigned long long)g_selfBase, (unsigned long long)g_selfEnd,
                        (unsigned long long)g_wxBase, (unsigned long long)g_wxEnd);
            sink(b);
            sink("[probe] " + stamp() + " SQL 入口探针已就绪（只记日志）\r\n");
        }
    }

    // ── 第二轮补挂的 SQL 入口（都在同一张 sqlite3_api_routines 表里）──────
    //   prepare16    == sqlite3_prepare16_v2  (sqlite3.h:164)
    //   prepare_v3   == sqlite3_prepare_v3    (sqlite3.h:336)
    //   prepare16_v3 == sqlite3_prepare16_v3  (sqlite3.h:338)
    //   exec         == sqlite3_exec          (sqlite3.h:146)
    // 全部用 MinHook 挂"函数代码地址"（与 prepare / open_v2 同一套已验证生效的手法）。
    typedef int (*prepare16_t)(sqlite3*, const void*, int, sqlite3_stmt**, const void**);
    prepare16_t g_origPrepare16 = nullptr;

    typedef int (*prepare_v3_t)(sqlite3*, const char*, int, unsigned int, sqlite3_stmt**, const char**);
    prepare_v3_t g_origPrepareV3 = nullptr;

    typedef int (*prepare16_v3_t)(sqlite3*, const void*, int, unsigned int, sqlite3_stmt**, const void**);
    prepare16_v3_t g_origPrepare16V3 = nullptr;

    typedef int (*exec_t)(sqlite3*, const char*, sqlite3_callback, void*, char**);
    exec_t g_origExec = nullptr;

    // step == sqlite3_step (sqlite3.h:186)。最热，但也是唯一能戳穿"语句被缓存"的入口。
    typedef int (*step_t)(sqlite3_stmt*);
    step_t g_origStep = nullptr;

    int detourStep(sqlite3_stmt* stmt) {
        void* caller = _ReturnAddress();
        int rc = g_origStep ? g_origStep(stmt) : 1;
        // 每个 stmt 对象只取样一次（环形缓存，无锁）；step 的热路径就是一次 load+比较
        if (stmt != nullptr && !probe::stmtSeen((void*)stmt)) {
            probe::onStep(stmt, rc, caller);
        }
        return rc;
    }

    int detourPrepare(sqlite3* db, const char* sql, int n, sqlite3_stmt** stmt, const char** tail) {
        void* caller = _ReturnAddress();     // 原调用者（MinHook 用 jmp 进 detour，返回地址不变）
        int rc = g_origPrepare ? g_origPrepare(db, sql, n, stmt, tail) : 1;
        // 只在成功且句柄未知时才登记（noteHandle 内部会先查表，开销可忽略）
        if (db != nullptr) {
            noteHandle(db, g_api);
        }
        // 探针：只记日志。不改 rc、不改出参、不拦截。
        probe::onPrepare(db, sql, n, rc, stmt, caller);
        return rc;
    }

    int detourPrepare16(sqlite3* db, const void* sql, int n, sqlite3_stmt** stmt, const void** tail) {
        void* caller = _ReturnAddress();
        int rc = g_origPrepare16 ? g_origPrepare16(db, sql, n, stmt, tail) : 1;
        if (db != nullptr) noteHandle(db, g_api);
        probe::onSql16(db, sql, n, rc, stmt, "prepare16_v2", caller);
        return rc;
    }

    int detourPrepareV3(sqlite3* db, const char* sql, int n, unsigned int flags,
                        sqlite3_stmt** stmt, const char** tail) {
        void* caller = _ReturnAddress();
        int rc = g_origPrepareV3 ? g_origPrepareV3(db, sql, n, flags, stmt, tail) : 1;
        if (db != nullptr) noteHandle(db, g_api);
        probe::onSql(db, sql, n, rc, stmt, "prepare_v3", caller);
        return rc;
    }

    int detourPrepare16V3(sqlite3* db, const void* sql, int n, unsigned int flags,
                          sqlite3_stmt** stmt, const void** tail) {
        void* caller = _ReturnAddress();
        int rc = g_origPrepare16V3 ? g_origPrepare16V3(db, sql, n, flags, stmt, tail) : 1;
        if (db != nullptr) noteHandle(db, g_api);
        probe::onSql16(db, sql, n, rc, stmt, "prepare16_v3", caller);
        return rc;
    }

    int detourExec(sqlite3* db, const char* sql, sqlite3_callback cb, void* arg, char** errmsg) {
        void* caller = _ReturnAddress();
        int rc = g_origExec ? g_origExec(db, sql, cb, arg, errmsg) : 1;
        if (db != nullptr) noteHandle(db, g_api);
        probe::onSql(db, sql, -1, rc, nullptr, "exec", caller);
        return rc;
    }

    // 挂一个"函数代码级"钩子。失败只记日志、返回 false —— 绝不抛、绝不影响既有行为。
    bool installOneHook(void* target, LPVOID detour, LPVOID* orig, const char* name) {
        if (target == nullptr) {
            OutputDebugStringA((std::string("[db_registry] ") + name + " 槽位为空（该 sqlite 版本没这个入口），跳过\n").c_str());
            return false;
        }
        if (MH_CreateHook(target, detour, orig) != MH_OK) {
            OutputDebugStringA((std::string("[db_registry] MH_CreateHook(") + name + ") 失败\n").c_str());
            return false;
        }
        if (MH_EnableHook(target) != MH_OK) {
            OutputDebugStringA((std::string("[db_registry] MH_EnableHook(") + name + ") 失败\n").c_str());
            return false;
        }
        OutputDebugStringA((std::string("[db_registry] ") + name + " 钩子已安装\n").c_str());
        return true;
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

        // ── 第二轮：把其它 SQL 入口一次挂全 ──────────────────────────────
        // 第一轮实测"消息写库不经过 prepare"，所以把这张表上所有可能承载 SQL 的入口都挂上，
        // 一次部署就能看出写库到底走哪个（全部失败也不影响主路径，纯探针）。
        installOneHook((void*)api->prepare16,    (LPVOID)&detourPrepare16,   (LPVOID*)&g_origPrepare16,   "prepare16_v2");
        installOneHook((void*)api->prepare_v3,   (LPVOID)&detourPrepareV3,   (LPVOID*)&g_origPrepareV3,   "prepare_v3");
        installOneHook((void*)api->prepare16_v3, (LPVOID)&detourPrepare16V3, (LPVOID*)&g_origPrepare16V3, "prepare16_v3");
        installOneHook((void*)api->exec,         (LPVOID)&detourExec,        (LPVOID*)&g_origExec,        "exec");
        // step：唯一能抓到"挂钩之前就 prepare 好、之后反复复用"的写语句
        installOneHook((void*)api->step,         (LPVOID)&detourStep,        (LPVOID*)&g_origStep,        "step");

        probe::arm();   // 探针就绪（只记日志，见文件上方 probe 命名空间）
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