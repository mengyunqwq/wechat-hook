// HookQueue.cpp —— 文件队列通道（2026-11-12）
//
// 为什么要有它：
//   在微信 4.1.10.27 上，hook 的 HTTP 服务端**起不来**
//   （fd_set 只有 64 项而 socket 句柄是 1480 → FD_SET 越界 →
//     select 永远返回 0 → accept 永不执行 → 端口 LISTEN 但连不上）。
//   换 WSAPoll 在 listen socket 上同样不可靠。
//   → 干脆不要让 hook 当"服务端"：改成**桥写请求文件，hook 轮询执行、写结果文件**。
//
// 协议（目录 = <hook dll 所在目录>\hook-queue）：
//   请求：req-<id>.json   {"id":"...","op":"queryDB","optDbName":"contact.db","SQL":"SELECT ..."}
//   结果：res-<id>.json   {"ok":true,"status":0,"data":[...]}  或  {"ok":false,"error":"..."}
//   hook 处理完删 req 文件；桥读到 res 后删 res 文件。
//
// 支持 op（第一批，覆盖桥的日常用途）：
//   ping      → "pong"
//   status    → {"IsLogin":1,"hWeixin":...}
//   queryDB   → DatabaseMgr::execute(optDbName, SQL)
//   apitable  → apiTableReport()

#include <winsock2.h>   // 必须在 windows.h 之前（否则 fd_set/sockaddr 重定义）
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstdio>

#include "json.hpp"   // 项目自带（include/json.hpp）
#include "db_mgr.h"
#include "global.h"
#include "CrashLog.h"
#include "HookQueue.h"
#include "wx_send.h"   // WeixinSend::SendText / SendImage
#include "http_routes.h"   // RegisterRoutes（复用全部 60 个端点）
#include "httplib.h"

using json = nlohmann::ordered_json;
using namespace std::chrono;

namespace hookq {

// ★ 2026-11-12：一个"只用来分发、从不 listen"的 Server。
//   把全部路由注册到它上面，队列线程用 DispatchSynthetic 在内存里直接调用，
//   于是**所有 HTTP 端点都能通过队列使用**，无需逐个重写。
static httplib::Server* g_routeSrv = nullptr;
static std::mutex      g_dispatchMtx;   // 分发串行化（路由里有非线程安全的全局状态）

static std::atomic<bool> g_running{ false };

// 本文件自己的日志（不依赖 db_mgr 的实现，避免命名空间/链接问题）
static void queueLog(const char* msg)
{
    FILE* f = nullptr;
    if (fopen_s(&f, "D:/wxhook/wx4110/hook-queue.log", "a") == 0 && f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);
        fclose(f);
    }
}
static std::thread       g_thread;
static std::wstring      g_dir;

// ── 目录 ────────────────────────────────────────────────────────────
static std::wstring QueueDir()
{
    if (!g_dir.empty()) return g_dir;

    wchar_t path[MAX_PATH] = { 0 };
    HMODULE self = nullptr;
    // 拿本 DLL 的路径（version.dll 在客户端目录里）
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&QueueDir, &self);
    if (self) GetModuleFileNameW(self, path, MAX_PATH);
    std::wstring dir(path);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) dir = dir.substr(0, pos);
    if (dir.empty()) dir = L".";
    g_dir = dir + L"\\hook-queue";
    CreateDirectoryW(g_dir.c_str(), nullptr);
    CreateDirectoryW((g_dir + L"\\done").c_str(), nullptr);
    return g_dir;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::string ReadAll(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/** 原子写：先写 .tmp 再替换，避免桥读到半截文件 */
static bool WriteAtomic(const std::wstring& path, const std::string& content)
{
    std::wstring tmp = path + L".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(content.data(), (std::streamsize)content.size());
        f.flush();
    }
    return MoveFileExW(tmp.c_str(), path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

// ── op 实现 ─────────────────────────────────────────────────────────
static json HandleOp(const json& req)
{
    const std::string op = req.value("op", "");

    if (op == "ping") return json{ {"ok", true}, {"data", "pong"} };

    if (op == "status") {
        return json{
            {"ok", true},
            {"data", {
                {"IsLogin", g_IsLogin},
                {"hWeixin", (unsigned long long)(uintptr_t)g_hWeixinDll},
            }}
        };
    }

    if (op == "apitable") {
        try {
            return json{ {"ok", true}, {"data", xmgr::DatabaseMgr::getInstance().apiTableReport()} };
        } catch (std::exception& e) {
            return json{ {"ok", false}, {"error", e.what()} };
        }
    }

    if (op == "http") {
        // ★ 通用分发：桥传 method / path / body，这里在内存里走一遍路由表。
        //   这样 hook 的每一个端点（含朋友圈、语音、XML 转发、各种 Debug）
        //   都可以通过队列调用。
        if (g_routeSrv == nullptr) return json{ {"ok", false}, {"error", "路由表未初始化"} };
        const std::string m = req.value("method", "POST");
        const std::string path = req.value("path", "");
        std::string body;
        if (req.contains("body")) {
            if (req["body"].is_string()) body = req["body"].get<std::string>();
            else body = req["body"].dump();
        }
        if (path.empty()) return json{ {"ok", false}, {"error", "path 为空"} };

        // ── 危险端点黑名单（2026-11-12 实测）────────────────────────────
        // /Debug/StructCheck 会扫全地址空间做结构校验，在本构建上**直接把微信搞崩**
        // （实测崩溃号 5E9808250147CEA1...，客户端弹"错误报告"）。
        // 这类纯调试端点没有业务价值，从队列通道一律拒绝，避免误调。
        {
            static const char* kDeny[] = {
                "/Debug/StructCheck", "/Debug/ScanVt", "/Debug/MemScan",
                "/MemScan", "/Debug/PeProbe", "/Debug/DpProbe", "/Debug/DwProbe",
                "/Debug/TsProbe", "/Debug/VuProbe",
            };
            for (size_t i = 0; i < sizeof(kDeny) / sizeof(kDeny[0]); i++) {
                if (path.find(kDeny[i]) != std::string::npos) {
                    return json{ {"ok", false},
                                 {"error", std::string("该调试端点已禁用（实测会崩溃微信）：") + kDeny[i]} };
                }
            }
        }

        // 诊断：SendTextMsg 走通用分发时，把 body 的前 60 字节打成 hex
        // （排查"桥发的消息中文变 ◊◊"到底是编码还是长度问题）
        if (path.find("SendText") != std::string::npos) {
            char hex[512] = {0}; int hn = 0;
            for (size_t i = 0; i < body.size() && i < 60; i++)
                hn += sprintf_s(hex + hn, sizeof(hex) - hn, "%02x", (unsigned char)body[i]);
            FILE* lf = nullptr;
            if (fopen_s(&lf, "D:/wxhook/wx4110/queue-send.log", "a") == 0 && lf) {
                fprintf(lf, "[http] path=%s bytes=%d hex=", path.c_str(), (int)body.size());
                fputs(hex, lf);
                fputs("\n", lf);
                fclose(lf);
            }
        }

        std::string resBody;
        int resStatus = 0;
        httplib::Headers resHeaders;
        bool hit = false;
        {
            std::lock_guard<std::mutex> lg(g_dispatchMtx);
            hit = g_routeSrv->DispatchSynthetic(m, path, body, resBody, resStatus, resHeaders);
        }
        if (!hit) return json{ {"ok", false}, {"error", "404 未注册的端点: " + path} };

        // 端点通常返回 JSON 文本；能解析就原样给桥，不能解析就当字符串
        json payload;
        bool parsed = false;
        try { payload = json::parse(resBody); parsed = true; } catch (...) {}
        if (parsed) return json{ {"ok", true}, {"data", payload}, {"status", resStatus} };
        return json{ {"ok", true}, {"data", resBody}, {"status", resStatus} };
    }

    if (op == "sendText") {
        // ★ 2026-11-12：队列通道的发送能力。
        //   字段与 HTTP 端点 /SendTextMsg 完全一致（wxidorgid / msg / atlist），
        //   桥那边一行都不用改。
        const std::string to = req.value("wxidorgid", "");
        const std::string msg = req.value("msg", "");
        if (to.empty() || msg.empty()) return json{ {"ok", false}, {"error", "wxidorgid/msg 不能为空"} };

        std::string atlist;
        try {
            if (req.contains("atlist")) {
                if (req["atlist"].is_array()) {
                    for (auto& x : req["atlist"]) {
                        if (!atlist.empty()) atlist += ",";
                        atlist += x.get<std::string>();
                    }
                } else if (req["atlist"].is_string()) {
                    atlist = req["atlist"].get<std::string>();
                }
            }
        } catch (...) {}

        // 诊断：把收到的 msg 打成十六进制，确认编码（中文 UTF-8 应是 e4b8.. 之类）
        {
            char hex[512] = {0}; int n = 0;
            for (size_t i = 0; i < msg.size() && i < 60; i++)
                n += sprintf_s(hex + n, sizeof(hex) - n, "%02x", (unsigned char)msg[i]);
            FILE* lf = nullptr;
            if (fopen_s(&lf, "D:/wxhook/wx4110/queue-send.log", "a") == 0 && lf) {
                fprintf(lf, "to=%s bytes=%d hex=", to.c_str(), (int)msg.size());
                fputs(hex, lf);
                fputs("\n", lf);
                fclose(lf);
            }
        }
        try {
            WeixinSend::SendText(to, msg, atlist);
            return json{ {"ok", true}, {"data", { {"ret", 0}, {"retmsg", "success"} }} };
        } catch (std::exception& e) {
            return json{ {"ok", false}, {"error", e.what()} };
        }
    }

    if (op == "sendImage") {
        const std::string to = req.value("wxid", "");
        const std::string path = req.value("imgPath", "");
        if (to.empty() || path.empty()) return json{ {"ok", false}, {"error", "wxid/imgPath 不能为空"} };
        try {
            WeixinSend::SendImage(to, path);
            return json{ {"ok", true}, {"data", { {"ret", 0}, {"retmsg", "success"} }} };
        } catch (std::exception& e) {
            return json{ {"ok", false}, {"error", e.what()} };
        }
    }

    if (op == "dbs") {
        // ★ 2026-11-12：桥用 /QueryDB/debug 拿"有哪些库"，没有它桥就以为
        //   "消息库分片不可用"（shardNames 为空 → 不探测 → 轮询起不来）。
        //   这里给出同样形状：{ dbs: [ { dbName, ... } ] }
        try {
            auto info = xmgr::DatabaseMgr::getInstance().getDatabaseInfo();
            // 桥读的是 dd.dbs（历史 HTTP 端点返回 {dbs:[...]}），这里保持同样的形状
            return json{ {"ok", true}, {"data", { {"dbs", info}, {"IsLogin", g_IsLogin} }} };
        } catch (std::exception& e) {
            return json{ {"ok", false}, {"error", e.what()} };
        }
    }

    if (op == "queryDB") {
        const std::string db = req.value("optDbName", "");
        const std::string sql = req.value("SQL", "");
        if (sql.empty()) return json{ {"ok", false}, {"error", "SQL 为空"} };
        try {
            auto r = xmgr::DatabaseMgr::getInstance().execute(db, sql);
            // ★ 关键：桥会把 {"data": ...} 里的 data 当成"响应本体"，
            //   所以这里要**再包一层**，让桥拿到完整的 {status, desc, data}。
            //   （HTTP 端点是平铺返回的，队列必须保持同样的最终形状）
            return json{ {"ok", true}, {"data", r} };
        } catch (std::exception& e) {
            return json{ {"ok", false}, {"error", e.what()} };
        }
    }

    return json{ {"ok", false}, {"error", "未知 op: " + op} };
}

// ── 主循环 ──────────────────────────────────────────────────────────
static void LoopImpl()
{
    const std::wstring dir = QueueDir();
    const std::wstring pattern = dir + L"\\req-*.json";

    while (g_running.load())
    {
      // ★ 2026-11-12：整个迭代体兜底。
      //   以前只有"解析 + HandleOp"包了 try，而且只 catch std::exception ——
      //   文件枚举、vector、字符串转换、写结果、dump() 任何一处抛异常
      //   （bad_alloc / 非 std 异常）都会穿出线程函数 → std::terminate → abort()。
      //   崩溃签名（Weixin.dll+0x3290，mov [0],0x1338）正是 CRT abort。
      try
      {
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) { Sleep(200); continue; }

        std::vector<std::wstring> names;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) names.push_back(fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);

        for (const auto& name : names)
        {
            const std::wstring full = dir + L"\\" + name;
            const std::string raw = ReadAll(full);
            if (raw.empty()) { DeleteFileW(full.c_str()); continue; }

            // id 从文件名里取：req-<id>.json
            std::string id = WideToUtf8(name);
            if (id.rfind("req-", 0) == 0) id = id.substr(4);
            if (id.size() > 5) id = id.substr(0, id.size() - 5);

            json resp;
            try {
                json req = json::parse(raw);
                resp = HandleOp(req);
            } catch (std::exception& e) {
                resp = json{ {"ok", false}, {"error", std::string("解析失败: ") + e.what()} };
            } catch (...) {
                resp = json{ {"ok", false}, {"error", "未知异常（已吞掉，不影响客户端）"} };
            }
            resp["id"] = id;

            const std::wstring resPath = dir + L"\\res-" + std::wstring(id.begin(), id.end()) + L".json";
            WriteAtomic(resPath, resp.dump());
            DeleteFileW(full.c_str());
        }

        Sleep(150);
      }
      catch (const std::exception& e) {
        // 记下具体异常（否则只知道"抛了"，不知道"抛什么"）
        char buf[512];
        sprintf_s(buf, "迭代异常(std): %s", e.what());
        queueLog(buf);
        Sleep(150);
      }
      catch (...) {
        queueLog("迭代异常(非 std)：已吞掉并继续");
        Sleep(150);
      }
    }
}

static void Loop()
{
    // 最外层再兜一层：万一 LoopImpl 自己抛了（比如 QueueDir 失败）
    try { LoopImpl(); }
    catch (...) { queueLog("队列主循环异常退出"); }
}

void Start()
{
    if (g_running.exchange(true)) return;
    QueueDir();                       // 建目录

    // 注册全部路由到"分发专用" Server（不 listen，纯内存调用）
    if (g_routeSrv == nullptr) {
        try {
            g_routeSrv = new httplib::Server();
            RegisterRoutes(*g_routeSrv);
        } catch (...) {
            g_routeSrv = nullptr;
        }
    }
    g_thread = std::thread(Loop);
    g_thread.detach();
}

void Stop()
{
    g_running.store(false);
}

} // namespace hookq
