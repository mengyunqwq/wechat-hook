

#define CPPHTTPLIB_WIN32
#define CPPHTTPLIB_THREAD_POOL_COUNT 8

// 减少 Windows select() 的 idle interval，提升并发响应速度
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 100  // 原来是 10000 (10ms)

#include <cstdarg>
#include <cstdio>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "httplib.h"
#include "json.hpp"

#include "http_server.h"
#include "http_routes.h"

#include <windows.h> 

#include <string>
#include <thread>
#include <atomic>

using json = nlohmann::json;


HttpServer::HttpServer(){}

HttpServer::~HttpServer()
{
    Stop();
}

bool HttpServer::Start(const std::string& host, int port)
{
    if (m_running)
        return true;

    m_running = true;
    m_thread = std::thread(&HttpServer::Run, this, host, port);
    m_thread.detach();   // DLL 中建议 detach，避免阻塞卸载
    return true;
}

void HttpServer::Stop()
{
    if (m_server)
        m_server->stop(); // httplib::Server 停止 listen
    m_running = false;
}

// ── 2026-11-11 诊断埋点 ──────────────────────────────────────────────
// 现象：30001 处于 LISTEN，但客户端连进来一直 SYN_RECEIVED（从不 accept），
//       CPU 0%，说明"bind+listen 成功但 accept 循环没跑"或"端口被别人占"。
//       这一版把 Run() 每一步写进文件，并**自己探一次 bind** 判断端口是否可用。
//       下次卡住直接看 http-trace.log 就知道卡在哪。
static void HttpTrace(const char* fmt, ...)
{
    char buf[1024] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200] = { 0 };
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(line, "[%02d:%02d:%02d.%03d][pid=%lu tid=%lu] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentProcessId(), GetCurrentThreadId(), buf);

    FILE* f = nullptr;
    if (fopen_s(&f, "D:\\wxhook\\wx4110\\http-trace.log", "a") == 0 && f)
    {
        fputs(line, f);
        fflush(f);
        fclose(f);
    }
    OutputDebugStringA(line);
}

/** 只做 socket+bind 探一次，判断端口是不是被别人占了（不 listen、立刻关闭） */
static void ProbePort(const char* host, int port)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { HttpTrace("PROBE WSAStartup 失败"); return; }
    SOCKET t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t == INVALID_SOCKET) { HttpTrace("PROBE socket() 失败 err=%d", WSAGetLastError()); WSACleanup(); return; }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &a.sin_addr);   // 现代 API，避免 inet_addr 的 C4996
    int rc = bind(t, (sockaddr*)&a, sizeof(a));
    int err = WSAGetLastError();
    if (rc == 0) HttpTrace("PROBE bind %s:%d 可用（端口没被占）", host, port);
    else HttpTrace("PROBE bind %s:%d 失败 err=%d %s", host, port, err,
        err == 10048 ? "← WSAEADDRINUSE：端口已被别的进程占用！" : "");
    closesocket(t);
    WSACleanup();
}

// ★ 2026-11-11：同步任务队列 —— 不创建任何 worker 线程，
//   accept 到连接后就在当前线程把请求处理完。
//   理由：只有一个本机客户端（wx-bridge），请求频率极低（6 秒一次），
//   而"在微信进程里动态建线程池"实测不可靠（accept 成功但请求没人处理）。
class InlineTaskQueue : public httplib::TaskQueue
{
public:
    void enqueue(std::function<void()> fn) override
    {
        if (fn) fn();          // 直接同步执行，不建线程
    }
    void shutdown() override {}
    void on_idle() override {}
};

void HttpServer::Run(const std::string& host, int port)
{
    HttpTrace("=== Run 进入 host=%s port=%d this=%p ===", host.c_str(), port, (void*)this);
    ProbePort(host.c_str(), port);
    HttpTrace("1/5 make_unique<Server>");
    m_server = std::make_unique<httplib::Server>();

    // 启用线程池，支持并发请求处理
    HttpTrace("2/5 设置 new_task_queue（ThreadPool %d 线程）", CPPHTTPLIB_THREAD_POOL_COUNT);
    // ★ 2026-11-11：不再自定义线程池。原来是 new ThreadPool(8)，
    //   在 DLL 里创建大量线程 + 与 select 轮询配合，出问题无法观测。
    //   默认实现就够用（我们只有 1 个本机客户端）。
    // ★ 2026-11-11：改成同步队列（不建 worker 线程）
    m_server->new_task_queue = [] { return new InlineTaskQueue(); };

    // 减少 idle interval，提升响应速度
    // ★ 2026-11-11：原来是 set_idle_interval(0, 100) = 100 微秒。
    //   Windows 的 select() 精度是 1~15.6ms，100μs 会被截断成"立即返回"，
    //   于是 accept 循环变成纯空转（CPU 0% 但永远 accept 不到）。
    //   httplib 默认是 10ms（CPPHTTPLIB_IDLE_INTERVAL_USECOND=10000），用它。
    // 显式设成 10ms：100us 在 Windows 上撑不住（select/WSAPoll 精度 1~15.6ms），
    // 会退化成纯轮询空转。10ms 与 httplib 默认值一致。
    m_server->set_idle_interval(0, 10000);

    // 禁用 Nagle 算法，减少延迟
    m_server->set_tcp_nodelay(true);

    // 注册路由
    HttpTrace("3/5 RegisterRoutes 前");
    // ★ 2026-11-11 诊断：不碰数据库的探针端点，用来二分"HTTP 层"和"DB 层"
    m_server->Get("/Ping", [](const httplib::Request&, httplib::Response& res) {
        HttpTrace("PING 命中：HTTP 层已通（不涉及数据库）");
        res.set_content("pong", "text/plain");
    });
    RegisterRoutes(*m_server);
    HttpTrace("3/5 RegisterRoutes 完成");

    char buf[256];
    sprintf_s(buf, "[HTTP] Started -> %s:%d (ThreadPool: %d, IdleInterval: 100us)\n", 
              host.c_str(), port, CPPHTTPLIB_THREAD_POOL_COUNT);
    OutputDebugStringA(buf);

    // 0.0.0.0:30001
    // ★ 2026-11-11：句柄超 FD_SETSIZE 时 select_read 直接返回"可读"，
    //   此时 accept 必须是非阻塞的（没连接立刻返回 WSAEWOULDBLOCK），
    //   否则会阻塞在 accept 上。httplib 内部用 EAGAIN 分支处理这种情况。
    HttpTrace("4/5 listen 调用（内部=bind+listen+accept 循环）");
    // ★ 2026-11-11 自愈循环：
    //   实测监听 socket 会在 listen() 之后被外部关掉（Listen 状态消失、只剩 SynReceived），
    //   而 httplib 的 accept 循环对着失效 fd 空转、永不返回 → 表现为"hook 挂不上"。
    //   这里只要 listen() 返回（正常情况下它永不返回），就重建 Server 重新监听。
    int round = 0;
    while (m_running.load())
    {
        round++;
        HttpTrace("listen 第 %d 轮开始", round);
        bool listenOk = m_server->listen(host.c_str(), port);
        HttpTrace("listen 第 %d 轮返回 %d（0=失败/已停止）→ 重建后重试", round, (int)listenOk);
        if (!m_running.load()) break;

        // 重建一个干净的 Server（旧的 socket 已不可信）
        m_server = std::make_unique<httplib::Server>();
        m_server->set_idle_interval(0, 10000);
        m_server->set_tcp_nodelay(true);
        m_server->Get("/Ping", [](const httplib::Request&, httplib::Response& res) {
            HttpTrace("PING 命中：HTTP 层已通（不涉及数据库）");
            res.set_content("pong", "text/plain");
        });
        RegisterRoutes(*m_server);
        Sleep(1000);   // 给外部清理逻辑一点时间，避免无效重建打转
    }
    HttpTrace("listen 循环退出（m_running=false）");

#ifdef _DEBUG
    OutputDebugStringA("[HTTP] Server stopped\n");
#endif
}
