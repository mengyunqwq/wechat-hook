// ═════════════════════════════════════════════════════════════════════════════
//  SendMoment.cpp —— /SendMoment（发朋友圈）
//
//  逆向依据（Weixin.dll 4.1.10.27）：
//    0x04EB0B90  构造 mmsnspost 请求 + CoCgiSendRequest 发送
//      5 参：rcx=P1 输出对象(0x38+ 字节)、rdx=P2(单例虚方法返回)、
//            r8=P3(栈结构)、r9=P4(std::string)、栈上第5参=P5
//      P5 = { DWORD type; DWORD flag; std::string text; void* extra; }
//          type=0、flag=0x1D4C0，text 在 +0x08（MSVC std::string）
//    P2 来源：读全局单例 [base+0x0A7F9B20]，再 call [[singleton]+0x10]
//
//  分阶段（stage 参数）便于先验证低风险部分：
//    stage=1  只读单例 + 取 P2（不调 mmsnspost，用来确认单例/虚表正常）
//    stage=2  完整调用 mmsnspost（有崩溃风险，默认关）
//
//  安全默认：默认 stage=1；要真发必须显式 stage=2 且开关文件存在。
// ═════════════════════════════════════════════════════════════════════════════
#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <ctime>
#include "global.h"
#include "SendMoment.h"
#include <MinHook.h>   // MOMENT-CAPTURE: 勾住 mmsnspost 构造函数录真实参数

using json = nlohmann::json;

std::string BuildMomentXml(const std::string& text, const std::string& wxid, bool priv);

namespace
{
    inline uintptr_t WxBase() { return (uintptr_t)GetModuleHandleA("Weixin.dll"); }

    // MSVC std::string 布局（32 字节）：buf[16] @+0x00、size @+0x10、cap @+0x18
    // 本函数把 s 写入 dst（dst 指向 string 起点）
    inline void BuildMsString(void* dst, const std::string& s)
    {
        char* p = (char*)dst;
        ::memset(p, 0, 32);
        if (s.size() <= 15)
        {
            if (!s.empty()) ::memcpy(p, s.data(), s.size());
            *(size_t*)(p + 0x10) = s.size();
            *(size_t*)(p + 0x18) = 15;
        }
        else
        {
            char* heap = new char[s.size() + 1];
            ::memcpy(heap, s.data(), s.size());
            heap[s.size()] = 0;
            *(char**)p          = heap;
            *(size_t*)(p + 0x10) = s.size();
            *(size_t*)(p + 0x18) = s.size();
        }
    }

    // P5：{ DWORD type; DWORD flag; std::string text(@+0x08); void* extra(@+0x28) }
    struct MomentParam5
    {
        unsigned int type;     // +0x00
        unsigned int flag;     // +0x04
        char         str[32];  // +0x08  MSVC std::string
        void*        extra;    // +0x28
    };

    // __try 不能与需要对象展开（有析构函数）的函数共存（C2712），
    // 因此把 SEH 保护抽成只吃裸指针的独立函数。
    typedef int (*MomentFn5)(void*, void*, void*, void*, void*);

    // 崩溃现场（给 stage=2 迭代用）：异常码 / 异常地址 / 读写地址 / 关键寄存器
    volatile int       g_lastVariant = 0;
    volatile DWORD     g_exCode = 0;
    volatile ULONG_PTR g_exAddr = 0;
    volatile ULONG_PTR g_exAccess = 0;
    volatile ULONG_PTR g_exRcx = 0, g_exRdx = 0, g_exR8 = 0, g_exR9 = 0;
    volatile ULONG_PTR g_exRsi = 0, g_exRdi = 0, g_exRsp = 0, g_exRbp = 0;
    volatile ULONG_PTR g_stack[12] = {0};   // 栈上落在 Weixin.dll 内的返回地址（RVA）
    volatile int       g_stackN = 0;

    void ScanStack(ULONG_PTR rsp, uintptr_t base)
    {
        g_stackN = 0;
        __try
        {
            const ULONG_PTR* p = (const ULONG_PTR*)rsp;
            for (int i = 0; i < 0x200 && g_stackN < 12; ++i)
            {
                ULONG_PTR v = p[i];
                if (v >= base && v < base + 0x0AF0E000)
                {
                    g_stack[g_stackN] = v - base;
                    ++g_stackN;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    int RecordCrash(struct _EXCEPTION_POINTERS* ep)
    {
        if (ep && ep->ExceptionRecord)
        {
            g_exCode = ep->ExceptionRecord->ExceptionCode;
            g_exAddr = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
            if (ep->ExceptionRecord->NumberParameters >= 2)
                g_exAccess = (ULONG_PTR)ep->ExceptionRecord->ExceptionInformation[1];
        }
        if (ep && ep->ContextRecord)
        {
            CONTEXT* c = ep->ContextRecord;
            g_exRcx = c->Rcx; g_exRdx = c->Rdx; g_exR8 = c->R8; g_exR9 = c->R9;
            g_exRsi = c->Rsi; g_exRdi = c->Rdi; g_exRsp = c->Rsp; g_exRbp = c->Rbp;
            ScanStack(c->Rsp, (uintptr_t)GetModuleHandleA("Weixin.dll"));
        }
        return 1;
    }

    int CallVirtualProvoke(void* singleton, void** out)
    {
        __try
        {
            using Vfn = void* (*)(void*);
            void** vtbl = *(void***)singleton;
            if (!vtbl) return -1;
            Vfn vf = (Vfn)vtbl[2];          // [vtable + 0x10]
            if (!vf) return -1;
            *out = vf(singleton);
            return 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    int CallCtorGuarded(MomentFn5 fn, void* p1, void* p2, void* p3, void* p4, void* p5)
    {
        g_exCode = g_exAddr = g_exAccess = 0;
        g_exRcx = g_exRdx = g_exR8 = g_exR9 = 0;
        g_exRsi = g_exRdi = g_exRsp = g_exRbp = 0;
        __try { return fn(p1, p2, p3, p4, p5); }
        __except (RecordCrash(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) { return -99; }
    }

    int CallP3Ctor(void (*ctor)(void*), void* obj)
    {
        __try { ctor(obj); return 0; }
        __except (RecordCrash(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) { return -1; }
    }

    std::string DiagJson(uintptr_t base, void* singleton, void* p2, int stage, int ret)
    {
        // 崩溃地址落在哪个模块？(0x400000 = MEMORY_BASIC_INFORMATION.AllocationBase 偏移)
        uintptr_t exModule = 0;
        if (g_exAddr)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)g_exAddr, &mbi, sizeof(mbi)))
                exModule = (uintptr_t)mbi.AllocationBase;
        }
        uintptr_t selfBase = (uintptr_t)GetModuleHandleA("version.dll");
        if (!selfBase) selfBase = (uintptr_t)GetModuleHandleA("Weixin.dll");

        char buf[1900];
        std::snprintf(buf, sizeof(buf),
            "{\"base\":\"0x%llX\",\"selfBase\":\"0x%llX\",\"exModule\":\"0x%llX\","
            "\"exIsSelf\":%d,\"exIsWeixin\":%d,"
            "\"singleton\":\"0x%llX\",\"p2\":\"0x%llX\","
            "\"stage\":%d,\"variant\":%d,\"ret\":%d,\"ctorRva\":\"0x%llX\",\"singletonRva\":\"0x%llX\","
            "\"exCode\":\"0x%llX\",\"exAddr\":\"0x%llX\",\"exAddrRva\":\"0x%llX\",\"exAccess\":\"0x%llX\","
            "\"reg\":{\"rcx\":\"0x%llX\",\"rdx\":\"0x%llX\",\"r8\":\"0x%llX\",\"r9\":\"0x%llX\","
            "\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\",\"rsp\":\"0x%llX\",\"rbp\":\"0x%llX\"}",
            (unsigned long long)base,
            (unsigned long long)selfBase,
            (unsigned long long)exModule,
            (exModule && selfBase && exModule == selfBase) ? 1 : 0,
            (exModule && base && exModule == base) ? 1 : 0,
            (unsigned long long)(uintptr_t)singleton,
            (unsigned long long)(uintptr_t)p2,
            stage, g_lastVariant, ret,
            (unsigned long long)offset::mmsnspost_ctor,
            (unsigned long long)offset::sns_singleton_ptr,
            (unsigned long long)g_exCode,
            (unsigned long long)g_exAddr,
            (unsigned long long)(base && g_exAddr ? (g_exAddr - base) : 0),
            (unsigned long long)g_exAccess,
            (unsigned long long)g_exRcx, (unsigned long long)g_exRdx,
            (unsigned long long)g_exR8,  (unsigned long long)g_exR9,
            (unsigned long long)g_exRsi, (unsigned long long)g_exRdi,
            (unsigned long long)g_exRsp, (unsigned long long)g_exRbp);
        std::string out(buf);
        // 追加栈回溯（崩溃时栈上落在 Weixin.dll 内的返回地址，RVA）
        out += ",\"stack\":[";
        for (int i = 0; i < g_stackN; ++i)
        {
            char t[24];
            std::snprintf(t, sizeof(t), "%s\"0x%llX\"", i ? "," : "",
                          (unsigned long long)g_stack[i]);
            out += t;
        }
        out += "]}";
        return out;
    }
}

// 返回：0 成功；-1 参数错；-2 模块未找到；-3 单例为空；-4 虚表异常；-99 未实现/未开启
int WeixinMoment::SendMoment(const std::string& text, int stage, std::string* diag, int variant, const std::string& wxid)
{
    g_lastVariant = variant;
    uintptr_t base = WxBase();
    if (!base) { if (diag) *diag = "{\"why\":\"Weixin.dll not loaded\"}"; return -2; }

    void* singleton = *(void**)(base + offset::sns_singleton_ptr);
    if (!singleton)
    {
        if (diag) *diag = DiagJson(base, nullptr, nullptr, stage, -3);
        return -3;
    }

    // P2 = singleton 的虚方法 [vtbl + 0x10] 的返回值
    void* p2 = nullptr;
    if (CallVirtualProvoke(singleton, &p2) != 0)
    {
        if (diag) *diag = DiagJson(base, singleton, nullptr, stage, -4);
        return -4;
    }

    if (stage < 2)
    {
        if (diag) *diag = DiagJson(base, singleton, p2, stage, 0);
        return 0;   // 只做探测
    }


    // ── stage 3：自己拼 XML 放进 P1+0x40，再调构造函数 ───────────────────────
    // 实测：真实调用时 P1+0x40 已是 std::string(buf@+0x40/size@+0x50/cap@+0x58)，
    //       内容就是 TimelineObject XML；P1+0x38 是 Weixin.dll 内函数指针(RVA 0x2BD9B9)
    if (stage == 3)
    {
        struct Q5 { unsigned int type; unsigned int flag; char str[32]; void* extra; };
        typedef void (*P3CtorT)(void*);
        MomentFn5 fn3 = (MomentFn5)(base + offset::mmsnspost_ctor);

        static char p1x[0x200];
        static char p3x[0x200];
        static char p4x[0x100];
        ::memset(p1x, 0, sizeof(p1x));
        ::memset(p3x, 0, sizeof(p3x));
        ::memset(p4x, 0, sizeof(p4x));
        *(void**)(p1x + 0x38) = (void*)(base + 0x2BD9B9);
        BuildMsString(p1x + 0x40, BuildMomentXml(text, wxid, false));

        P3CtorT p3c = (P3CtorT)(base + offset::moment_p3_ctor);
        if (CallP3Ctor(p3c, p3x) != 0)
        {
            if (diag) *diag = "{\"why\":\"P3 ctor crashed\",\"stage\":3}";
            return -5;
        }
        BuildMsString(p4x, "");

        Q5 q5;
        ::memset(&q5, 0, sizeof(q5));
        q5.type = 0;
        q5.flag = 0x1D4C0;
        BuildMsString(q5.str, "");

        int r3 = CallCtorGuarded(fn3, p1x, p2, p3x, p4x, &q5);
        if (diag) *diag = DiagJson(base, singleton, p2, stage, r3);
        return r3;
    }

    // ── stage 2：真正调用 mmsnspost ───────────────────────────────────────────
    MomentFn5 fn = (MomentFn5)(base + offset::mmsnspost_ctor);
    typedef void (*P3Ctor)(void*);

    static struct { char b[0x100]; } p1;
    static char p3[0x200];          // 真实大小 0x1A0，留余量
    static char p4[0x100];
    ::memset(&p1, 0, sizeof(p1));
    ::memset(p3, 0, sizeof(p3));
    ::memset(p4, 0, sizeof(p4));

    // P3 必须先构造（真实调用方：memset(0xAA, 0x1A0) 后 call 0x04DA2BB0）
    if (variant != 8)               // variant=8 故意不构造，作对照
    {
        P3Ctor p3ctor = (P3Ctor)(base + offset::moment_p3_ctor);
        int cr = CallP3Ctor(p3ctor, p3);
        if (cr != 0)
        {
            if (diag) *diag = DiagJson(base, singleton, p2, stage, -5);
            return -5;              // P3 构造就崩了
        }
    }

    MomentParam5 p5;
    ::memset(&p5, 0, sizeof(p5));
    p5.type = 0;          // 普通朋友圈
    p5.flag = 0x1D4C0;    // 调用方常量 0x1D4C000000000 的高 32 位
    BuildMsString(p5.str, text);

    // variant：逐项试探哪个参数不能为空（崩了 SEH 兜住，只记录现场）
    switch (variant)
    {
    case 1:  p5.extra = p2;              break;  // extra = P2
    case 2:  p5.extra = singleton;       break;  // extra = 单例
    case 3:  p5.extra = &p1;             break;  // extra = P1
    case 4:  *(void**)((char*)&p1 + 0x28) = p2;   break;  // P1+0x28 = P2
    case 5:  p5.type = 1;                break;
    case 6:  p5.type = 0x10;             break;
    case 7:  p5.flag = 0;                break;
    case 8:  break;                      // 故意不构造 P3（对照）
    // ★ P1 在 +0x18 处有 std::string（buf@0x18 / size@0x28 / cap@0x30），
    //   小函数 0x04EB3910 从这里把它拷进 P3+0x18 —— 正文很可能在这里而不是 P5
    case 10: BuildMsString((char*)&p1 + 0x18, text); break;
    case 11: BuildMsString((char*)&p1 + 0x18, text);
             BuildMsString(p5.str, text); break;
    default: break;
    }

    int ret = CallCtorGuarded(fn, &p1, p2, p3, p4, &p5);

    if (diag) *diag = DiagJson(base, singleton, p2, stage, ret);
    return ret;
}

void Route_SendMoment(httplib::Server& svr)
{
    // POST /SendMoment { "text": "...", "stage": 1|2 }
    svr.Post("/SendMoment", [](const httplib::Request& req, httplib::Response& res)
        {
            json resp;
            json reqJson;
            try { reqJson = json::parse(req.body); }
            catch (...)
            {
                resp["ret"] = -1;
                resp["retmsg"] = "invalid json";
                res.set_content(resp.dump(), "application/json");
                return;
            }

            std::string text = reqJson.value("text", "");
            int stage = 1;
            if (reqJson.contains("stage") && reqJson["stage"].is_number())
                stage = reqJson["stage"].get<int>();

            if (stage >= 2 && text.empty())
            {
                resp["ret"] = -1;
                resp["retmsg"] = "stage2 requires non-empty text";
                res.set_content(resp.dump(), "application/json");
                return;
            }

            int variant = 0;
            if (reqJson.contains("variant") && reqJson["variant"].is_number())
                variant = reqJson["variant"].get<int>();

            std::string diag = "{}";
            std::string wxid = reqJson.value("wxid", "wxid_3odtthhn7u5t22");
            int ret = WeixinMoment::SendMoment(text, stage, &diag, variant, wxid);

            resp["ret"] = ret;
            resp["retmsg"] = (ret == 0) ? "ok" : "failed";
            try { resp["diag"] = json::parse(diag); }
            catch (...) { resp["diag"] = diag; }
            res.set_content(resp.dump(), "application/json");
        });

    // GET /SendMoment 看能力探测
    svr.Get("/SendMoment", [](const httplib::Request&, httplib::Response& res)
        {
            uintptr_t base = WxBase();
            json j;
            j["base"] = (unsigned long long)base;
            j["ctorRva"] = (unsigned long long)offset::mmsnspost_ctor;
            j["singletonRva"] = (unsigned long long)offset::sns_singleton_ptr;
            j["singleton"] = base ? (unsigned long long)(uintptr_t)(*(void**)(base + offset::sns_singleton_ptr)) : 0;
            j["note"] = "POST {text, stage:1} 只探测；stage:2 才真正调用 mmsnspost（有崩溃风险）";
            res.set_content(j.dump(), "application/json");
        });
}


// ═════════════════════════════════════════════════════════════════════════════
//  MOMENT-CAPTURE：勾住 0x04EB0B90，让用户手动发一条朋友圈，把真实参数与调用栈全录下来
//
//  为什么这么做：调试器会被微信反调试干掉，但本 DLL 已经在进程内，
//  MinHook 只是改函数入口跳转（和现有 send_message/xlog 的 hook 同一种技术），
//  不会被反调试判定为"被调试"。录到的是真实 UI 发表流程的参数与栈，
//  这样就不必再盲猜 P1..P5 的语义。
// ═════════════════════════════════════════════════════════════════════════════
typedef int (*MomentFn5T)(void*, void*, void*, void*, void*);

namespace
{
    MomentFn5T      g_momentOrig = nullptr;
    bool            g_momentHooked = false;
    volatile LONG   g_capHits = 0;
    volatile DWORD  g_capTid = 0;
    volatile ULONGLONG g_capP[5] = {0,0,0,0,0};
    volatile ULONG  g_capType = 0, g_capFlag = 0;
    volatile ULONGLONG g_capTextSize = 0, g_capTextCap = 0;
    char            g_capText[260] = {0};
    volatile ULONGLONG g_capP1Size = 0, g_capP1Cap = 0;
    char            g_capP1[260] = {0};
    volatile int    g_capFrames = 0;
    volatile int    g_p1Len = 0, g_p3Len = 0, g_p4Len = 0, g_p5Len = 0;
    unsigned char   g_p1Raw[0x100] = {0};   // P1 原始字节
    unsigned char   g_p3Raw[0x1C0] = {0};   // P3 原始字节（0x1A0 + 余量）
    unsigned char   g_p4Raw[0x40]  = {0};   // P4 原始字节
    unsigned char   g_p5Raw[0x60]  = {0};   // P5 原始字节（type/flag/string）
    volatile int    g_p3aLen = 0, g_p3bLen = 0;
    unsigned char   g_p3aRaw[0x200] = {0};  // P3+0x10 指向对象
    unsigned char   g_p3bRaw[0x200] = {0};  // P3+0x38 指向对象
    volatile int    g_p1PostLen = 0;        // ★ 调用返回后的 P1（已构建的请求）
    unsigned char   g_p1PostRaw[0x400] = {0};
    volatile int    g_q28Len = 0, g_q30Len = 0, g_q40Len = 0;
    volatile int    g_p2Len = 0, g_p2aLen = 0, g_p2bLen = 0, g_p2cLen = 0;
    unsigned char   g_p2Raw[0x300] = {0};   // P2 本身
    unsigned char   g_p2aRaw[0x300] = {0};  // *(P2+0x00)
    unsigned char   g_p2bRaw[0x300] = {0};  // *(P2+0x08)
    unsigned char   g_p2cRaw[0x300] = {0};  // *(P2+0x10)
    unsigned char   g_q28Raw[0x400] = {0};  // *(P1+0x28)
    unsigned char   g_q30Raw[0x400] = {0};  // *(P1+0x30)
    unsigned char   g_q40Raw[0x400] = {0};  // *(P1+0x40)
    volatile ULONGLONG g_capStack[20] = {0};

    void SafeCopy(void* src, void* dst, int n, volatile int* pLen)
    {
        __try { for (int i = 0; i < n; ++i) ((unsigned char*)dst)[i] = ((const unsigned char*)src)[i]; *pLen = n; }
        __except (EXCEPTION_EXECUTE_HANDLER) { *pLen = 0; }
    }

    void TakeString(const void* base, size_t off, volatile ULONGLONG* pSize,
                    volatile ULONGLONG* pCap, char* dst, size_t dstLen)
    {
        const char* p = (const char*)base + off;
        size_t sz  = *(const size_t*)(p + 0x10);
        size_t cap = *(const size_t*)(p + 0x18);
        *pSize = sz;
        *pCap  = cap;
        if (sz > dstLen - 1) sz = dstLen - 1;
        const char* src = (cap >= 0x10) ? *(const char**)p : p;
        if (!src) return;
        for (size_t i = 0; i < sz; ++i) dst[i] = src[i];
        dst[sz] = 0;
    }

    int MomentDetourImpl(void* p1, void* p2, void* p3, void* p4, void* p5)
    {
        __try
        {
            g_capTid = GetCurrentThreadId();
            g_capP[0] = (ULONGLONG)(uintptr_t)p1;
            g_capP[1] = (ULONGLONG)(uintptr_t)p2;
            g_capP[2] = (ULONGLONG)(uintptr_t)p3;
            g_capP[3] = (ULONGLONG)(uintptr_t)p4;
            g_capP[4] = (ULONGLONG)(uintptr_t)p5;

            // 先做原始内存 dump（放在读字符串之前，避免后者异常把它们跳过）
            // P2 及其头三个指针（正文可能挂在 P2 上）
            if (p2)
            {
                SafeCopy(p2, (void*)g_p2Raw, 0x100, &g_p2Len);
                void* a = *(void**)((char*)p2 + 0x00);
                void* b = *(void**)((char*)p2 + 0x08);
                void* c = *(void**)((char*)p2 + 0x10);
                if (a) SafeCopy(a, (void*)g_p2aRaw, 0x100, &g_p2aLen);
                if (b) SafeCopy(b, (void*)g_p2bRaw, 0x100, &g_p2bLen);
                if (c) SafeCopy(c, (void*)g_p2cRaw, 0x100, &g_p2cLen);
            }

            if (p1) SafeCopy(p1, (void*)g_p1Raw, 0x100, &g_p1Len);
            if (p3) SafeCopy(p3, (void*)g_p3Raw, 0x1C0, &g_p3Len);
            if (p4) SafeCopy(p4, (void*)g_p4Raw, 0x40,  &g_p4Len);
            if (p5) SafeCopy(p5, (void*)g_p5Raw, 0x60,  &g_p5Len);
            if (p3)
            {
                void* q1 = *(void**)((char*)p3 + 0x10);
                void* q2 = *(void**)((char*)p3 + 0x38);
                if (q1) SafeCopy(q1, (void*)g_p3aRaw, 0x200, &g_p3aLen);
                if (q2) SafeCopy(q2, (void*)g_p3bRaw, 0x200, &g_p3bLen);
            }

            // P5 = { DWORD type; DWORD flag; std::string text@+08; void* extra@+28 }
            if (p5)
            {
                g_capType = *(ULONG*)p5;
                g_capFlag = *((ULONG*)p5 + 1);
                TakeString(p5, 0x08, &g_capTextSize, &g_capTextCap, g_capText, sizeof(g_capText));
            }
            // P1 +0x18 处也有一个 string（小函数会把它拷进 P3+0x18）
            if (p1)
            {
                TakeString(p1, 0x18, &g_capP1Size, &g_capP1Cap, g_capP1, sizeof(g_capP1));
            }

            // 原始内存 dump：P1 / P3 / P4（含正文可能在 P3 内部）

            // 真实调用栈（转成相对 Weixin.dll 的 RVA，只留模块内的帧）
            void* frames[20] = {0};
            USHORT n = RtlCaptureStackBackTrace(1, 20, frames, nullptr);
            uintptr_t base = (uintptr_t)GetModuleHandleA("Weixin.dll");
            int k = 0;
            for (USHORT i = 0; i < n && k < 20; ++i)
            {
                uintptr_t a = (uintptr_t)frames[i];
                if (base && a >= base && a < base + 0x0AF0E000)
                    g_capStack[k++] = a - base;
            }
            g_capFrames = k;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
        InterlockedIncrement(&g_capHits);

        int r = g_momentOrig(p1, p2, p3, p4, p5);
        // ★ 调用返回后再 dump P1：此时 mmsnspost 请求已构建，序列化正文应在其中
        if (p1)
        {
            SafeCopy(p1, (void*)g_p1PostRaw, 0x400, &g_p1PostLen);
            void* q28 = *(void**)((char*)p1 + 0x28);
            void* q30 = *(void**)((char*)p1 + 0x30);
            void* q40 = *(void**)((char*)p1 + 0x40);
            if (q28) SafeCopy(q28, (void*)g_q28Raw, 0x400, &g_q28Len);
            if (q30) SafeCopy(q30, (void*)g_q30Raw, 0x400, &g_q30Len);
            if (q40) SafeCopy(q40, (void*)g_q40Raw, 0x400, &g_q40Len);
        }
        return r;
    }

    // 无 SEH 的包一层，保证对象展开不冲突
    int MomentDetour(void* p1, void* p2, void* p3, void* p4, void* p5)
    {
        return MomentDetourImpl(p1, p2, p3, p4, p5);
    }

    bool InstallMomentHook()
    {
        if (g_momentHooked) return true;
        uintptr_t base = (uintptr_t)GetModuleHandleA("Weixin.dll");
        if (!base) return false;
        MH_STATUS st = MH_Initialize();
        if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) return false;
        LPVOID target = (LPVOID)(base + offset::mmsnspost_ctor);
        if (MH_CreateHook(target, (LPVOID)&MomentDetour, (LPVOID*)&g_momentOrig) != MH_OK)
            return false;
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            return false;
        }
        g_momentHooked = true;
        return true;
    }

    bool RemoveMomentHook()
    {
        if (!g_momentHooked) return true;
        uintptr_t base = (uintptr_t)GetModuleHandleA("Weixin.dll");
        if (base)
        {
            LPVOID target = (LPVOID)(base + offset::mmsnspost_ctor);
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        g_momentHooked = false;
        g_momentOrig = nullptr;
        return true;
    }

    std::string CaptureJson()
    {
        std::string j = "{\"hooked\":";
        j += g_momentHooked ? "true" : "false";
        char buf[512];
        std::snprintf(buf, sizeof(buf),
            ",\"hits\":%ld,\"tid\":%lu,\"type\":%lu,\"flag\":%lu,"
            "\"p1\":\"0x%llX\",\"p2\":\"0x%llX\",\"p3\":\"0x%llX\",\"p4\":\"0x%llX\",\"p5\":\"0x%llX\"",
            (long)g_capHits, (unsigned long)g_capTid,
            (unsigned long)g_capType, (unsigned long)g_capFlag,
            g_capP[0], g_capP[1], g_capP[2], g_capP[3], g_capP[4]);
        j += buf;

        j += ",\"textSize\":";
        j += std::to_string((unsigned long long)g_capTextSize);
        j += ",\"textCap\":";
        j += std::to_string((unsigned long long)g_capTextCap);
        j += ",\"text\":\"";
        for (const char* p = g_capText; *p; ++p)
        {
            unsigned char c = (unsigned char)*p;
            if (c == 0x22 || c == 0x5C) { j += (char)0x5C; j += (char)c; }
            else if (c < 0x20) { char t[8]; std::snprintf(t, sizeof(t), "%04X", c); j += (char)0x5C; j += 'u'; j += t; }
            else j += (char)c;
        }
        j += "\",\"p1Text\":\"";
        for (const char* p = g_capP1; *p; ++p)
        {
            unsigned char c = (unsigned char)*p;
            if (c == 0x22 || c == 0x5C) { j += (char)0x5C; j += (char)c; }
            else if (c < 0x20) { char t[8]; std::snprintf(t, sizeof(t), "%04X", c); j += (char)0x5C; j += 'u'; j += t; }
            else j += (char)c;
        }
        auto hexOf = [](const unsigned char* b, int n)
        {
            std::string h;
            static const char* D = "0123456789abcdef";
            for (int i = 0; i < n; ++i) { h += D[b[i] >> 4]; h += D[b[i] & 0xF]; }
            return h;
        };
        j += "\",\"p1Raw\":\"";
        j += hexOf(g_p1Raw, (int)g_p1Len);
        j += "\",\"p3Raw\":\"";
        j += hexOf(g_p3Raw, (int)g_p3Len);
        j += "\",\"p4Raw\":\"";
        j += hexOf(g_p4Raw, (int)g_p4Len);
        j += "\",\"p5Raw\":\"";
        j += hexOf(g_p5Raw, (int)g_p5Len);
        j += "\",\"p3aRaw\":\"";
        j += hexOf(g_p3aRaw, (int)g_p3aLen);
        j += "\",\"p3bRaw\":\"";
        j += hexOf(g_p3bRaw, (int)g_p3bLen);
        j += "\",\"p1PostRaw\":\"";
        j += hexOf(g_p1PostRaw, (int)g_p1PostLen);
        j += "\",\"q28Raw\":\"";
        j += hexOf(g_q28Raw, (int)g_q28Len);
        j += "\",\"q30Raw\":\"";
        j += hexOf(g_q30Raw, (int)g_q30Len);
        j += "\",\"q40Raw\":\"";
        j += hexOf(g_q40Raw, (int)g_q40Len);
        j += "\",\"p2Raw\":\"";
        j += hexOf(g_p2Raw, (int)g_p2Len);
        j += "\",\"p2aRaw\":\"";
        j += hexOf(g_p2aRaw, (int)g_p2aLen);
        j += "\",\"p2bRaw\":\"";
        j += hexOf(g_p2bRaw, (int)g_p2bLen);
        j += "\",\"p2cRaw\":\"";
        j += hexOf(g_p2cRaw, (int)g_p2cLen);
        j += "\",\"stack\":[";
        for (int i = 0; i < g_capFrames; ++i)
        {
            char t[28];
            std::snprintf(t, sizeof(t), "%s\"0x%llX\"", i ? "," : "", g_capStack[i]);
            j += t;
        }
        j += "]}";
        return j;
    }
}

void Route_SendMomentCapture(httplib::Server& svr)
{
    // POST /SendMoment/Hook { "on": true|false }  —— 装上/卸下 mmsnspost 捕获钩子
    svr.Post("/SendMoment/Hook", [](const httplib::Request& req, httplib::Response& res)
        {
            json resp;
            json body;
            try { body = json::parse(req.body); } catch (...) { body = json::object(); }
            bool on = body.value("on", true);
            bool ok = on ? InstallMomentHook() : RemoveMomentHook();
            resp["ok"] = ok;
            resp["hooked"] = g_momentHooked;
            resp["hits"] = (long)g_capHits;
            res.set_content(resp.dump(), "application/json");
        });

    // GET /SendMoment/Capture —— 读录制结果
    svr.Get("/SendMoment/Capture", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(CaptureJson(), "application/json");
        });

    // POST /SendMoment/Capture  {"reset":true} —— 清空计数，重新录
    svr.Post("/SendMoment/Capture", [](const httplib::Request&, httplib::Response& res)
        {
            InterlockedExchange(&g_capHits, 0);
            g_capFrames = 0;
            g_capText[0] = 0;
            g_capP1[0] = 0;
            g_capType = g_capFlag = 0;
            g_capTextSize = g_capTextCap = g_capP1Size = g_capP1Cap = 0;
            for (int i = 0; i < 5; ++i) g_capP[i] = 0;
            json resp; resp["ok"] = true; resp["hits"] = 0;
            res.set_content(resp.dump(), "application/json");
        });
}


// ── BIZ-CAPTURE：勾住业务层 0x04EAE7F0(rcx=对象, rdx=&结构)，看"内容"从哪来 ──
namespace
{
    typedef int (*BizFn)(void*, void*);
    BizFn           g_bizOrig = nullptr;
    bool            g_bizHooked = false;
    volatile LONG   g_bizHits = 0;
    volatile ULONGLONG g_bizRcx = 0, g_bizRdx = 0;
    volatile int    g_bizRcxLen = 0, g_bizRdxLen = 0;
    unsigned char   g_bizRcxRaw[0x200] = {0};
    unsigned char   g_bizRdxRaw[0x300] = {0};
    volatile int    g_bizP1Len = 0, g_bizP2Len = 0;
    unsigned char   g_bizP1Raw[0x300] = {0};   // *(rdx+0x00) 之类的首指针
    unsigned char   g_bizP2Raw[0x300] = {0};
    volatile ULONGLONG g_bizA = 0, g_bizB = 0, g_bizC = 0, g_bizD = 0;

    int BizDetour(void* rcx, void* rdx)
    {
        __try
        {
            g_bizRcx = (ULONGLONG)(uintptr_t)rcx;
            g_bizRdx = (ULONGLONG)(uintptr_t)rdx;
            if (rcx) SafeCopy(rcx, (void*)g_bizRcxRaw, 0x200, &g_bizRcxLen);
            if (rdx)
            {
                SafeCopy(rdx, (void*)g_bizRdxRaw, 0x300, &g_bizRdxLen);
                void* a = *(void**)((char*)rdx + 0x00);
                void* b = *(void**)((char*)rdx + 0x08);
                void* c = *(void**)((char*)rdx + 0x10);
                void* d = *(void**)((char*)rdx + 0x18);
                g_bizA = (ULONGLONG)(uintptr_t)a; g_bizB = (ULONGLONG)(uintptr_t)b;
                g_bizC = (ULONGLONG)(uintptr_t)c; g_bizD = (ULONGLONG)(uintptr_t)d;
                if (a) SafeCopy(a, (void*)g_bizP1Raw, 0x300, &g_bizP1Len);
                if (b) SafeCopy(b, (void*)g_bizP2Raw, 0x300, &g_bizP2Len);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
        InterlockedIncrement((volatile LONG*)&g_bizHits);
        return g_bizOrig(rcx, rdx);
    }

    bool InstallBizHook()
    {
        if (g_bizHooked) return true;
        uintptr_t base = (uintptr_t)GetModuleHandleA("Weixin.dll");
        if (!base) return false;
        MH_STATUS st = MH_Initialize();
        if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) return false;
        LPVOID t = (LPVOID)(base + 0x04EAE7F0);
        if (MH_CreateHook(t, (LPVOID)&BizDetour, (LPVOID*)&g_bizOrig) != MH_OK) return false;
        if (MH_EnableHook(t) != MH_OK) { MH_RemoveHook(t); return false; }
        g_bizHooked = true;
        return true;
    }

    bool RemoveBizHook()
    {
        if (!g_bizHooked) return true;
        uintptr_t base = (uintptr_t)GetModuleHandleA("Weixin.dll");
        if (base)
        {
            LPVOID t = (LPVOID)(base + 0x04EAE7F0);
            MH_DisableHook(t); MH_RemoveHook(t);
        }
        g_bizHooked = false; g_bizOrig = nullptr;
        return true;
    }

    std::string BizJson()
    {
        auto hexOf = [](const unsigned char* b, int n) {
            std::string h; static const char* D = "0123456789abcdef";
            for (int i = 0; i < n; ++i) { h += D[b[i] >> 4]; h += D[b[i] & 0xF]; }
            return h;
        };
        std::string j = "{\"hooked\":";
        j += g_bizHooked ? "true" : "false";
        char buf[256];
        std::snprintf(buf, sizeof(buf), ",\"hits\":%d,\"rcx\":\"0x%llX\",\"rdx\":\"0x%llX\","
            "\"a\":\"0x%llX\",\"b\":\"0x%llX\",\"c\":\"0x%llX\",\"d\":\"0x%llX\"",
            (int)g_bizHits, g_bizRcx, g_bizRdx, g_bizA, g_bizB, g_bizC, g_bizD);
        j += buf;
        j += ",\"rcxRaw\":\"" + hexOf(g_bizRcxRaw, (int)g_bizRcxLen) + "\"";
        j += ",\"rdxRaw\":\"" + hexOf(g_bizRdxRaw, (int)g_bizRdxLen) + "\"";
        j += ",\"p1Raw\":\"" + hexOf(g_bizP1Raw, (int)g_bizP1Len) + "\"";
        j += ",\"p2Raw\":\"" + hexOf(g_bizP2Raw, (int)g_bizP2Len) + "\"";
        j += "}";
        return j;
    }
}

void Route_SendMomentBiz(httplib::Server& svr)
{
    svr.Post("/SendMoment/BizHook", [](const httplib::Request& req, httplib::Response& res)
        {
            json body; try { body = json::parse(req.body); } catch (...) { body = json::object(); }
            bool on = body.value("on", true);
            bool ok = on ? InstallBizHook() : RemoveBizHook();
            json r; r["ok"] = ok; r["hooked"] = g_bizHooked; r["hits"] = (int)g_bizHits;
            res.set_content(r.dump(), "application/json");
        });
    svr.Get("/SendMoment/BizCapture", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(BizJson(), "application/json");
        });
}

// 生成朋友圈请求体 XML（结构照实测抓包）
std::string BuildMomentXml(const std::string& text, const std::string& wxid, bool priv)
{
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            case 0x27: o += "&apos;"; break;
            default: o += c;
            }
        }
        return o;
    };
    long long ts = (long long)time(nullptr);
    std::string x;
    x.reserve(700);
    x += "<TimelineObject><id>0</id><username>";
    x += esc(wxid);
    x += "</username><createTime>";
    x += std::to_string(ts);
    x += "</createTime><contentDesc>";
    x += esc(text);
    x += "</contentDesc><contentDescShowType>0</contentDescShowType><contentDescScene>0</contentDescScene><private>";
    x += priv ? "1" : "0";
    x += "</private><sourceUserName></sourceUserName><sourceNickName></sourceNickName>"
         "<publicPhotoAccountUserName></publicPhotoAccountUserName><publicPhotoAccountNickName></publicPhotoAccountNickName>"
         "<sightFolded>0</sightFolded><showFlag>0</showFlag>"
         "<ContentObject><contentStyle>2</contentStyle><title></title><description></description><mediaList/></ContentObject>"
         "</TimelineObject>";
    return x;
}

