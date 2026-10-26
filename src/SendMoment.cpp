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
#include "global.h"
#include "SendMoment.h"

using json = nlohmann::json;

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
        char buf[1536];
        std::snprintf(buf, sizeof(buf),
            "{\"base\":\"0x%llX\",\"singleton\":\"0x%llX\",\"p2\":\"0x%llX\","
            "\"stage\":%d,\"variant\":%d,\"ret\":%d,\"ctorRva\":\"0x%llX\",\"singletonRva\":\"0x%llX\","
            "\"exCode\":\"0x%llX\",\"exAddr\":\"0x%llX\",\"exAddrRva\":\"0x%llX\",\"exAccess\":\"0x%llX\","
            "\"reg\":{\"rcx\":\"0x%llX\",\"rdx\":\"0x%llX\",\"r8\":\"0x%llX\",\"r9\":\"0x%llX\","
            "\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\",\"rsp\":\"0x%llX\",\"rbp\":\"0x%llX\"}",
            (unsigned long long)base,
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
int WeixinMoment::SendMoment(const std::string& text, int stage, std::string* diag, int variant)
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
            int ret = WeixinMoment::SendMoment(text, stage, &diag, variant);

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
