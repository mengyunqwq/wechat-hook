#pragma once

#include <string>

// WHAT: 发朋友圈（/SendMoment）
// WHY : 朋友圈发布走微信内部 mmsnspost 请求构造（0x04EB0B90），没有公开 HTTP 接口
// HOW : POST /SendMoment { "text": "...", "stage": 1|2 }
//       stage=1 只探测单例与 P2（安全）；stage=2 真正调用 mmsnspost（可能崩客户端）

namespace httplib { class Server; }

void Route_SendMoment(httplib::Server& svr);
void Route_SendMomentCapture(httplib::Server& svr);

namespace WeixinMoment
{
    // 返回 0 成功；-2 模块未加载；-3 单例为空；-4 虚表异常；-99 访问违例/未实现
    int SendMoment(const std::string& text, int stage, std::string* diag, int variant = 0);
}
