#pragma once

// 文件队列通道：桥写 req-*.json，hook 轮询执行并写 res-*.json
// （取代不可用的 HTTP 服务端，见 HookQueue.cpp 顶部说明）
namespace hookq {
    void Start();
    void Stop();
}
