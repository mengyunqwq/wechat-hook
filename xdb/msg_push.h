#pragma once
// ══════════════════════════════════════════════════════════════════════
//  消息写入抓取 + 推送（第三轮）
//
//  分工（保持 db_mgr.cpp 只做"识别"，本文件只做"抓取与投递"）：
//    db_mgr.cpp  挂 SQL 入口钩子、解析 SQL、判断是不是消息写库、
//                解析/查询列清单，然后调这里的 mark()。
//    本文件      记录 bind 的值、成行打包 JSON、有界队列 + 单工作线程
//                POST 到 g_CallBack_Url。
//
//  设计约束（对应任务书红线 4「hook 里绝不阻塞」）：
//    * 微信线程上**绝不做网络 I/O**：只做内存拷贝 + 入队（有界，满了丢最旧并计数）。
//    * POST 全部在一条独立工作线程上，WinHTTP 显式短超时（≤1.5s），失败只记日志。
//    * 开关运行时可切：标记文件存在 = 开；工作线程每 250ms 复查，**无需重启**。
//    * 所有日志量都有上限。
//    * 本文件不碰任何既有逻辑：只被 db_mgr.cpp 的 detour 调用，不返回任何值给 SQLite。
// ══════════════════════════════════════════════════════════════════════
#include <string>
#include <vector>
#include "sqlite3.h"

namespace msgpush {

    typedef void (*LogFn)(const std::string& line);

    // 安装：设日志出口、算好标记文件路径、起工作线程（只起一次）
    void arm(LogFn logger);

    bool enabled();                 // 当前开关状态
    std::string markerPath();       // 标记文件完整路径
    std::string postUrl();          // 推送目标（快照自 g_CallBack_Url）

    // prepare 时机：把这条 INSERT/REPLACE 标进表
    //   pushable = 是否是"要推给桥"的行（表名 Msg_*）
    void mark(sqlite3_stmt* stmt, const std::string& db, const std::string& table,
              const std::vector<std::string>& cols, bool pushable);

    // bind 时机：只处理已标记的 stmt；data/nbytes 仅对 TEXT/BLOB 有效
    void bindValue(sqlite3_stmt* stmt, int idx, int type,
                   const void* data, int nbytes, long long ival, double dval);

    // step 返回 SQLITE_DONE：成行 + 入队。
    // 返回 true = 该 stmt 已被标记（本次已处理）；false = 未标记（调用方可做"补标记"兜底）
    bool rowDone(sqlite3_stmt* stmt);

    // finalize：清理标记
    void finalizeStmt(sqlite3_stmt* stmt);

    // 统计（供日志/调试）
    void stats(long long& marked, long long& queued, long long& sent, long long& failed, long long& dropped);

} // namespace msgpush
