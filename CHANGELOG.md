# 变更记录

## 1.0.0（2026-10-24）

首个公开整理版本。相对上游 aixed/WeChat-Hook 的主要改动：

### 数据库
- Hook `open` / `open16` / `open_v2` / `prepare`，按真实文件名登记句柄
- `safeDbName` 读取整体进 SEH，避免野指针崩溃
- **late-arm**：每次查询前补装缺失的开库钩子（解决重启后 contact.db 读不到）
- `/QueryDB/execute`、`/QueryDB/status`、`/QueryDB/GetAllDBName`、`/QueryDB/debug`

### 发送
- `/SendTextMsg`（支持 atlist 真 @）
- `/SendImgMsg`
- `/SendVoiceMsg`：构造语音消息（type 34）发真语音气泡
- 全局 `recursive_mutex` 串行化查库与发送，降低并发踩内存的概率

### 眼睛（原图 / 整片视频）
- `VoiceUploadProbe`：9 个只读探针钩子 + CDN 重放（`hook-cdn-replay.on`）
- `/Debug/VuProbe` 状态接口

### 其它
- 偏移特征码自动生成（`offset_patterns.h`）+ 运行时扫描（`offset_resolver.cpp`）
- 只监听 127.0.0.1
- 若干诊断路由（`/Debug/ApiTable`、`/Debug/DBRescan`、`/Debug/VoiceDump`）

### 已知问题
- sqlite 连接无锁访问导致 lookaside 损坏（见 docs/reverse-notes.md 第五节）