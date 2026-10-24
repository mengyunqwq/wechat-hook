# 变更记录

## 1.1.0（2026-10-24）

### 修复：客户端在 `Weixin.dll+0x32BB50C` 崩溃（sqlite lookaside 损坏）
- 根因：Hook 走 `sqlite3_api_routines` 函数表调 `prepare/step`，**绕过了 sqlite 的连接互斥锁**；
  与客户端线程并发时会踩坏 lookaside 空闲链表。
- 修复：新增 `SqliteConnLock`，查库/备份前后用 `api->db_mutex / mutex_enter / mutex_leave`
  拿同一把连接锁（recursive，重入安全）。

### 修复：登录前就装数据库钩子（早装）
- 客户端秒登录时，DB 在 Hook 装 open16/prepare 之前就打开了，句柄登记不上 → 查库全失败。
- 新增 `xmgr::StartEarlyArmThread()`：DLL 加载后轮询 API 表，一填好就装钩子（幂等）。
- 安装入口（install/installCode/installPrepare/rearm）加 `recursive_mutex`，避免早装线程与
  首次 HTTP 查询并发重复挂钩。

### 其它
- `/QueryDB/execute` 成功拿到库句柄时置 `g_IsLogin=1`（桥不再误判未登录）
- `backup()` 也套同一把连接锁

### 验证
- 冷启动：首次查询前 `registry=36 / named=30`，contact/session/message 三库立即只读
- 查询 1~10ms，无死锁；发送 ret=0

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