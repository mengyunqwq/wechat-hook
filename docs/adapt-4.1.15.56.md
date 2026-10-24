# 适配微信 4.1.15.56（进行中）

> 目标：把 Hook 从 4.1.10.27 迁到 4.1.15.56 x64（Weixin.dll 194.8MB）。
> 本文记录**已经确认**的新偏移与逆向方法，避免下次从零开始。

## 进展快照（2026-10-24）

| 项 | 状态 |
|---|---|
| 新版客户端副本 | `D:\wxhook\wx4156`（0.86GB）|
| 旧特征码自动迁移 | ❌ 20 条里只有 1 条能唯一命中（5%）→ 逐条重新定位 |
| **sqlite3_api_routines 表** | ✅ **已找到：RVA `0x9A907C0`** |
| sqlite 版本 | ✅ 仍是 **3.27.2**（`3.27.2` 字符串在 .rdata）→ 结构体布局不变 |
| 其余偏移（发送/语音/眼睛/登录） | ⬜ 未开始 |

## 怎么找到 API 表的（可复用的方法）

1. `3.27.2` 字符串在文件 `0x96772E0`（VA `0x189678CE0`）
2. 在 `.text` 里搜引用它的 `lea rax,[rip+d]` → 得到 `sqlite3_libversion`：
   `VA 0x1835DB590`，指令 `48 8D 05 49 D7 09 06 C3`（lea rax,[rip+0x609D749]; ret）
3. 在 `.rdata` 里搜这个函数指针（qword）→ 出现在 file `0x9A8F000`
4. `sqlite3_api_routines` 里 `libversion` 是第 **72** 个字段 → 表起点 = `0x9A8F000 - 72*8 = 0x9A8EDC0`
   → **表 RVA = 0x9A907C0**（VA `0x189A907C0`）

## 已验证的槽位（新表）

| 字段 | 槽位 # | 新 VA | 说明 |
|---|---|---|---|
| libversion | 72 | 0x1835DB590 | 定位锚点 |
| open16 | 77 | 0x1835DF4F0 | **4.x 实际开库入口** |
| prepare | 78 | 0x185953070 | |
| step | 100 | 0x185927600 | |
| finalize | 63 | 0x185926D70 | |
| open_v2 | 143 | 0x1859275D0 | |
| db_filename | 192 | 0x18592E3C0 | |
| db_mutex | 176 | 0x1859291B0 | 返回 NULL（THREADSAFE=2，无连接锁）|
| mutex_enter | 139 | 0x18592D7E0 | |

> 槽位编号与 `xdb/sqlite3.h` 里的 `struct sqlite3_api_routines` 字段顺序一致（260 个字段）。

## 下一步（按依赖顺序）

1. `XWECHAT_SQLITE3_VFS_OFFSET`：在 .data 找 `sqlite3_vfs*` 全局指针（可先跳过，DB 层不依赖）
2. `SQLCIPHER_API_ROUTINES`：小表（9 个字段：key@2、rekey@4 …），找方式：搜引用 "cipher" 或从 codec 结构反查
3. `SQLITE3_CODEC_GET_KEY_FUNC`：取每库密钥，A 方案（独立只读连接）需要
4. `send_message` / 文本、图片、语音构造器：从字符串与调用图找，逐个验证
5. vtable（消息结构）与 `FORWARD_XML_CALL`
6. 眼睛探针（VoiceUploadProbe）：9 个钩子，最后做

## 结论

- 结构体布局没变（sqlite 版本相同）是最大的好消息：**DB 层可以先跑通**
- 发送/语音/眼睛仍需逐个逆，预计 **1~3 天**
- 在完成前，机器人继续用 4.1.10.27（当前稳定）

## 进展：SQLCipher 表 / 密钥函数（2026-10-24 追加）

- `sqlcipher_api_routines` 只有 9 个字段（register_provider / get_provider / key / key_v2 /
  rekey / rekey_v2 / register_custom_provider / unregister_custom_provider / get_fallback_provider）
- 用「9 连 .text 指针」在 .rdata 扫候选：**命中 10 万+**（vtable 区太多），无法唯一定位
- 已知 sqlcipher 相关字符串都在（`cipher_store_pass` @ file 0x9A8D038、`sqlcipher_export` @ 0x9A8D5A3），
  但 `lea rax,[rip+d]` 形式的 xref 没找到（引用寄存器不一定是 rax，需要更宽的 xref 扫描）

### 策略调整

**先不追密钥/独立连接**，因为：

1. 独立只读连接（A 方案）要 `codec_get_key`，它是 sqlcipher 内部函数，定位难度高
2. 4.1.10.27 上「借用客户端连接 + 全局串行化」虽然理论上有并发风险，但实测能长期工作
3. 把目标拆成两步：**先让新版能读库/收消息**（借用连接），再单独攻独立连接

### 阶段 2 计划（新版能读库）

1. 偏移可配置：`XWECHAT_SQLITE3_API_ROUTINES_OFFSET` 支持运行时覆盖（已有），加一份 4.1.15.56 的值
2. 用一个「仅 DB 层」的构建：只装 open16/prepare/step/finalize（新表槽位已知），
   其余用旧偏移的 hook（发送、语音、眼睛、登录监视、xlog）全部 **条件编译关掉**
3. 在新客户端上验证：`/QueryDB/status` + `/QueryDB/execute` 三库可读
4. 通过后再逐个恢复：发送 → 语音 → 图片 → 眼睛
## 阻塞点：注入方式变了（2026-10-24 15:00）

实测新版 4.1.15.56：

```
Weixin.exe  导入表：只有 KERNEL32.dll
Weixin.dll  导入表：只有 KERNEL32.dll
→ 所有其它 DLL 都是运行时 LoadLibrary 加载

我们的 version.dll 放 exe 目录 / 放 4.1.15.56 子目录，均未加载
进程实际加载的是 C:\WINDOWS\system32\version.dll
→ version.dll 代理劫持在 4.1.15.56 上失效
```

ETW（logman / Microsoft-Windows-Kernel-Process）抓 ImageLoad 需要管理员权限，当前会话被拒；
机器上也没有 Procmon。

### 换注入点的候选

新版 Weixin.dll 里动态加载的自有 DLL（且已在客户端目录）：

| 候选 | 大小 | 备注 |
|---|---|---|
| `ilink_wrapper.dll` | 0.23MB | 最小，导出少，优先试 |
| `ConfSdk.dll` | 1.22MB | |
| `roam_migration.dll` | 6.09MB | |
| `VoipEngine.dll` | 19.92MB | 太大 |

做法：把原 DLL 改名（如 `ilink_wrapper_orig.dll`），我们的 DLL 用 `.def` 转发全部导出到 orig，
并保留 hook 初始化逻辑；再验证是否被加载、是否优先于版本目录。

### 结论

适配 4.1.15.56 = **注入方案重做 + 偏移全套重逆**，工作量按周计，不是小时级。
机器人继续跑 4.1.10.27（稳定）。
## 注入点打通：ilink_wrapper 代理（2026-10-24 16:00）

### 已验证

```
新版加载的是 4.1.15.56\ilink_wrapper.dll（版本目录，exe 目录无效）
把原 DLL 改名 ilink_wrapper_orig.dll + 代理转发 8 个导出 → 微信能正常启动（5 进程）
hook 逻辑已接入代理（InitIlinkProxy + CustomInit 起线程等 Weixin.dll）
新版上 /QueryDB/status 能响应（HTTP 30001 起来）
```

### 仍然崩溃

新版下两个 dump：

```
Weixin.dll+0x53B4FE4
Weixin.dll+0x593AC51
```

不是旧版那个固定点，说明还有**旧偏移的探针/钩子**在新版被装到了错误地址。
hook-probe.log 显示 `[probe] SQL 入口探针已就绪` 仍在装（SQL 入口探针用的是旧偏移）。

### 待办（按顺序）

1. 新版模式下禁用所有「只读探针」：SQL 入口探针、PUSH 线程、语音/眼睛（已部分跳过）
2. 只保留 DB 层：open16/prepare/step/finalize（新 api 表槽位已知）
3. 验证三库可读后再逐个恢复
4. 另需适配：登录检测（g_IsLogin）、GetSelfProfile、发送/语音/图片

### 现状

机器人继续跑 4.1.10.27（稳定）；新版适配是长期任务。
## 转向 WCDB 层（2026-10-24 晚）

### 新版 sqlite 的结论

- 新版只有 **一套** sqlite（`3.27.2` 字符串只出现 1 次）
- 没有 SQLite API-armor 的特征字符串（"API call with"、"misuse at line" 均无）
- 但任何「改 api 表 / MinHook 挂钩 / 提前触碰」都会让客户端崩 → 微信在 sqlite 层有自己的保护

### WCDB 痕迹（新版 Weixin.dll）

```
"WCDB" 字符串         file 0x91ED85C
"wcdb_one_or_binary"  file 0x91ED85C 附近
"wcdb_builtin_compression_record" file 0x9186BF8
"Init BaseStorage"    file 0x9186BF8 附近
Name2Id / sqlite_master / chunksizeconfig 等表名
getHandle 字符串       file 0xB3FF5A9
```

没有 `WCDB::` 的 C++ 符号（Release 剥了 RTTI）。

### 已定位的 WCDB 锚点（xref）

| 字符串 | 被引用位置（VA） |
|---|---|
| "Init BaseStorage" | 0x180FDFC3E |
| "wcdb_builtin_compression_record" | 0x1814B85AE |
| "WCDB" | 0x181486026 |

下一步：从 `0x180FDFC3E` 所在函数（WCDB 初始化）往下走，找「数据库句柄获取 / SQL 执行」的封装入口，
从 WCDB 层借道读库，绕开 sqlite 表。

### 现状

机器人继续跑 4.1.10.27；新版适配作为独立项目继续。
### WCDB 逆向第一轮结果（2026-10-24 13:20）

- `"Init BaseStorage"` 的 xref = `0x180FDFC3E`，所在函数起点约 `0x180FDF7D2`（内部调用少，像是初始化/日志）
- `"WCDB"` 的 xref = `0x181486026`，所在函数起点约 `0x181485F71`
- **`"getHandle"` 是误报**：它属于 Qt 的 `PM_DockWidgetHandleExtent` 等字符串，不是 WCDB
- 结论：WCDB 的 C++ 符号在 Release 里被剥离，字符串锚点不足以直接定位“取句柄”的函数

### 继续 WCDB 需要

1. 用 Ghidra/IDA 对 `0x180FDF7D2` 与 `0x181485F71` 两个函数做调用图分析
2. 从 WCDB 初始化往下找 Database 对象构造，再找 handle 获取（可能内联，无独立函数）
3. 或者换思路：从 `sqlite3_open16` 的调用方（WCDB 层）反查——新版 hook 不了表，但可以在**我们自己的线程**里调用 WCDB 的公开接口（若能定位）

### 目前状态（收尾）

- 机器人：4.1.10.27 正常
- 新版：可注入 + HTTP，无 DB 能力
- 这项已从“半天适配”变成“独立的 WCDB 逆向项目”
## 开源项目调研与 4.1.15.13 偏移实测（2026-10-24 晚）

### 找到的项目

| 项目 | 许可 | 支持版本 | 价值 |
|---|---|---|---|
| [xueze-ai/wx-helper](https://github.com/xueze-ai/wx-helper) | MIT | **4.1.15.13** | 完整 C++ 桥接源码（text_bridge.cpp）+ MinHook + 版本指纹 |
| [msfm2018/wxrobot](https://github.com/msfm2018/wxrobot) | — | 4.1.15.13 / 4.1.15.53 分支 | 防撤回补丁（偏移外部传入） |
| [miloira/wxhook](https://github.com/miloira/wxhook) | 闭源 | 声称 4.1.15.56 | pip 包内 DLL 实为 3.x（WeChatWin），需完整版 |

### wx-helper 给出的 4.1.15.13 偏移

```
0x54B02F0  文本消息 Builder（接收 TextRequest{SmallString receiver; SmallString body}）
0x6F4C70   @ 工厂（MinHook hook 目标）
0x8E53588  对象 vtable（校验用）
消息结构：type +0x14、正文 +0x758、成员列表 +0x778、记录步长 0x78
```

### 实测：这些偏移在 4.1.15.56 上失效

```
0x54B02F0 → 变成一个「构造函数」（rcx 作输出指针、写 vtable、ret），与 Builder 语义不符
0x8E53588 → 是 ASCII 字符串（"207C8.09…"），不是 vtable
```

### 旧版 send_message 函数特征也无法迁移

```
旧版 4.1.10.27 send_message = 0x1677A30
取前 16/24/32 字节在新版搜索：命中 83~103 处（都是通用 prologue，定不住）
取前 40 字节：0 命中（函数体已变）
```

### 结论

- 4.1.15.13 → 4.1.15.56 之间偏移已变，不能直接搬运
- 旧版函数字节特征在新版无法唯一定位
- 要在 4.1.15.56 上恢复发送/读库能力，需要 **IDA/Ghidra 级逆向**（几天，且不保证成功）

### 现状

机器人继续使用 4.1.10.27（功能完整、稳定）。
`2026-10-24`