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
## 动态探针：拿到 4.1.15.56 的真实发送调用栈（2026-10-24 14:35）

工具链：`wxdump.dll`（146KB，纯 Win32，无 MinHook）
- 由 ilink 代理调用 `WxDumpStart()` 启动
- patch `ws2_32!send` 头 12 字节为 `mov rax, my_send; jmp rax`
- 第一次调用时记录 `RtlCaptureStackBackTrace` 并恢复原字节（只抓一次）

实测：在 4.1.15.56 上给文件传输助手发一条文字，抓到调用栈：

```
[send] bytes=861
  Weixin.dll+0x4DC7DFB     ← 最内层，直接调用 send（含 WSAGetLastError，网络发送封装）
  Weixin.dll+0x66C04CB
  Weixin.dll+0x4E83297
  Weixin.dll+0x4E7CD51
  Weixin.dll+0x121D26
  KERNEL32.DLL+0x2E8D7
  ntdll.dll+0x8C53C
```

### Ghidra 环境（已就绪）

```
Ghidra 12.2 + JDK 25（E:\tools\ghidra / E:\tools\jdk25）
脚本：E:\tools\gh_scripts\decompile_at.java（按 RVA 反编译）
已验证：反编译 0x4DC7D90 成功（含 WSAGetLastError 调用）
```

### 下一步

1. 反编译 0x66C04CB / 0x4E83297 / 0x4E7CD51 / 0x121D26 所在函数
2. 找消息业务层（构造 TextRequest / 调 send 的那一层）
3. 得到 4.1.15.56 的发送入口 RVA → 写进 hook
## 资产清点（上下文压缩前必读）

### 工具链（都装好了，可直接用）

| 工具 | 路径 | 用途 |
|---|---|---|
| Ghidra 12.2 | `E:\tools\ghidra\ghidra_12.2_PUBLIC` | 反编译（需 JDK 25）|
| JDK 25 | `E:\tools\jdk25\jdk-25.0.4.1+1` | Ghidra 要求 |
| x64dbg | `E:\tools\x64dbg\release\x64\x64dbg.exe` | 动态调试（备用）|
| Ghidra 脚本 | `E:\tools\gh_scripts\decompile_at.java` | 按 RVA 反编译 |
| Ghidra 项目 | `E:\tools\gh_proj\wx`（/Weixin.dll 已导入，noanalysis）| |

启动 Ghidra 命令模板：

```
set JAVA_HOME=E:\tools\jdk25\jdk-25.0.4.1+1
E:\tools\ghidra\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat E:\tools\gh_proj wx -process Weixin.dll -noanalysis -scriptPath E:\tools\gh_scripts -postScript decompile_at.java <RVA_HEX> <LEN_HEX>
```

### 动态探针（已验证可用）

`D:\微信deepseek\data\wxdump\wxdump2.cpp` → 编译成 `wxdump.dll`（102KB）

- 纯 Win32（无 MinHook、无 CRT stdio），导出 `WxDumpStart`
- 由 ilink 代理（`D:\微信deepseek\data\proxy\proxy.cpp`）在加载时调用
- 作用：patch `ws2_32!send`，第一次调用记录调用栈后自动恢复
- 部署位置：`D:\wxhook\wx4156\4.1.15.56\wxdump.dll`
- 日志：`D:\wxhook\wx4156\4.1.15.56\wxdump.log`

### 已抓到的发送调用栈（4.1.15.56）

```
Weixin.dll+0x4DC7DFB   ← 直接调用 send 的网络封装（反编译确认含 WSAGetLastError）
Weixin.dll+0x66C04CB
Weixin.dll+0x4E83297
Weixin.dll+0x4E7CD51
Weixin.dll+0x121D26
```

### 关键环境问题与解法（免得重踩）

```
1. Ghidra 12.2 要求 JDK 25（不是 21）；本机 java 是 D:\ 平铺安装、缺 release 文件
   → 已下载 JDK 25 到 E:\tools\jdk25，JAVA_HOME 指向它
2. Ghidra 12 用 PyGhidra，headless 下 .py 脚本不可用 → 改用 .java 脚本
3. FlatProgramAPI.disassemble 只有 (Address) 单条重载 → 用 DisassembleCommand
4. createFunction 只有 (Address, String) 重载 → createFunction(addr, null)
5. 先 clearListing(range) 再反汇编，避免残留 1 字节函数导致反编译为空
6. wxdump 最初用 MinHook + CRT stdio 会导致 Weixin.exe 崩溃（0xC0000409）
   → 改成纯 Win32 + 手写 inline patch 后稳定
```
## 当前进度（2026-10-24 14:45，压缩前存档）

### 已完成

1. **动态探针可用**：`wxdump.dll` 在 4.1.15.56 上成功 patch `ws2_32!send` 并抓到真实调用栈
2. **发送调用栈**（4.1.15.56）：
   ```
   Weixin.dll+0x4DC7DFB   ← 网络发送封装（含 WSAGetLastError）
   Weixin.dll+0x66C04CB
   Weixin.dll+0x4E83297
   Weixin.dll+0x4E7CD51
   Weixin.dll+0x121D26
   ```
3. **Ghidra 12.2 + JDK 25 环境可用**，能反编译指定 RVA（0x4DC7D90 已验证）

### 进行中（卡点）

反编译调用栈上层函数时，脚本输出解析有问题（伪代码没保存到文件）。
已创建 `E:\tools\gh_scripts\func_of_ret.java`（向前找函数起点 → 反编译），
需要修正它把伪代码写到 `E:\tools\gh_out\<rva>.c`。

### 下一步

1. 修好 `func_of_ret.java` 的写文件逻辑（`PrintWriter` 那段替换没生效，需检查锚点）
2. 依次反编译 0x4E7CD51 / 0x4E83297 / 0x66C04CB 所在函数
3. 从中识别「构造 TextRequest → 调发送」的业务层 → 得到发送入口 RVA
4. 把该 RVA 写进 hook 的新版分支，验证发文字

### 工具速查

```
JAVA_HOME = E:\tools\jdk25\jdk-25.0.4.1+1
headless  = E:\tools\ghidra\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat
项目      = E:\tools\gh_proj  （程序 /Weixin.dll，noanalysis）
脚本目录  = E:\tools\gh_scripts
```
## 调用栈逐层分析结果（2026-10-24 15:00）

反汇编 5 个返回地址的调用点，结论：

| 返回地址 | 所在函数 | 分析结论 |
|---|---|---|
| 0x4DC7DFB | 0x4DC7D90（429B）| 网络发送封装，含 `WSAGetLastError`，调 `ws2_32!send` |
| 0x4E7CD51 | 0x4E7CA6A 附近 | 虚函数调用（`call rax`，rax=[rdi]+0x60），附近字符串 `"net_stat_ is empty"` → 网络统计/上报 |
| 0x4E83297 | — | 大对象虚调用（参数含 `[rsi+0x1318]`）→ 网络管理器层 |
| 0x66C04CB | **0x66C04A0**（可靠）| 小 thunk：`sub rsp,0x38; lea r9,[rcx+0x38]; ...` |
| 0x121D26 | **0x121D10**（可靠）| 析构函数：`call 0x121D40; call [rax+8]; call 0x121F60` |

**关键结论：这条调用栈是「发送完成后的清理/统计路径」，不是消息构造路径。**
单次 send 断点抓不到业务层，因为业务层（构造 TextRequest）在更深/更早的调用中。

### 下一步方案（需要动态调试器交互）

要用 x64dbg 在「消息发送」时中断并**向上回溯完整调用栈**（x64dbg 的 Call Stack 窗口直接显示函数名+起始 RVA），再对起点用 Ghidra 反编译。

x64dbg 已装：`E:\tools\x64dbg\release\x64\x64dbg.exe`
- 附加 wx4156 的 Weixin.exe
- 断点：`bp ws2_32.send` 或 `bp ws2_32.WSASend`
- 发消息 → 看 Call Stack 窗口（会自动解析出每个函数的起始 RVA）
- 记录业务层函数 RVA → Ghidra 反编译

### 当前状态

机器人已恢复 4.1.10.27（5 进程、登录、30 表、查询正常）。
## 栈扫描探针（2026-10-24 15:10）

`wxdump3.cpp`（103KB）→ 部署为 `wxdump.dll`
- patch `ws2_32!send` 后，第一次调用时扫描整个栈（rsp ~ rsp+256KB）
- 用 SEH 保护的 `scan_range()` 挑出所有落在 `Weixin.dll` 范围内的 qword
- 输出 `WX+0x...` 列表

### 抓到 512 帧、13 个唯一地址

```
0x76C9F47  (call 0x754BEA0 = __security_check_cookie)
0x76CB501
0x76CB6DA  (call 0x76CBB48)
0x76CB97E  (call 0x76D0FA8)
0x76CBF2B  (call 0x754BEA0)
0x76CC200
0x7707A9F  (call 0x7708424)
0x7708BB1  (call 0x771005C)
0x901247D / 0x90124A6 / 0x9E552C0 / 0x9E6F4D6 / 0xBB8F940（非 call 返回，可能是数据/过期帧）
```

### 重要判断

发送线程的栈里**没有业务层**（构造消息对象那层）。原因：
- 发送是**异步**的（业务线程把消息放进队列，网络线程负责 send）
- 所以我们 hook `send` 只能看到网络线程的栈

### 下一步（要抓业务层，需要换断点位置）

1. **在主线程/UI 线程上探针**：hook `PostMessage`/`DispatchMessage` 或消息循环，发消息时记录栈
2. **hook 消息队列投递**：微信异步发送一般走 task 队列（`0x76CB6DA` 那条链可能就是队列 worker）
3. **hook 数据库写入**：发消息前通常会写 `message_*.db`，hook sqlite 的 `prepare`（表地址已知）能拿到业务层调用栈
4. 或者：**hook 已知的 0x4E7CD4F 虚调用目标**（vtable），看谁调它

### 当前状态

机器人已恢复 4.1.10.27（5 进程、登录、30 表、查询正常）。
## 外部栈采样探针（2026-10-24 15:25）

`wxdump5.cpp` → 部署为 `wxdump.dll`
- 不修改任何代码/数据
- 每 5ms 用 Toolhelp32 + SuspendThread + GetThreadContext 采样所有线程栈
- 只记录「v-5 处是 E8」(即 call 返回地址) 的值，按窗口（0.5s）输出频率

### 实测（发消息时刻 vs 基线）

```
发消息窗口（14:46:23）新增地址：
  0x94C7 / 0x69AF27 / 0x76C9F47
```

反汇编 0x69AF27 / 0x69B03E：都是普通函数结尾（返回 al=1 / 堆管理），**不是发送业务层**。

### 结论

采样分辨率不够（发消息瞬间只有几毫秒），抓不到业务层；**需要断点而不是采样**。

### 下一步建议（同步路径）

发消息前微信会**同步写 `message_*.db`**，可在 sqlite `prepare`（函数 RVA 0x5953070，来自已知 api 表 0x9A907C0 的 #78 槽）上做 inline patch：
- 恢复原字节 → 记录调用栈（SEH 保护）→ 调原函数 → 重新 patch
- 或只在发消息窗口内启用（用文件标志控制）
- 预期：能拿到「UI 线程 → 消息构造 → DB 写入」的完整业务栈

（注意：不能改 api 表本身，会触发微信校验崩溃；只能 patch 表项指向的函数。）
## step 断点探针：抓到发消息时的 DB 调用链（2026-10-24 15:35）

`wxdump7.cpp`（104KB）→ 部署为 `wxdump.dll`
- 目标：api 表（0x9A907C0）第 **#100 槽 = sqlite3_step**（RVA 0x5927600）
- 触发方式：`record.on` 文件存在时 arm（每 100ms 检查），删除后 disarm
- 每次 step：恢复原字节 → 扫栈（只记 call 返回地址）→ 调原函数 → 重新 arm
- 上限 200 次记录

### 实测：发消息时刻（14:49:59.x）的 step 调用链

```
业务层：  0x1491E18 / 0x1493042 / 0x1493788 / 0x149925D
DB 封装： 0x35AE113 / 0x35BD067 / 0x35BD0F6 / 0x35BD448
          0x3602239 / 0x3604DE7 / 0x363DD25 / 0x363E4E6
sqlite：  0x5926DC0 / 0x5928186 / 0x593CBFB / 0x594B279
其它：    0x610C43 / 0x117FE1
```

### 反汇编调用点

```
0x1491E18: call 0x14A47D0       (rsi, r14, r8=0, r9d=ebx)  ← 业务层，消息构造/发送
0x1493788: call 0x3602220       (rdi)                       ← 业务层调 DB 封装
0x35BD067: call 0x35BD090       (rdi, rsi)                  ← DB 层
```

### 下一步

1. 用 Ghidra 反编译 0x1491E18 / 0x1493788 所在函数，确认哪个是「发送文本消息」
2. 顺着 0x14A47D0 往下找真正的发送入口
3. 得到入口 RVA → 写进 hook

### 当前状态

微信 4.1.15.56 正在运行（带 step 探针，未登录状态可随时点「进入微信」）。
机器人未启动（按用户要求，优先搞新版）。
## 区域定性：step 栈抓到的其实都是 WCDB（2026-10-24 15:45）

扫描两段区域的字符串引用，确认：

| 区域 | 字符串特征 | 定性 |
|---|---|---|
| `0x1480000-0x14C0000` | `wcdb_one_or_binary` / `WCDB.Operation` / `com.Tencent.WCDB.Config.*` / "Backup can't be run in transaction" | **WCDB 库** |
| `0x35B0000-0x3640000` | `Unpaired lock` / `Checkpoint-%p` / WAL / `PRAGMA cipher_compatibility` / fts3/fts5 | **WCDB 锁/检查点/加密层** |

也就是说 step 探针抓到的：
```
0x1491E18 / 0x1493788  → WCDB 的 SQL 执行层
0x35BD067 / 0x3602220  → WCDB 的 DB 封装层
0x5928186 / 0x593CBFB  → sqlite 内核
```
**都不是微信的业务层（消息发送）**——业务层在更上层，但被 32KB 栈扫描范围截断了。

### 下一步

把 `wxdump7.cpp` 的栈扫描范围从 `0x8000` 放大到 `0x40000`（256KB），重新抓一次，
应该能看到「业务层 → WCDB → sqlite」的完整链条，才能定位发送入口。

（机器人未启动，微信 4.1.15.56 在跑，随时可测。）
## 256KB 栈扫描：看到完整层次（2026-10-24 15:52）

把 wxdump7 的栈扫描范围从 32KB 放大到 256KB 后重抓，得到 170 个唯一地址。按区域定性：

| 区域 | 字符串特征 | 定性 |
|---|---|---|
| `0x61xxxxx` | SNSWindow / GridImage / QScrollArea / ChatBotHistory / sns_timeline | **Qt GUI 层**（UI 线程）|
| `0x35Bxxxx-0x364xxxx` | Unpaired lock / Checkpoint / WAL / cipher | WCDB 锁/加密层 |
| `0x148xxxx-0x14Cxxxx` | WCDB.Operation / Backup / Migrate | WCDB SQL 层 |
| `0x592xxxx` | sqlite 内核 | sqlite |

**完整链条**：`Qt UI (0x61x) → 业务层 → WCDB (0x35B/0x149) → sqlite (0x592)`

### 非 WCDB / 非 UI 的候选地址（待定性）

```
0x3B3E91 / 0x3B4262 / 0x3B4B1D / 0x3BC89D     (0x3B 区域)
0x3FF3F3 / 0x3FF404 / 0x3FF418 ... (0x3FF 区域，一串相邻)
0x4E7B3C                                        (接近网络层 0x4E7CD51)
0xD8C8DC
0x117FE1 / 0x13003C
```

### 下一步

1. 定性 0x3FF 区域 / 0xD8C8DC（扫字符串）
2. 找到「发送消息」业务函数（很可能在 0x3FF 或 0xD8 段）
3. 从该函数反推：它是否调用 WCDB 插入 + 网络发送
## 顺序化栈：拿到 32 层完整链（2026-10-24 16:05）

`wxdump7` 改为按「首次出现顺序」输出（#00 = 最内层 step 调用者，编号越大越外层）。

一次发消息的完整链（36 个）节选：

```
#00 0x71D52CA    #01 0x61149E (Qt)   #02 0x363DFA0 (WCDB)
#03 0x611B06 (Qt) #04 0x612A40 (Qt)   #05 0x360BF8A (WCDB)
#06 0x5928186 (sqlite)  ...
#11 0x1491E3D (WCDB SQL) #12 0x234C084 (WCDB ORM)
#13 0x149C161 (WCDB)     #14 0x274DF77 (联系人 schema)
#15 0x13003C    #16 0x10B6B3F   #17 0x69AF27
#18 0x754CEAC   #19 0x76DBCAD   #20 0x117FE1
#21 0x7550683   #22 0x10B0655   #23 0x1699136
#24-26 0x570xxxx  #27 0x12E52F0  #28 0x3BC89D
#29 0x1690487    #30 0x570455C  #31 0x34FAAC0
```

### 区域定性（新增）

| 区域 | 字符串特征 | 定性 |
|---|---|---|
| `0x234Cxxx` | "Can not read sql" / "AUTOINCREMENT" / "Auto add column" | WCDB ORM 层 |
| `0x274Dxxx` | contact / chat_room / chatroom_member / name2id / biz_info | **联系人 DB schema** |
| `0x3FFxxxx` | chat_cell_avater_size / file_list_cell_* | Qt 聊天界面布局 |
| `0xD8xxxx` | QMargins / gpu_control / GetFileVersionInfo | Qt/工具层 |

### 仍未定位

「发送消息」业务层。已知它在这条链的 #12~#23 之间某处（既不是 Qt、也不是 WCDB），
候选地址：`0x13003C / 0x10B6B3F / 0x69AF27 / 0x76DBCAD / 0x117FE1 / 0x1699136 / 0x570xxxx / 0x12E52F0 / 0x3BC89D / 0x1690487 / 0x34FAAC0`

### 备注

整个 DLL 里**没有** "message_0/message_1/message.db" 这类字符串（库名是拼接的），
所以不能用库名做锚点。
## SQL 过滤探针尝试与崩溃（2026-10-24 16:20）

`wxdump8.cpp`：hook step + 用 api 表 #161 槽（sqlite3_sql）读 SQL 文本，只记录 INSERT/UPDATE。

结果：**没有抓到任何 SQL，且微信多次崩溃**（14:52/14:53/14:56 三个 dump），
微信进入「安全模式」对话框（"当前检测出微信连续异常"）。

### 崩溃原因

`my_step` 的实现是「恢复原字节 → 调用原函数 → 重新 arm」，
在微信高频 DB 访问（多线程并发）下，**恢复/重打之间存在竞态窗口**，
其他线程可能正好执行到被改写的函数头 → 崩溃。

### 修复方案

改用 **MinHook trampoline**（不恢复/重打，入口挂 jmp + trampoline 跳回），
MinHook 已处理指令重定位，能避免竞态。

（注：之前 MinHook 崩溃是因为 hook 了错误的地址（api 表槽位）；
现在 hook 真实函数 RVA（step = 0x5927600），应该可行。）

### 已恢复

移除探针、重启微信 → 安全模式解除，回到登录页正常。

### 下一步

1. 用 MinHook 重写 step 探针（trampoline 模式）
2. 抓 INSERT/UPDATE 的 SQL 文本 + 顺序栈 → 定位「写消息」业务层
3. 拿到业务层 RVA → 写进 hook
## 探针演进与当前状态（2026-10-24 16:50）

### 探针版本线

| 版本 | 方式 | 结果 |
|---|---|---|
| wxdump5 | 外部栈采样（SuspendThread）| 可用，但分辨率不足 |
| wxdump6 | prepare 断点（恢复/重打）| 发消息不走 prepare |
| wxdump7 | step 断点（恢复/重打）| 抓到 200 条栈，但**竞态崩溃**（安全模式）|
| wxdump8 | step + 读 SQL（恢复/重打）| 崩 |
| wxdump9 | MinHook trampoline | MH_EnableHook 成功但**未触发** |
| **wxdump10** | **手动 trampoline（一次 patch 永久保持）** | **hook 正常触发（STEP HIT 验证）**，但 SQL/db 名读取有问题 |

### 已验证的技术点

```
1. 手动 trampoline 可行：copy 12 字节 + jmp 回原函数 + 12，一次 patch 无竞态
2. 目标地址正确：api 表(0x9A907C0) #100 槽 = step = RVA 0x5927600
3. 登录时 step 被调用（STEP HIT 出现 5 次）
```

### 卡点

```
api 表 #161 槽（sqlite3_sql）返回 NULL → 拿不到 SQL 文本
用 stmt->db + api->db_filename(#192) 过滤 message 库 → 崩溃
```

### 下一步（换方案）

**栈特征过滤**：不用 SQL/db 名，改为「栈里含 Qt UI 层地址（0x6000000-0x7000000）才记录」——
用户操作（发消息）触发的 DB 写入会经过 UI 层，后台轮询不会。
这样能精确抓到「发消息」的 step 调用链。

### 已抓到的完整调用链（117 帧，256KB 扫描）

业务层候选（非 Qt/WCDB）：
```
0x3FA8E1 / 0x3FA8D0 / 0x3FA890 / 0x691D24 / 0x47BABE
0x2296BF / 0xD8946A / 0xD8C8DC / 0xD8D64B / 0x4A11FE / 0x3E1FC / 0x4A3F2F
```
## Qt 栈过滤探针成功（2026-10-24 17:05）

`wxdump11.cpp`：手动 trampoline hook step，只在「栈里含 Qt UI 层地址（0x6000000-0x7000000）」时记录。

结果：**30 个块，每块 132~137 帧**（完整调用链）。

### 固定调用链（出现在 26~29/30 块）

```
0x76DBCAD (29/30)
0x570EFD7 / 0x570455C / 0x570404E / 0x570BCBD / 0x570D8C9   (0x570xxxx)
0x6A16248 / 0x6A165F7                                        (0x6A1xxxx)
0x34FAAC0 / 0x37D44A6 / 0x3BC89D
```

这些是「用户操作 → DB 写入」的**框架层**（任务调度/消息队列），不是发送业务层。

### 结论与转向

继续在 sqlite 层下钻，区分「发消息」与「其他 DB 写」的成本太高。

**建议改为「调用微信自己的 WCDB API」**：
- 0x1480000-0x14C0000 是 WCDB 库（字符串 "WCDB.Operation"）
- 找到 WCDB 的「执行 SQL」接口（接收字符串参数）→ 从我们的线程调用
- 不需要 hook sqlite，也不需要改表 → 最可能绕过保护

### 工具链现状（可直接复用）

```
Ghidra 12.2 + JDK 25     E:\tools\ghidra / E:\tools\jdk25
Ghidra 脚本              E:\tools\gh_scripts\decompile_at.java / func_of_ret.java
探针源码                 D:\微信deepseek\data\wxdump\wxdump5..11.cpp
手动 trampoline 版       wxdump10/11（已验证 hook 生效）
部署位置                 D:\wxhook\wx4156\4.1.15.56\wxdump.dll（由 ilink 代理加载）
触发开关                 D:\wxhook\wx4156\4.1.15.56\record.on
```
## 会话阶段性总结（2026-10-24 17:15）

### 新版（4.1.15.56）适配到什么程度

| 能力 | 状态 |
|---|---|
| 注入（ilink_wrapper 代理 + 延迟加载 core） | ✅ 完成 |
| HTTP 服务（30001，/QueryDB/status 等）| ✅ 稳定 |
| 登录 | ✅ 正常 |
| 读库（sqlite） | ❌ 未完成 |
| 发消息 | ❌ 未完成 |
| 探针工具链（抓调用栈） | ✅ 完成（wxdump5-11 六代）|
| Ghidra 反编译 | ✅ 可用（JDK 25 环境已配好）|

### 读库为什么没完成

1. 改 api 表 → 微信校验崩溃
2. MinHook 挂错地址 → 崩；挂对地址（手动 trampoline）→ 可触发
3. 需要定位「发消息」业务函数，但：
   - 调用栈能抓到（132 帧 × 30 块）
   - 但业务层与框架层混杂，函数起点识别不准（Ghidra 反编译失败率高）

### 下一步（如果继续）

```
A. 修 Ghidra 函数起点识别（用 x64dbg 的调用栈视图，人工确认起点）
B. 找 WCDB 的 execute 接口（0x1480000-0x14C0000 区域），从我们线程调用
C. 保持 4.1.10.27 不动
```

### 机器人

机器人未启动（按用户要求，专心搞新版）。恢复命令：

```
powershell -ExecutionPolicy Bypass -File D:\微信deepseek\scripts\wechat-power.ps1 -Action start
```
## 为什么快不起来（2026-10-24 18:20 复盘）

### 投入与产出

| 已投入 | 产出 |
|---|---|
| 6 代探针（wxdump5-12）| 能抓 132 帧完整调用链 |
| Ghidra 12.2 + JDK 25 环境 | 能局部反编译（但函数起点不准）|
| 全量分析尝试 | 45 分钟未完成（194MB DLL），已停 |
| 静态锚点扫描（字符串/字段名/库名）| **全部失效**（无 rip 相对引用）|
| 注入 + HTTP + 登录 | ✅ 完成且稳定 |

### 卡点根因

1. **静态锚点失效**：`msgSvrId`/`msgId`/`isSend`/`message_1` 等字符串在 DLL 里都存在，但**没有任何 lea/mov 直接引用**（可能通过 ORM 元数据表间接引用）
2. **动态 hook 崩溃**：hook `0x14A47D0`（WCDB 执行入口）签名未知，4 参数透传仍崩
3. **全量分析太慢**：194MB DLL 的 Ghidra 全量分析 > 45 分钟

### 结论

4.1.15.56 的逆向需要 **IDA Pro 级**的完整分析（几十小时），脚本 + 局部反编译无法闭环。

### 建议

1. **机器人继续 4.1.10.27**（完全可用）
2. 新版适配：保留现有成果（注入方案、探针工具链、调用链数据、文档），等有 IDA 环境或愿意投入时再继续
3. 若要新版立刻可用：考虑 miloira 闭源完整版（需付费）

### 环境清理

微信已停止，探针已移除（wxdump.dll.off），机器人可用 wechat-power.ps1 启动。
## 重大进展：codec_get_key 定位成功（2026-10-24 19:10）

### 方法：跨版本函数体精确匹配

用旧版 4.1.10.27 的 `codec_get_key`(RVA 0x4EE64D0) 前 96~384 字节，
在新版 4.1.15.56 里做精确匹配：

```
96 字节  → 1 处命中
128 字节 → 1 处命中
384 字节 → 1 处命中
结果：新版 codec_get_key = RVA 0x57B94A0
```

这说明 **SQLCipher 的 codec_get_key 函数在两个版本里编译结果完全一致**（唯一命中）。

### 同时也确认

- `g_pat_3`（sqlcipher api routines，含绝对地址）→ 新版 0 命中（预期）
- `g_pat_4`（codec_get_key 内部特征）→ 新版 198 命中（不够独特）

### 卡在最后一步

尝试在 `sqlite3_step` hook 里调用 `codec_get_key(db, 0, &key, &len)` 抓密钥 → **崩溃**。

可能原因：
1. `stmt->db` 偏移不对（3.27 结构假设）
2. codec_get_key 需要特定的 db 上下文状态
3. 跨线程/锁问题

### 下一步（如果继续）

1. 验证 stmt->db 偏移（用旧版 4.1.10.27 的已知结构对照）
2. 改用 open_v2 hook + 更早时机（微信启动时数据库已打开，需在代理加载前 hook）
3. 或从内存扫描找 db 句柄（pVfs 特征）

### 已有资产

```
codec_get_key (4.1.15.56) = base + 0x57B94A0   ← 关键成果
api 表 = base + 0x9A907C0（#76 open / #77 open16 / #100 step / #143 open_v2）
```
## 重要纠错：codec_get_key 定位从一开始就是错的（2026-10-24 19:40）

### 证据

反汇编旧版 `0x4EE64D0` 与新版匹配到的 `0x57B94A0`，**两处是同一段代码**：

```asm
0x4EE64C0: lea ebx, [rbx + rbx*4]     ; base32 编码循环
0x4EE64C3: neg r11d
0x4EE64C6: add r11d, r8d
0x4EE64C9: add r11d, 0x23
0x4EE64CD: movzx r11d, byte ptr [r11 + rax]
0x4EE64D2: mov byte ptr [rdx + 1], r11b
```

这是 **base32 编码函数**，不是 codec_get_key。

### 结论

`g_pat_4` 特征码匹配的是 base32 编码函数（新版 198 处命中，说明它根本不独特）。
所谓「96 字节唯一命中」只是匹配到了这个函数体，**不是 codec_get_key**。

**因此旧版 `tryCaptureKey` 抓到的"密钥"很可能一直是无效的**，旧版读库实际走的是客户端连接（不是独立连接 + 密钥）。

### 但这带来一个更好的方案

**不需要密钥**：在 `step` 的 hook 里（客户端线程）：
1. 用 `api->prepare`（#78）准备我们自己的 SELECT
2. 用 **trampoline（原 step）** 执行 —— 不经过 hook，无递归
3. 用 `api->column_text`（#36）读结果
4. `api->finalize`（#63）释放
5. 再调原 step（传进来的 stmt）

全程在**客户端线程**、用**客户端连接**、不跨线程、不改表 —— 安全。

这是新版读库最可行的路径。
## 🎉 突破：新版读库链路打通（2026-10-24 20:05）

### 方案：在 step hook 里用客户端连接执行自己的 SQL

`wxdump18.cpp`：
1. 手动 trampoline hook `sqlite3_step`（RVA 0x5927600，函数头只有 push/sub，安全）
2. 第一次 step 调用时（客户端线程）：
   - `db = *(void**)stmt`（stmt 偏移 0 = db ✓ 已验证）
   - `api->prepare(#78)(db, "SELECT count(*) FROM sqlite_master", -1, &stmt2, 0)`
   - `((step_fn)tramp)(stmt2)` —— 走 trampoline，不触发我们的 hook，无递归
   - `api->column_int(#28)(stmt2, 0)` 读值
   - `api->finalize(#63)(stmt2)`
3. 再调原 step

### 实测日志

```
STEP first: stmt=000002E8A14DA070 db=000002E8A13C5BD0
QUERY rc=100 text=count(*) int=1
```

- `rc=100` = SQLITE_ROW（查询成功）
- `int=1` = column_int 读到了值（这个 db 只有 1 张表）
- prepare / step / column_int / finalize **全部工作**

### 为什么这个方案可行

- 客户端线程（hook 在微信自己的线程里）
- 客户端连接（用传进来的 db，不跨线程）
- 不改表、不新建连接、不需要密钥
- 我们的查询走 trampoline（原函数），不递归

### 下一步

1. 用 `api->db_filename(#192)` 拿库名，按库名查（message_1.db / contact.db）
2. 缓存 db 句柄（多个库）
3. 把查询结果通过 HTTP 接口暴露（/QueryDB）
4. 再接消息轮询
## 🎉🎉 新版读库完全打通（2026-10-24 20:35）

### 关键修正：column_text 槽位是 #42（不是 #36）

api 表存在 **+6 槽位偏移**：
- `column_name` 实际在 #30 → 我们之前用 #36 读到的是列名（"name"）而不是值
- `column_text` 实际在 **#42**（= 36 + 6）

### 实测：成功列出各库的表

```
DB #1   tables: LoginKeyInfoTable
DB #201 tables: contact, name2id, encrypt_name2id, chat_room,
                 chat_room_info_detail, stranger, ticket_info, ...
DB #401 tables: name2id
```

**这是真的读到了微信的数据库结构**（contact 库的表名全部正确）。

### 完整可用链路（已验证）

```
step hook（客户端线程）
  → db = *(void**)stmt              (stmt 偏移 0 = db)
  → prepare(#78)(db, sql, -1, &stmt2, 0)
  → step via trampoline(stmt2)      (原函数，不递归)
  → column_text(#42)(stmt2, 0)      (★ 槽位 42)
  → finalize(#63)(stmt2)
```

### 槽位表（4.1.15.56 实测）

| 函数 | 槽位 |
|---|---|
| step | #100 |
| prepare | #78 |
| finalize | #63 |
| **column_text** | **#42**（不是 36！）|
| column_int | #28 |
| db_filename | #192（调用会崩，不用）|
| open | #76 / #77 / #143（微信不走表，hook 不到）|
| sql | #161（返回 NULL，不用）|

### 下一步

1. 枚举更多库，找到 message 库（表名可能含 msg/chat）
2. 对 message 库执行 `SELECT * FROM <表名> ORDER BY rowid DESC LIMIT 10`
3. 把结果通过 HTTP 暴露