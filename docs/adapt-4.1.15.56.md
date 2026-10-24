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