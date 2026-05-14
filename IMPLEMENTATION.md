# Donut 代码实现详解

本文档基于 donut v1.1 源代码分析，逐模块描述其架构与技术实现。

---

## 1. 总体架构

Donut 采用**生成器 + 装载器**双组件模型：

```
┌────────────────────────────────────────────────────┐
│  生成器 (donut.c)                                   │
│  ┌──────────┐  ┌────────┐  ┌──────────┐           │
│  │ 文件分析  │→│ 压缩   │→│ 加密     │           │
│  └──────────┘  └────────┘  └──────────┘           │
│       ↓                                            │
│  ┌──────────────────────────────────────┐          │
│  │ build_instance() → DONUT_INSTANCE    │          │
│  └──────────────────────────────────────┘          │
│       ↓                                            │
│  ┌──────────────────────────────────────┐          │
│  │ build_loader() → CALL + INST + 装载器 │          │
│  └──────────────────────────────────────┘          │
│       ↓                                            │
│  输出: 位置无关 shellcode (PIC)                     │
└────────────────────────────────────────────────────┘
                       ↓
┌────────────────────────────────────────────────────┐
│  装载器 (loader/loader.c 运行时)                     │
│  ┌──────────┐  ┌──────────┐  ┌────────────────┐   │
│  │ API解析  │→│ 解密解压  │→│ 载荷分派执行    │   │
│  │(PEB+哈希)│  │(Chaskey) │  │(PE/CLR/脚本)   │   │
│  └──────────┘  └──────────┘  └────────────────┘   │
└────────────────────────────────────────────────────┘
```

最终生成的 shellcode 内存布局：

```
┌──────────────────────────────────────────────┐
│ CALL $+inst_len        (E8 xx xx xx xx)     │  ← 入口点
├──────────────────────────────────────────────┤
│ DONUT_INSTANCE 结构体                         │
│  ├─ len, key, iv, api[64]    (明文区)       │
│  └─ dll_names, bypass, module... (密文区)    │  ← 加密边界: api_cnt 字段之后
├──────────────────────────────────────────────┤
│ POP ECX                (0x59)                │  ← 获取实例指针
├──────────────────────────────────────────────┤
│ LOADER_EXE 字节码 (预编译的装载器)             │
└──────────────────────────────────────────────┘
```

**CALL技巧**：`E8` 指令执行时会将下一条指令地址压栈，随后 `POP ECX` 获取该地址到寄存器，从而获得 `DONUT_INSTANCE` 的自引用指针——在位置无关代码中定位配置数据的标准技巧。

---

## 2. 核心数据结构

> 所有结构定义见 [include/donut.h](include/donut.h)

### 2.1 DONUT_CONFIG（用户配置）

生成器的顶层配置，由 CLI 参数填充。关键字段：

| 字段 | 用途 |
|------|------|
| `len`, `zlen` | 原始/压缩后文件大小 |
| `arch` | 目标架构: 1=x86, 2=x64, 3=x86+amd64(双模) |
| `bypass` | AMSI/WLDP/ETW 绕过策略 |
| `compress` | 压缩引擎: aPLib / LZNT1 / Xpress |
| `entropy` | 熵级别: 无/随机名称/随机+加密 |
| `format` | 输出格式: 二进制/Base64/C/Python/PowerShell/C#/Hex/UUID |
| `exit_opt` | 退出方式: 线程/进程/阻塞 |
| `inst_type` | 实例类型: EMBED(嵌入) 或 HTTP(远程下载) |
| `mod*`, `inst*`, `pic*` | 指向构建好的模块/实例/最终shellcode的指针 |

### 2.2 DONUT_INSTANCE（运行时配置 — 装载器消费）

装载器 shellcode 在目标进程中读取的核心结构。字段可用分为三层：

**第1层 — 始终明文**（装载器初始化必需）：

| 偏移/字段 | 用途 |
|-----------|------|
| `len` | 结构体总大小 |
| `key` | DONUT_CRYPT 结构：16字节 Chaskey 密钥 + 16字节 CTR 计数器 |
| `iv` | 64位 Maru 哈希初始化向量（每份 shellcode 随机） |
| `api` | 联合体：生成时存 64 个 API 哈希，运行时覆写为 64 个函数指针 |
| `exit_opt` | 退出行为 |
| `entropy` | 熵级别 |
| `oep` | 宿主进程恢复执行的偏移 |
| `api_cnt` | API 导入数量 — **加密边界：此字段之后全部密文** |

**第2层 — 加密区**（运行时先解密再读取）：

| 字段 | 用途 |
|------|------|
| `dll_names` | 分号分隔的 DLL 名列表："ole32;oleaut32;wininet;mscoree;shell32" |
| `bypass`, `amsi*`, `wldp*`, `etw*` | AMSI/WLDP/ETW 绕过所需字符串 |
| `cmd_syms`, `exit_api` | EXE 命令行修补和退出 API 拦截所需符号名 |
| `wscript`, `wscript_exe` | VBS/JS 执行相关字符串 |
| `decoy` | 诱饵模块（模块重载）路径 |
| `type` | 实例类型：EMBED 或 HTTP |
| `server[]`, `username[]`, `password[]` | HTTP 远程参数 |
| `mod_key` | **模块**加解密的独立密钥 |
| `mod_len` | 模块大小 |
| `module` | 联合体：嵌入的 DONUT_MODULE 副本 或 远程下载后的指针 |

**第3层 — API 函数指针联合体**

`api` 字段是 `union { uint64_t hash[64]; void *addr[64]; struct { ... } named; }`。当 `LOADER_H` 宏定义时，展开为命名函数指针结构（`VirtualAlloc`、`LoadLibraryA`、`GetProcAddress` 等 45 个 API），使用 `offsetof` 计算固定索引。这使生成器可以在编译时确定每个 API 指针的偏移量。

### 2.3 DONUT_MODULE（载荷描述）

描述 payload 本身：

| 字段 | 用途 |
|------|------|
| `type` | 模块类型: NET_DLL / NET_EXE / DLL / EXE / VBS / JS |
| `compress` | 使用的压缩引擎 |
| `runtime[]` | CLR 版本字符串 |
| `domain[]` | AppDomain 名称 |
| `cls[]` | 类名 (.NET DLL) |
| `method[]` | 方法/函数名 |
| `args[]` | 参数字符串 |
| `zlen` / `len` | 压缩/原始大小 |
| `data[]` | 柔性数组成员 — 实际的压缩/原始载荷紧随结构体之后 |

### 2.4 DONUT_CRYPT（加密密钥）

```c
typedef struct _DONUT_CRYPT {
    uint8_t mk[DONUT_KEY_LEN];   // 16字节主密钥
    uint8_t ctr[DONUT_BLK_LEN];  // 16字节计数器+Nonce (CTR模式)
} DONUT_CRYPT;
```

---

## 3. 生成器流程

主函数 `DonutCreate()`（[donut.c:1578](donut.c)）的完整 pipeline：

```
1. validate_loader_cfg()    验证用户配置
2. read_file_info()         打开/mmap输入文件 → 分类文件类型 → 解析PE头/.NET元数据
3. validate_file_cfg()      交叉校验(架构匹配、DLL导出检查等)
4. build_module()           压缩载荷 → 构造 DONUT_MODULE → 可选加密模块
5. build_instance()         填充 DONUT_INSTANCE → 计算API哈希 → 加密实例尾部
6. build_loader()           拼接 CALL + 实例 + POP + 装载器字节码 → 最终 shellcode
7. save_loader()            按选定格式写出
```

### 3.1 文件识别（read_file_info）

1. 通过 `mmap` 映射输入文件
2. 检查 DOS/NT 头 → 若为 PE：
   - 读取 `FileHeader.Machine` 判断 x86/x64
   - 检查是否是 DLL（`IMAGE_FILE_DLL`）
   - 扫描 .NET 目录（`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`）→ 提取 CLR 运行时版本
   - 对 .NET 程序集额外检查 `IMAGE_FILE_DLL` 决定 NET_DLL vs NET_EXE
3. 若非 PE：
   - 检查文件扩展名 `.vbs` / `.js` / `.jse` → 对应脚本类型
   - 其他 → 视为原生 EXE（需有重定位表）

### 3.2 压缩（build_module 中的 compress_file）

支持三种引擎：

| 引擎 | 常量值 | 实现 | 可用性 |
|------|--------|------|--------|
| aPLib | 2 | `aP_pack()` 静态库 | 跨平台 |
| LZNT1 | 3 | `ntdll!RtlCompressBuffer` + `COMPRESSION_FORMAT_LZNT1` | 仅 Windows |
| Xpress | 4 | `ntdll!RtlCompressBuffer` + `COMPRESSION_FORMAT_XPRESS` | 仅 Windows |

压缩后的数据存入 `DONUT_MODULE` 尾部的 `data[]`。

### 3.3 加密（build_instance）

加密分两层，使用独立密钥：

1. **实例加密**：仅加密 `api_cnt` 字段之后的部分。位于 `DONUT_INSTANCE` 结构体内，保护所有配置信息。
2. **模块加密**：加密整个 `DONUT_MODULE` 的载荷数据。使用 `mod_key`（独立于实例密钥）。

加密前为每个密钥对生成随机 MAC：`maru(inst->sig, inst->iv)` — 运行时用于验证解密完整性。

密钥生成：Windows 上使用 `CryptGenRandom`，Linux 上使用 `/dev/urandom`。

### 3.4 API 哈希计算（build_instance）

遍历 `api_imports[]` 表，对每个 API 计算：

```c
inst->api.hash[i] = maru(api_name, inst->iv) ^ maru(dll_name, inst->iv);
```

`maru` 是自定义 64 位哈希函数（基于 SPECK-64/128 分组密码）。每个生成的 shellcode 使用不同的随机 IV，使哈希值不可预测，防止预计算攻击。

### 3.5 最终拼接（build_loader）

**x86 布局：**
```
CALL $+inst_len       (E8 + 32位偏移)
DONUT_INSTANCE 数据
POP ECX               (0x59)
POP EDX               (0x5A)
PUSH ECX              (0x51)  → 保存实例指针给装载器
PUSH EDX              (0x52)  → 保存返回地址
LOADER_EXE_X86[]      字节码
```

**x64 布局：**
```
CALL $+inst_len
DONUT_INSTANCE 数据
POP ECX               (0x59) → 实际是 POP RCX
LOADER_EXE_X64_RSP_ALIGN[]  → 16字节栈对齐序言
LOADER_EXE_X64[]            字节码
```

**x84 双模布局（CPU位检测跳板）：**
```
CALL $+inst_len
DONUT_INSTANCE 数据
XOR EAX, EAX         (0x31 0xC0)
DEC EAX              (0x48)
  → 32位模式: DEC EAX, SF=0
  → 64位模式: REX.W + DEC EAX → DEC RAX → 0xFFFFFFFFFFFFFFFF, SF=1
JS <x64_offset>      (0x0F 0x88 xx xx xx xx)
  → SF=1时跳转至x64装载器
  → SF=0时继续x86装载器
LOADER_EXE_X64_RSP_ALIGN[]
LOADER_EXE_X64[]
POP EDX
PUSH ECX
PUSH EDX
LOADER_EXE_X86[]
```

CPU 检测的巧妙之处：`0x48` 在 32 位模式下是 `DEC EAX`（清除符号位），在 64 位模式下是 `REX.W` 前缀，与 `DEC EAX` 组合成 `DEC RAX`（RAX 回绕到最大值，设置符号位）。随后 `JS`（符号位为1则跳转）实现架构分发。

---

## 4. 装载器运行时

入口函数 `DonutLoader()`（[loader/loader.c:36](loader/loader.c)）接收一个 `DONUT_INSTANCE*` 指针。

### 4.1 启动路径

**OEP ≠ 0 模式（恢复宿主进程执行）：**
1. 哈希解析 `CreateThread` → 创建新线程执行 `MainProc(inst)`
2. 哈希解析 `NtContinue` + `GetThreadContext`
3. 修改线程上下文：`RIP ← host_base + oep`，对齐栈指针
4. 调用 `NtContinue()` 将 CPU 跳转到宿主原始入口点
5. 宿主继续正常运行，新线程独立执行载荷

**OEP = 0 模式（默认）：**
直接在当前线程调用 `MainProc(inst)`。

### 4.2 MainProc 主流程

`MainProc()`（[loader/loader.c:101](loader/loader.c)）按严格顺序执行：

1. **Bootstrap API**：哈希解析 `VirtualAlloc` + `VirtualFree` + `RtlExitUserProcess` — 最小操作集合
2. **实例重定位**：分配 RW 内存 → 复制整个 `DONUT_INSTANCE` → 更新指针，确保实例在可写内存中
3. **解密实例**：`donut_decrypt()` 解密 `api_cnt` 之后的密文 → `maru(sig, iv)` 校验 MAC
4. **DLL 加载**：解析 `inst->dll_names`（分号分隔的 DLL 列表），逐个通过 PEB 查找或 `LoadLibraryA` 加载
5. **批量 API 解析**：遍历 `inst->api.hash[1..api_cnt]` — 每个哈希解析为函数地址，覆写同一内存位置
6. **模块获取**：
   - EMBED: 直接使用 `inst->module.x`
   - HTTP: 调用 `DownloadFromHTTP()` 远程下载
7. **AMSI/WLDP/ETW 绕过**（可选）
8. **解压模块**：LZNT1/Xpress（`RtlDecompressBuffer`）或 aPLib（`aP_depack`）
9. **载荷分派**：
   - 原生 DLL/EXE → `RunPE()` — 内存 PE 加载器
   - .NET DLL/EXE → `LoadAssembly()` → `RunAssembly()` → `FreeAssembly()`
   - VBS/JS → `RunScript()` — IActiveScript 执行
10. **清理**：清零 + 释放实例和模块内存，按配置退出线程/进程/阻塞

### 4.3 内存清理模式

整个装载器中一致使用"先清零再释放"的模式：

```c
Memset(ptr, 0, size);              // 先安全清零
VirtualFree(ptr, 0, MEM_RELEASE);  // 再释放
```

这最小化了密钥、载荷、脚本等在内存中的残留。

---

## 5. API 解析系统

位于 [loader/peb.c](loader/peb.c)。完全不依赖导入表，使用 PEB 手动遍历实现自举。

### 5.1 PEB 遍历

```
TEB → PEB → Ldr → InLoadOrderModuleList (双向链表)
    → 遍历每个 LDR_DATA_TABLE_ENTRY
        → BaseAddress + ExportDirectory
```

### 5.2 xGetProcAddressByHash（哈希查找）

```c
xGetProcAddressByHash(hash, iv)
  → 遍历所有已加载 DLL:
      → dll_hash = maru(module_name, iv)
      → 遍历导出表:
          → computed = maru(api_name, iv) ^ dll_hash
          → if computed == hash: 找到目标
```

XOR 与 DLL 哈希的设计使同一个 API 名称在不同 DLL 中有不同的哈希值，防止跨模块冲突。

### 5.3 前向引用处理

如果解析出的地址落在导出目录范围内（即前向引用如 `ntdll.RtlEqualString`），`FindReference()` 解析字符串中的 `"模块.函数"` 格式，递归查找。

### 5.4 Maru 哈希函数

位于 [hash.c](hash.c)。基于 **SPECK-64/128** 分组密码（27 轮 ARX）的 Merkle-Damgard 风格构造：

1. 输入 64 位 IV（初始化向量）
2. 每 16 字节处理一块：`h ^= speck(block, h)`
3. 末尾填充 `0x80` + 比特长度（MD 强化）
4. 输出 64 位哈希

IV 随机化使每个 shellcode 实例的 API 哈希不可预测。

---

## 6. 加密系统

位于 [encrypt.c](encrypt.c)。

### 6.1 Chaskey 分组密码

轻量级 128 位分组密码（128 位密钥）：
1. 状态与密钥 XOR
2. 16 轮 ARX 置换
3. 再次与密钥 XOR

### 6.2 CTR 模式

`donut_encrypt(mk, ctr, data, len)`：
1. 取 16 字节本地缓冲区，初始化为计数器值
2. 用 Chaskey 加密缓冲区得到密钥流
3. 密钥流与明文 XOR（最多 16 字节）
4. 计数器按**大端无符号 128 位**递增（从最低字节开始）
5. 重复处理全部数据

CTR 模式天然对称 — `donut_decrypt` 就是 `donut_encrypt` 的宏别名。

### 6.3 两层密钥体系

```
实例密钥 (inst->key)     → 加密 DONUT_INSTANCE 尾部（配置信息）
模块密钥 (inst->mod_key)  → 加密 DONUT_MODULE 载荷数据

哈希 IV  (inst->iv)       → 多样化 API 哈希值（非密钥，但随机）
```

防御纵深设计：即使模块密钥泄露，实例密钥和配置仍受保护，反之亦然。

---

## 7. PE 内存加载

位于 [loader/inmem_pe.c](loader/inmem_pe.c)，`RunPE()` 函数。

### 7.1 Section 对象映射

**无诱饵模块：**
1. `NtCreateSection(hSection, PAGE_EXECUTE_READWRITE, SEC_COMMIT)`
2. `NtMapViewOfSection(hSection, PAGE_READWRITE)` — 映射 RW 视图
3. 复制 PE 头和所有区段 → 应用重定位
4. `NtUnmapViewOfSection` + 重新映射为 `PAGE_EXECUTE_WRITECOPY`
5. `VirtualProtect` 按各区段特征设置最终权限

**有诱饵模块（模块重载）：**
1. `CreateFileA(decoy_path)` → 打开诱饵文件
2. `NtCreateSection(SEC_IMAGE)` → 创建磁盘镜像 backed section
3. 映射后清零，覆盖目标 PE 的头和区段
4. 在 Process Explorer 等工具中显示为正常的磁盘映射文件

### 7.2 重定位处理

遍历 `IMAGE_DIRECTORY_ENTRY_BASERELOC` 表，应用 `actual_base - preferred_base` 的 delta。支持：
- `IMAGE_REL_BASED_DIR64`（x64）
- `IMAGE_REL_BASED_HIGHLOW`（x86 绝对）
- `IMAGE_REL_BASED_HIGH` / `LOW`

### 7.3 导入表处理

遍历 `IMAGE_DIRECTORY_ENTRY_IMPORT`：
- 每个导入 DLL → `xGetLibAddress()` 查找/加载
- 每个 thunk → 按序数或名称通过 `xGetProcAddress()` 解析

**退出 API 拦截**：若 `inst->exit_api[0] != 0`（生成器填充了退出 API 列表），任何名称匹配 `inst->exit_api` 的导入项被替换为 `RtlExitUserThread`。拦截 `ExitProcess` 等调用，使 EXE 退出时只终止线程而非宿主进程。该机制在以下条件触发：
- 用户指定了 `-t`（线程模式）
- 用户指定了 `-x 1`（DONUT_OPT_EXIT_THREAD，要求宿主进程存活）

拦截列表：`ExitProcess;TerminateProcess;NtTerminateProcess;CorExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit`

### 7.4 延迟导入

同逻辑应用于 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`，包括退出 API 拦截（v1.1 原版遗漏了延迟导入的 Exit API 挂钩，本仓库已修复）。

### 7.5 PE 头覆盖

若 `inst->headers == DONUT_HEADERS_OVERWRITE`：
- 无诱饵：Section 视图和模块数据中的 PE 头均清零
- 有诱饵：复制回原始诱饵的 PE 头 → 内存映射呈现为诱饵文件

### 7.6 TLS 回调

解析 TLS 目录，仅调用 `DLL_PROCESS_ATTACH` 回调（在入口点之前执行一次）。

### 7.7 命令行修补

`SetCommandLineW()`（[inmem_pe.c:689](loader/inmem_pe.c)）：
1. 定位 `kernelbase.dll` 的 `.data` 区段
2. 扫描所有指针大小的值，寻找 `GetCommandLineW()` 的当前缓冲区
3. 找到后用 `RtlCreateUnicodeString` 覆写为新的 `UNICODE_STRING`
4. 同步修补 ANSI 版本
5. 遍历**所有**已加载模块，寻找 `inst->cmd_syms` 中列出的导出符号，修补指向命令行的指针 — 捕获静态链接的 CRT 全局变量（`__argc`/`__argv`/`__wargv`）

---

## 8. CLR 托管（.NET 执行）

位于 [loader/inmem_dotnet.c](loader/inmem_dotnet.c)。

### 8.1 LoadAssembly — 双通道加载

**通道 A — CLR v4+（CLRCreateInstance）：**
```
CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &metaHost)
  → ICLRMetaHost::GetRuntime("v4.0.30319", IID_ICLRRuntimeInfo, &runtimeInfo)
    → ICLRRuntimeInfo::IsLoadable(&loadable)
    → ICLRRuntimeInfo::GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, &corHost)
```

**通道 B — CLR v2 回退（CorBindToRuntime）：**
当 `CLRCreateInstance` 不可用时（早于 Win8）自动触发。

**共同路径：**
1. `ICorRuntimeHost::Start()` — 启动 CLR
2. 获取/创建 AppDomain（默认域或自定义名称）
3. 创建 `SAFEARRAY(VT_UI1)` → 将原始程序集字节拷贝进去
4. `AppDomain::Load_3(safeArray, &assembly)` — 从字节数组加载程序集
5. 立即清零内存中的 safe array 和模块数据（擦除痕迹）

### 8.2 RunAssembly — 调用入口

**.NET EXE：**
```
Assembly::EntryPoint(&methodInfo)
  → MethodInfo::GetParameters(&args)  → 检查 Main(string[] args)
  → 构造 SAFEARRAY<VARIANT> → 包含 SAFEARRAY<BSTR> 参数
  → MethodInfo::Invoke_3(NULL, args, &result)
```

**.NET DLL：**
```
Assembly::GetType_2(className, &type)
  → 解析参数字符串 → SAFEARRAY<VARIANT> of BSTR
  → Type::InvokeMember_3(method, Static|Public, NULL, target, args, &ret)
```

### 8.3 FreeAssembly — COM 释放

按自底向上依赖顺序释放所有 COM 接口：Type → MethodInfo → Assembly → ICorRuntimeHost（UnloadDomain → Stop → Release）→ AppDomain → ICLRRuntimeInfo → ICLRMetaHost。

### 8.4 GUID 嵌入

所有 CLR Hosting 所需的 CLSID/IID 均以原始 GUID 形式嵌入 `DONUT_INSTANCE`，装载器无需查阅注册表或链接 `uuid.lib`。

---

## 9. 脚本执行（IActiveScript）

位于 [loader/inmem_script.c](loader/inmem_script.c) + [loader/activescript.c](loader/activescript.c) + [loader/wscript.c](loader/wscript.c)。

### 9.1 RunScript 流程

1. 分配 RW 内存 → 将 ANSI 脚本转为 Unicode（`MultiByteToWideChar`）
2. 在栈上构造三个 COM vtables：
   - `IActiveScriptSite` — 脚本宿主站点
   - `IActiveScriptSiteWindow` — 窗口支持（stub）
   - `IHost` — WScript 对象实现
3. `CoInitializeEx(COINIT_MULTITHREADED)`
4. `CoCreateInstance(xCLSID_ScriptLanguage, ..., xIID_IActiveScript, &engine)` — CLSID 决定 VBScript vs JScript
5. `IActiveScriptParse::InitNew()`
6. `IActiveScript::SetScriptSite(&site)` — 挂载自定义站点
7. `IActiveScript::AddNamedItem("WScript", SCRIPTITEM_ISVISIBLE)` — 暴露 WScript 对象
8. `IActiveScriptParse::ParseScriptText(script)` — 解析
9. `IActiveScript::SetScriptState(SCRIPTSTATE_CONNECTED)` — 执行（阻塞直到脚本结束）

### 9.2 IHost（WScript）COM 实现

[wscript.c](loader/wscript.c) 实现了 Windows Script Host 的 `IHost` 接口：
- 26 个 vtable 条目（IUnknown + IDispatch + IHost 方法）
- 通过 `LoadTypeLib("wscript.exe")` 加载类型库，供 `GetIDsOfNames`/`Invoke` 使用
- 关键方法：`Quit()` 调用 `InterruptScriptThread` 终止脚本，`Sleep()` 委托给 `kernel32!Sleep`

---

## 10. HTTP 分阶段下载

位于 [loader/http_client.c](loader/http_client.c)，`DownloadFromHTTP()`。

### 10.1 连接流程

1. `InternetCrackUrl()` → 解析服务器 URL（主机名、路径、凭据、端口等）
2. `InternetOpen(PRECONFIG, ...)` → 使用宿主代理设置
3. `InternetConnect(hin, host, port, ...)`
4. `HttpOpenRequest(con, "GET", file, ...)`
5. 对 HTTPS 设置忽略证书错误（`SECURITY_FLAG_IGNORE_*`）
6. 可选设置用户名/密码
7. `HttpSendRequest()`

### 10.2 数据接收

**Content-Length 可用：**
读取 `HTTP_QUERY_CONTENT_LENGTH` → `HeapAlloc` → `InternetReadFile` 一次读取全部。

**Content-Length 不可用（chunked 编码）：**
循环 `InternetQueryDataAvailable()` → 每次 `HeapReAlloc` 扩展缓冲区 → `InternetReadFile` 读取块。

### 10.3 下载后处理

1. 从堆缓冲区复制到 `VirtualAlloc` 的可执行内存
2. 清零堆缓冲区并释放
3. 如果 `entropy == DONUT_ENTROPY_DEFAULT`：用 `mod_key` 解密模块
4. `maru(sig, iv)` 验证 MAC

---

## 11. AMSI / WLDP / ETW 绕过

位于 [loader/bypass.c](loader/bypass.c)。使用编译期功能标志（`BYPASS_AMSI_B` 等）选择具体绕过方案。

### 11.1 AMSI 绕过

**方案A** — 用户自定义（stub，返回 TRUE）。

**方案B — 函数覆写**：定位 `amsi.dll` → 将 `AmsiScanBuffer` 和 `AmsiScanString` 的前几字节覆写为总是返回 `AMSI_RESULT_CLEAN` 的 stub。使用"末端标记函数"技巧计算 stub 长度（两个功能相同但算术不同的标记函数防止 MSVC 合并）。

**方案C — 签名破坏**：在 `AmsiScanBuffer` 的代码中扫描 4 字节签名 "AMSI"，破坏其中一字节 → AMSI 初始化失败。

**方案D — 堆遍历破坏**：加载 `clr.dll` → 扫描可写区段寻找指向堆内存的指针 → 检查目标位置是否含 AMSI 签名 → 破坏。

### 11.2 WLDP 绕过

**方案A** — 用户自定义。

**方案B — 函数覆写**：定位 `wldp.dll` → 覆写 `WldpQueryDynamicCodeTrust`（总返回 S_OK）和 `WldpIsClassInApprovedList`（总设置 `*isApproved = TRUE`）。

### 11.3 ETW 绕过

**方案A** — 用户自定义。

**方案B — RET 指令补丁**：定位 `ntdll!EtwEventWrite` → x64：第一字节写 `0xC3`（ret），x86：前 4 字节写 `0xC2 0x14 0x00`（ret 14h）。阻止 ETW 记录进程事件。

### 11.4 通用模式

所有绕过：PEB 定位 DLL → 解析函数指针 → `VirtualProtect` 改权限 → 覆写代码 → 恢复权限。失败时根据 `inst->bypass` 决定中止或继续。

---

## 12. 构建系统

### 12.1 三条编译链路

| 平台 | Makefile | 编译器 | 产出 |
|------|----------|--------|------|
| Windows x64 | `Makefile.msvc` | MSVC (cl.exe) | donut.exe, donut.dll, loader_exe_x64.h |
| Windows x86 | `Makefile_x86.msvc` | MSVC | 同上(x86), loader_exe_x86.h |
| 交叉编译 | `Makefile.mingw` | MinGW-w64 | donut.exe + 32/64 双头文件 |
| Linux | `Makefile` | GCC | donut, libdonut.so, libdonut.a（使用预生成头文件） |

### 12.2 构建三阶段（MSVC）

**阶段1 — 构建 exe2h：** 编译 PE→C头文件转换工具。

**阶段2 — 构建装载器并转换：**
```cmd
cl loader.c hash.c encrypt.c depack.c clib.c
    -DBYPASS_AMSI_B -DBYPASS_WLDP_A -DBYPASS_ETW_B
    -Zp8 -Gy -Os -O1 -GR- -EHa -GS-
    -I include
link -order:@loader/order.txt -entry:DonutLoader -fixed -nodefaultlib
exe2h loader.exe  → 生成 loader_exe_x64.h / loader_exe_x64.go
```

关键编译选项：
- `-Zp8`：8 字节结构对齐（确保与 DONUT_INSTANCE 二进制兼容）
- `-Gy -Os -O1`：激进体积优化，函数级链接
- `-GS- -GR-`：禁用栈 Cookie 和 RTTI
- `-nodefaultlib`：零 CRT 依赖
- `-order:@loader/order.txt`：强制 `DonutLoader` 为 `.text` 段第一个函数 → 入口即 shellcode 偏移 0

**阶段3 — 构建生成器：** 编译 `donut.c`（`#include` 阶段2产生的头文件），链接 aPLib 静态库。

### 12.3 exe2h 工具

位于 [loader/exe2h/exe2h.c](loader/exe2h/exe2h.c)。将 PE 可执行文件转换为 C/Go 字节数组：

1. `mmap` 输入文件
2. 验证 DOS/NT 头
3. 定位 `.text` 段 → 提取节区原始字节
4. 若为非 PE 原始二进制 → 直接使用全部内容
5. 输出：`unsigned char LOADER_EXE_X64[] = {0x48, 0x89, ...};`（C）/ `var LOADER_EXE_X64 = []byte{...}`（Go）

这一步解决了 Donut 架构的循环依赖：生成器需要嵌入装载器的编译产物，但装载器必须先编译。

### 12.4 Python 模块

[donutmodule.c](donutmodule.c) 将 Donut C API 封装为 Python 扩展：

```python
import donut
shellcode = donut.create(
    file="payload.exe",
    arch=3,    # DONUT_ARCH_X84
    bypass=3,  # DONUT_BYPASS_CONTINUE
    entropy=3, # DONUT_ENTROPY_DEFAULT
    format=1,  # DONUT_FORMAT_BINARY
)
```

PyPI 发布仅包含 sdist（`.tar.gz`），用户安装时本地编译 C 源码。

---

## 13. 输出格式

位于 [format.c](format.c)。支持 9 种输出格式（v1.1 新增 UUID）：

| 格式 | 常量 | 函数 | 输出示例 |
|------|------|------|----------|
| 二进制 | `FORMAT_BINARY` | `fwrite()` 直写 | 原始字节 |
| Base64 | `FORMAT_BASE64` | `base64_template()` | Base64 字符串（Windows 上同时复制到剪贴板） |
| C/Ruby | `FORMAT_C` / `RUBY` | `c_ruby_template()` | `unsigned char buf[] = "\xAA\xBB...";` |
| Python | `FORMAT_PYTHON` | `py_template()` | `buff += b"\xAA\xBB..."` |
| PowerShell | `FORMAT_POWERSHELL` | `powershell_template()` | `[Byte[]] $buf = 0xAA,0xBB,...` |
| C# | `FORMAT_CSHARP` | `csharp_template()` | `byte[] buf = new byte[N] { 0xAA,... };` |
| Hex | `FORMAT_HEX` | `hex_template()` | `\xAA\xBB\xCC...` |
| UUID | `FORMAT_UUID` | `uuid_template()` | UUID 格式字符串，每 16 字节一个 UUID |

---

## 14. 关键设计原则总结

1. **完全位置无关**：无全局变量，无静态数据。所有状态在 `DONUT_INSTANCE` 中。x86 通过 `getpc.c` 实现 PC 相对寻址（`ADR()` 宏）。

2. **零导入表**：所有 API 解析通过 PEB 遍历 + Maru 哈希手动完成。装载器自身从不调用 `GetProcAddress` — 仅在处理 PE 导入和前向引用时使用。

3. **单次编译**：所有 `.c` 文件通过 `#include` 合并到 `loader.c`，产出一个目标文件。配合自定义 `clib.c`（`Memset`/`Memcpy`/`_strcmp`/`stricmp`），实现零 CRT 依赖。

4. **密钥隔离**：实例密钥 ≠ 模块密钥 ≠ 哈希 IV。一处密钥泄露不影响其他层面。

5. **无磁盘接触**：装载器从不写注册表、从不创建磁盘文件（可选诱饵文件为已存在文件）、从不使用可能被安全产品挂勾的标准 API 解析机制。

---

## 15. 退出机制问题分析与修复

### 15.1 问题根因

Donut 有两个**彼此独立**的退出控制开关：

| 开关 | CLI 参数 | 控制字段 | 作用范围 |
|------|----------|----------|----------|
| 退出选项 | `-x` | `inst->exit_opt` | `MainProc()` **返回之后**的行为 |
| 线程模式 | `-t` | `mod->thread` | EXE 入口是否在新线程执行 + IAT 挂钩 |

核心矛盾：`-x 1` (DONUT_OPT_EXIT_THREAD) 仅保证 MainProc 返回后调用 `RtlExitUserThread` 而非 `RtlExitUserProcess`。但当用户**只指定 `-x 1` 不指定 `-t`** 时：

```
RunPE() → Start(PEB)    // 直接调用 EXE 入口点，在主线程内
  → EXE 调用 ExitProcess()
    → 宿主进程立即终止     // MainProc 根本没机会返回
```

源文件中甚至有一条注释承认了这一点（[inmem_pe.c:606](loader/inmem_pe.c#L606) 原版）：

> *"if ExitProcess is called, this will terminate the host process."*

### 15.2 原始设计意图

| 场景 | CLI | 预期行为 |
|------|-----|----------|
| EXE 静态链接 CRT，调用 `exit()` | `-t` | IAT 中 `exit` → `RtlExitUserThread`，线程退出，宿主存活 |
| EXE 无退出调用，正常返回 | `-t` 或 直接 | 入口点返回，代码继续执行清理路径 |
| 不关心宿主存活 | 无 `-t` 无 `-x 1` | EXE 调用 `ExitProcess` → 宿主终止（默认行为） |

### 15.3 发现的 5 个 Bug

**Bug 1 — `-x 1` 不加 `-t` 时无效**

`exit_api` 字符串仅在 `c->thread != 0` 时填充（[donut.c:998](donut.c#L998) 原版）。不加 `-t` 则 `exit_api` 为空 → IAT 不做任何挂钩 → `ExitProcess` 直达内核 → 宿主终止。

**Bug 2 — 延迟导入表不做退出 API 替换**

[inmem_pe.c:338-372](loader/inmem_pe.c#L338-L372) 原版处理延迟导入时完全没有 `IsExitAPI()` 检查。如果 EXE 将退出函数放在延迟导入表（`/DELAYLOAD` 链接选项），`-t` 也拦不住。

**Bug 3 — 动态解析与直接 syscall 无视 IAT 挂钩**

`IsExitAPI` 仅在处理 PE 导入 thunk 时替换函数指针：
- `GetProcAddress(..., "ExitProcess")` → 直接拿到真地址
- 直接调用 `NtTerminateProcess`（syscall）→ 绕过所有 IAT 检测
- 直接调用 `RtlExitUserProcess` → 同上

**Bug 4 — `exit_api` 列表有遗漏**

原版列表缺少 `TerminateProcess`、`NtTerminateProcess`、`CorExitProcess`。如果 EXE 调用这些 API，即使 `-t` 生效也拦不住。

**Bug 5 — TLS 回调不受保护**

TLS `DLL_PROCESS_ATTACH` 回调在 IAT 挂钩生效**之前**就被调用（[inmem_pe.c:496-502](loader/inmem_pe.c#L496-L502)）。如果 TLS 回调调用退出函数，宿主必死。

### 15.4 修复方案

修复了 Bugs 1、2、4，涉及 [donut.c](donut.c) 和 [loader/inmem_pe.c](loader/inmem_pe.c)：

**修复 1 — 退出挂钩触发条件从 `-t` 扩展到 `-x 1`** ([donut.c:997-1004](donut.c#L997-L1004))

```c
// 旧：仅 -t 触发
if(c->thread != 0) {
    strcpy(inst->exit_api, "ExitProcess;exit;...");
}

// 新：-t 或 -x 1 都触发
if(c->thread != 0 || c->exit_opt == DONUT_OPT_EXIT_THREAD) {
    strcpy(inst->exit_api,
        "ExitProcess;TerminateProcess;NtTerminateProcess;CorExitProcess;"
        "exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit");
}
```

**修复 2 — IAT 挂钩条件统一用 `exit_api[0] != 0` 判断** ([inmem_pe.c:323-331](loader/inmem_pe.c#L323-L331))

```c
// 旧：挂钩依赖 -t 标志
if(mod->thread != 0) { ... }

// 新：只要 exit_api 非空就挂钩
if(inst->exit_api[0] != 0) { ... }
```

**修复 3 — 延迟导入表新增退出 API 挂钩** ([inmem_pe.c:368-375](loader/inmem_pe.c#L368-L375))

在延迟导入的名称解析路径中加入了 `IsExitAPI` 检查，与普通导入表逻辑一致。

**修复 4 — 自动线程模式** ([inmem_pe.c:592-604](loader/inmem_pe.c#L592-L604))

当 `exit_api` 非空但用户未显式指定 `-t` 时，自动将 EXE 放入新线程执行：

```c
} else if (inst->exit_api[0] != 0) {
    // 退出 API 挂钩已激活 → 强制线程模式保护宿主
    hThread = CreateThread(NULL, 0, Start, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
    }
} else {
    // 无挂钩 → 直接执行（默认行为）
    Start(NtCurrentTeb()->ProcessEnvironmentBlock);
}
```

### 15.5 仍存在的限制

| 场景 | 是否受保护 | 原因 |
|------|-----------|------|
| 静态导入的 `exit()` / `ExitProcess()` | 是 | IAT + 延迟导入均在挂钩范围内 |
| 静态导入的 `TerminateProcess()` / `NtTerminateProcess()` | 是 | 已加入 `exit_api` 列表 |
| `GetProcAddress` 动态解析退出 API | **否** | 运行时动态解析返回真实地址，绕过 IAT |
| 直接 `syscall NtTerminateProcess` | **否** | syscall 指令不经过导入表 |
| `RtlExitUserProcess` 调用 | **否** | 调用不需要导入表的 ntdll 函数 |
| TLS 回调中调用退出函数 | **否** | TLS 回调在挂钩生效前执行 |
| .NET 程序集的 `Environment.Exit()` | N/A | .NET 由 CLR 管理，不走 PE 导入表 |

Bug 3 和 Bug 5 是架构层面的固有限制，需要更复杂的方案（如 hook `NtTerminateProcess` 的 syscall stub、在 TLS 回调执行前预挂钩等），不在本次修复范围内。

---

*文档基于 donut v1.1 源代码分析及本仓库修复，具体选项与限制以实际代码为准。*
