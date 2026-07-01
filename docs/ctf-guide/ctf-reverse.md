# Reverse Engineering — 逆向工程深度参考

## Quick Wins（先试这些）

```bash
# 最基础的——直接提取字符串
strings binary | grep -iE 'flag|ctf|secret|password|恭喜|正确'
rabin2 -z binary 2>/dev/null | grep -i flag
strings binary | head -100

# 信息收集
file binary
xxd binary | head -20
strings binary | grep -E '^/'  # 提取路径
objdump -T binary | head -30   # 查看导入表 (Linux)
# Windows: dumpbin /imports binary.exe

# 动态分析
ltrace ./binary 2>&1 | head -50   # 捕获库调用
strace -f ./binary 2>&1 | head -50  # 捕获系统调用
echo "test" | ./binary

# UPX脱壳
upx -d packed.exe -o unpacked.exe

# PE查壳 (Windows)
# Exeinfo PE, PEiD, Detect It Easy (DIE)
```

---

## 题型总览

| 题型 | 描述 | 关键工具 |
|------|------|---------|
| **算法逆向** | 反编译后分析校验逻辑 | IDA, Ghidra, Z3 |
| **控制流混淆(OLLVM)** | 控制流平坦化/虚假控制流 | deflat, angr |
| **VM逆向** | 自定义虚拟机指令集 | 迹分析, 指令映射 |
| **APK逆向** | Android应用破解 | jadx, apktool, Frida |
| **Python字节码** | 反编译.pyc文件 | uncompyle6, pycdc |
| **.NET/Java** | 托管代码反编译 | dnSpy, jd-gui |
| **固件逆向** | 嵌入式设备固件 | binwalk, Ghidra |
| **密码学集成** | 自定义加密算法 | FindCrypt, 手动识别常量 |
| **WASM逆向** | WebAssembly | wasm-decompile, wabt |
| **PE/ELF加壳** | 壳加密 | 脱壳 + dump |

---

## 主要逆向类型

### 算法逆向（核心考点）
```
1. strings 和 file 基本分析
2. 反汇编/反编译，定位main或关键函数
3. 分析校验逻辑：
   - 逐字节比较 → 直接提取flag
   - 加密/编码 → 逆向算法写解密脚本
   - 数学运算 → 用Z3约束求解
   - CRC/MD5比对 → 爆破/彩虹表
4. 用Z3/angr自动求解
5. 动态调试确认
```

### 控制流混淆

**OLLVM 控制流扁平化 (CFG Flattening)**
- 特征: 大量 switch-case 结构，一个分发器
- 去混淆工具:
  - `deflat.py` — 老牌去平坦化工具
  - `angr` — 符号执行自动绕过

```python
# angr 自动绕过控制流混淆
import angr

proj = angr.Project('./obfuscated_binary',
                    auto_load_libs=False)

# 找到要跳过的地址范围（被混淆的函数）
cfg = proj.analyses.CFGFast()
for func in cfg.functions.values():
    if func.is_plt: continue
    print(f"0x{func.addr:x}: {func.name} ({func.size} bytes)")

# 符号执行找正确路径
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# 找到打印flag的地址
find_addr = 0x401234  # 正确分支
avoid_addrs = [0x401000]  # 错误分支

simgr.explore(find=find_addr, avoid=avoid_addrs)
if simgr.found:
    found = simgr.found[0]
    stdin_data = found.posix.dumps(0)  # 找到的输入
    print(f"Found input: {stdin_data}")
```

---

## IDA Pro 深度使用 (进阶)

### 热键扩展（上篇未覆盖的）

| 快捷键 | 功能 |
|--------|------|
| `Alt+F7` | 运行IDAPython脚本 |
| `Alt+F8` | 查看IDAPython输出 |
| `Shift+F2` | 打开IDC/IDAPython命令行 |
| `Alt+T` | 文本搜索 |
| `Ctrl+T` | 二进制搜索 |
| `Alt+B` | 二进制搜索(下一处) |
| `Ctrl+Alt+B` | 断点列表 |
| `Shift+F3` | 打开调用图 |
| `F12` | 文本视图(全屏模式) |
| `Ctrl+W` | 保存数据库 |

### 无符号/去符号的二进制定位 main

```python
# 方法1: 从入口点
ent = idaapi.get_imagebase() + idaapi.get_entry(0)
print(f"Entry: {hex(ent)}")

# 方法2: 搜索 __libc_start_main
# 找到 call sub_xxx → 第一个参数就是 main
# 或者让 IDA 自动识别

# 方法3: 搜索常见字符串
# Shift+F12 → "Correct!" "Wrong" "flag{" "恭喜"

# 方法4: 找 WinMain (Windows PE)
# IDA 在 PE 加载时会自动识别 WinMain/main
```

### IDAPython 进阶脚本

```python
# 批量重命名 sub_xxx → 基于上下文自动命名
import idaapi, idc, idautils

def rename_subs():
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if name.startswith("sub_"):
            # 检查函数中的字符串引用
            func = idaapi.get_func(func_ea)
            if func is None: continue
            # 遍历指令
            for head in idautils.FuncItems(func_ea):
                if idc.print_insn_mnem(head) == "push":
                    op = idc.get_operand_value(head, 0)
                    string = idc.get_strlit_contents(op)
                    if string and len(string) > 3:
                        clean = string.decode('utf-8', errors='ignore')
                        if clean.isprintable():
                            # 根据字符串命名
                            if 'error' in clean.lower():
                                idc.set_name(func_ea, f"err_{clean[:12]}")
                            elif 'success' in clean.lower() or 'correct' in clean.lower():
                                idc.set_name(func_ea, f"success_{func_ea:x}")
                            break  # 只取第一个

# Patch 二进制（修改指令）
def patch_jnz_to_jmp(addr):
    """把条件跳转改为无条件跳转"""
    # jnz = 75 xx → jmp = EB xx
    bytes_at = idc.get_bytes(addr, 2)
    if bytes_at[0] == 0x75:  # jnz
        idc.patch_byte(addr, 0xEB)
        print(f"Patched JNZ to JMP at {hex(addr)}")
    elif bytes_at[0] == 0x74:  # jz
        idc.patch_byte(addr, 0xEB)
        print(f"Patched JZ to JMP at {hex(addr)}")
```

---

## Z3 符号执行详解

### 基本模式

```python
from z3 import *

# 最简 Z3 求解
flag_len = 32
flag = [BitVec(f'f{i}', 8) for i in range(flag_len)]
s = Solver()

# 约束1：可打印字符
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# 约束2：特定字符（比如flag开头是 ISCC{）
s.add(flag[0] == ord('I'))
s.add(flag[1] == ord('S'))
s.add(flag[2] == ord('C'))
s.add(flag[3] == ord('C'))
s.add(flag[4] == ord('{'))

# 约束3：逆向出的校验逻辑
# 例如: output[i] = (flag[i] + i) ^ 0x55
# expected = [0x66, 0x6c, ...]
# for i in range(flag_len):
#     s.add((flag[i] + i) ^ 0x55 == expected[i])

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[f].as_long()) for f in flag)
    print(f"Flag: {result}")
else:
    print("unsat — 约束条件矛盾")
```

### 高级 Z3 技巧

```python
# 1. 处理非线性约束（乘法）
x = BitVec('x', 32)
s.add(x * x == 100)  # BitVec 支持乘法

# 2. 条件分支模拟
# 如果 flag[i] > 0x60 → 走A分支，否则走B分支
for i in range(flag_len):
    branch = If(flag[i] > 0x60,
                flag[i] ^ 0x55,
                flag[i] + 0x20)
    s.add(branch == expected[i])

# 3. 数组/字符串操作
# 用 Array 模拟
arr = Array('arr', BitVecSort(8), BitVecSort(8))
for i in range(32):
    s.add(arr[i] == 0)

# 4. SMT-LIB 模式（复杂公式用
text = """
(declare-const x Int)
(assert (= x 42))
(check-sat)
(get-model)
"""

# 5. 位运算约束
s.add((flag[i] << 2) == val)  # 左移
s.add((flag[i] >> 2) & 0xFF == val)  # 右移
s.add(ZeroExt(24, flag[i]) * 5 > 0x100)  # 零扩展
```

---

## angr 符号执行（深入）

### 基础用法

```python
import angr
import claripy

# 创建项目
proj = angr.Project('./binary', auto_load_libs=False)

# 基本探索
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x400000+0x1234)  # 正确地址
if simgr.found:
    s = simgr.found[0]
    print(s.posix.dumps(0))  # 标准输入（flag）

# 有符号化的 stdin
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
state = proj.factory.entry_state(
    stdin=angr.SimFile('/dev/stdin', 
                       content=bytes(flag_chars))
)
# 约束：可打印
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234)
if simgr.found:
    s = simgr.found[0]
    flag = ''.join(chr(s.solver.eval(c)) for c in flag_chars)
    print(f"Flag: {flag}")
```

### angr 常用函数

```python
# 跳过某些函数（如反调试）
# 用 hook 跳过
def skip_function(state):
    return None

proj.hook(0x400500, length=5)  # hook(地址, 长度)
# 或用 simprocedure 替换
proj.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())

# 指定约束
# 从指定地址开始
state = proj.factory.blank_state(addr=0x400ABC)

# 设置寄存器
state.regs.rdi = 10

# 求解
solver = state.solver
val = solver.eval(solver.BVV(0x41, 8))  # 输出 'A'
```

---

## 常见加密常量识别（扩展）

### 完整常量参考表

| 十六进制常量 | 算法/用途 | 完整描述 |
|------------|----------|---------|
| `0x67452301, 0xefcdab89` | MD5 | A,B初始值 |
| `0x98badcfe, 0x10325476` | MD5 | C,D初始值 |
| `0x6a09e667, 0xbb67ae85` | SHA-256 | H0,H1 |
| `0x3c6ef372, 0xa54ff53a` | SHA-256 | H2,H3 |
| `0x510e527f, 0x9b05688c` | SHA-256 | H4,H5 |
| `0x1f83d9ab, 0x5be0cd19` | SHA-256 | H6,H7 |
| `0x9e3779b9` | TEA/XTEA/XXTEA | 黄金比例 |
| `0xCBFDAC56` | FNV Hash | FNV-1a 32位偏移基 |
| `0x811C9DC5` | FNV-1a | FNV-1a 32位初始哈希 |
| `0x6b646f6d` | FNV | "kdom" 常见FNV magic |
| `0x63,0x7c,0x77,0x7b` | AES S-Box (前4) | 256字节表 |
| `expand 32-byte k` | ChaCha20/Salsa20 | Sigma常量字符串 |
| `0x61707865` ('expa') | ChaCha20 | Sigma前4字节 |
| `0x3320646e` ('nd 3') | ChaCha20 | Sigma第2组 |
| `0x79622d32` ('2-by') | ChaCha20 | Sigma第3组 |
| `0x6b206574` ('te k') | ChaCha20 | Sigma第4组 |
| `0x6F54AE53` | TEA初始化 | TEA常量 |
| `0x3DA8B2C9` | SM3 | SM3 IV |
| `0x00000000, 0x00000000` | CRC32 | 初始值 |
| `0x04C11DB7` | CRC32 | 多项式 |
| `0x00000000, 0x5A827999` | SHA-0/SHA-1 | K常量 |
| `0x6ED9EBA1, 0x8F1BBCDC` | SHA-1 | K常量 |

### 从常量反推算法

```python
def detect_crypto(constants_hex):
    """从常量列表判断加密算法"""
    if 0x67452301 in constants:
        return "MD5 (A init)"
    if 0x6a09e667 in constants:
        return "SHA-256 (H0 init)"
    if 0x9e3779b9 in constants:
        return "TEA/XTEA/XXTEA"
    if 0xcafebabe in constants:
        return "Java class magic"
    if 0xcbfdac56 in constants:
        return "FNV-1a offset"
    # AES S-Box 检测（256字节）
    aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b])
    # ... 查找这个序列
```

---

## 脱壳技术（进阶）

### 工具脱壳

| 壳 | 命令/工具 | 说明 |
|----|----------|------|
| UPX | `upx -d file.exe -o unpacked.exe` | ✅ |
| ASPack | `unasp` | ✅ |
| MEW | `mew_shella` | ✅ |
| Enigma | 手动 + 脚本 | 较复杂 |
| VMProtect | 高级手工 | ⚠️ 极难 |
| Themida | 手工+WinLicense | ⚠️ 困难 |
| Armadillo | 多线程、Nanomites | ⚠️ OEP检测 |
| Obsidium | 变形引擎 | ⚠️ 需定位 |
| nSPack | `nspack` | ✅ |

### 手动脱壳: OEP 寻找技巧

```
1. ESP定律（已详述）
2. 内存断点法：
   - 对 .text 节设内存访问断点
   - F9 运行 → 停在代码从节读取处
3. 单步跟踪法：
   - 记录 pushad → 等到 popad
   - 之后的 JMP/CALL 就是 OEP
4. 区段跳转法：
   - 壳通常在最后将控制权交给 .text
   - 对壳代码的最后一个远跳转设断点
5. 导入表还原（OEP后必需）：
   - Scylla → IAT Autosearch
   - Get Imports → 修复无效
   - Fix Dump
```

---

## WASM (WebAssembly) 逆向

```bash
# 前置工具
# npm install -g wasm-decompile wabt

# 反编译 WASM 到伪代码
wasm-decompile module.wasm -o module.dcmp

# WASM 转 WAT (文本格式)
wasm2wat module.wasm -o module.wat

# WAT 转 WASM
wat2wasm module.wat -o module.wasm

# 反汇编
wasm-objdump -d module.wasm
```

### WASM 逆向要点

```python
# WASM 是低级的、类型安全的栈式虚拟机
# 特征：
# - 导入(import): 从JS调用的函数
# - 导出(export): 暴露给JS的函数
# - 内存(memory): 线性内存段

# 常见结构
# (module
#   (import "env" "puts" (func $puts (param i32)))
#   (memory (export "memory") 1)
#   (func $check_flag (param i32 i32) (result i32)
#     local.get 0
#     i32.load8_u
#     ... 逐字节比较
#   )
# )

# 反编译后看:
# 1. 是否有硬编码的加密数据
# 2. 逐字节比较 → 直接从 wasm 提取 bytes
# 3. 如果调用 JS 函数 → 分析 JS 代码
```

---

## 固件逆向

```bash
# 使用 binwalk 提取固件
binwalk -Me firmware.bin  # 自动提取
binwalk firmware.bin      # 分析文件结构

# 常见固件特征
# - 文件头: 自定义magic
# - U-Boot: 特定启动镜像
# - 压缩块: LZMA/gzip
# - 文件系统: squashfs, jffs2, yaffs2

# 提取文件系统后
# unsquashfs squashfs-root/squashfs
# 或 7z x rootfs.bin
```

---

## 动态调试技巧

### x32dbg/x64dbg 断点类型

| 类型 | 用法 | 说明 |
|------|------|------|
| 普通断点 | F2 | 执行到该地址 |
| 硬件断点 | Memory → Breakpoint | 对地址的访问/写入 |
| 内存断点 | 选中区域 → Breakpoint | 区域访问 |
| API断点 | 符号→断点 | kernel32!CreateFileA |

### 常用断点组合

```
# 文件操作
CreateFileA/W, ReadFile, WriteFile, CloseHandle

# 内存操作
VirtualAlloc, VirtualProtect, HeapAlloc, malloc

# 字符串
lstrlenA/W, strlen, printf, puts, MessageBox

# 对话框/窗口
GetDlgItemTextA/W, DialogBoxParam

# 注册表
RegQueryValueEx, RegSetValueEx

# 网络
send, recv, connect, WSASend, WSARecv

# 加密
CryptEncrypt, CryptDecrypt, CryptGenKey

# 进程操作
CreateProcess, CreateRemoteThread, WriteProcessMemory
```

---

---

## 新增: APK 逆向完整流程（内容补充）

### jadx 反编译
```bash
# jadx 能直接反编译为可读 Java 源码
jadx -d output_dir app.apk
jadx-gui app.apk  # GUI界面

# 重点看:
# - AndroidManifest.xml → 入口Activity
# - resources/ → 资源文件（可能含加密数据）
# - lib/ → native .so 文件（arm/x86）
# - assets/ → 嵌入文件
```

### Frida 动态调试 APK
```javascript
// hook Java 方法
Java.perform(function() {
    var MainActivity = Java.use('com.example.MainActivity');
    MainActivity.checkFlag.implementation = function(str) {
        console.log('checkFlag called with: ' + str);
        var result = this.checkFlag(str);
        console.log('Result: ' + result);
        return result;
    };
    
    // hook native 函数
    var nativeFunc = Module.findExportByName(null, 'native_check');
    Interceptor.attach(nativeFunc, {
        onEnter: function(args) {
            console.log('args: ' + args[0].readCString());
        },
        onLeave: function(retval) {
            console.log('ret: ' + retval);
        }
    });
});
```

### Objection (Frida 的封装)
```bash
# 自动绕过证书校验、root检测
objection -g com.example.app explore
# 内存搜索
android heap search strings flag
# hook 所有方法
android hooking list classes
```

### APK 签名校验绕过
```bash
# 修改 APK 后需要重打包
apktool d app.apk -o out/
# 修改 out/smali/ 中的代码
apktool b out/ -o modified.apk
# 重新签名
jarsigner -keystore my.keystore modified.apk alias
# 或使用 uber-apk-signer
```

### Unidbg — 模拟执行 SO 文件 ⭐⭐⭐⭐

Unidbg 是 Android Native SO 逆向的利器，可以在 PC 上模拟 ARM 环境执行 .so 文件，
无需真机/模拟器即可调试 Native 层逻辑。

```java
// === Unidbg 基本使用 ===
// 依赖: com.github.zhkl0228:unidbg-android:0.9.7

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

public class MainActivity extends AbstractJni {
    private final AndroidEmulator emulator;
    private final Module module;
    private final VM vm;

    public MainActivity() {
        // 创建32位ARM模拟器
        emulator = AndroidEmulatorBuilder
            .for32Bit()
            .setProcessName("com.example.app")
            .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(
            new AndroidResolver(23));  // API Level 23

        // 创建Dalvik虚拟机
        vm = emulator.createDalvikVM();
        vm.setJni(this);  // 注册JNI回调
        vm.setVerbose(true);

        // 加载SO文件
        DalvikModule dm = vm.loadLibrary(
            new File("libnative.so"), false);
        module = dm.getModule();

        // 调用JNI函数
        // 方式1: 直接调用模块中的函数
        Number result = module.callFunction(
            emulator,
            0x1234 + 1,  // 函数偏移 (奇数=Thumb模式)
            "input_string");

        // 方式2: 通过JNI方式调用
        DvmClass clazz = vm.resolveClass("com/example/MainActivity");
        String ret = clazz.callStaticJniMethod(
            emulator,
            "checkFlag(Ljava/lang/String;)Z",
            "test_input");
        System.out.println("Result: " + ret);
    }

    // 重写JNI回调 (hook系统调用)
    @Override
    public DvmObject<?> callStaticObjectMethodV(
            BaseVM vm, DvmClass dvmClass,
            String signature, VaList vaList) {
        if (signature.equals(
            "java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;")) {
            String key = vaList.getObject(0).getValue().toString();
            // 返回自定义值, 绕过环境检测
            switch (key) {
                case "ro.build.fingerprint":
                    return new StringObject(vm, "google/shamu...");
                case "ro.product.cpu.abi":
                    return new StringObject(vm, "arm64-v8a");
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    public static void main(String[] args) {
        new MainActivity();
    }
}
```

**Unidbg 进阶技巧:**
```java
// 1. Hook 函数调用 (类似于 Frida hook)
emulator.getBackend().hook_add_new(
    new CodeHook() {
        public void hook(Backend backend, long address,
                        int size, Object user) {
            // 在函数入口/出口打印参数
        }
    },
    module.base + 0x1234,
    module.base + 0x1238,
    null);

// 2. 内存补丁 (Patch)
memory.patch(module.base + 0x5678, new byte[]{0x00, 0xBF}); // NOP

// 3. 读取内存
byte[] data = memory.read(module.base + 0x9000, 256);

// 4. 控制台交互 (Console Debugger)
// 添加: emulator.attach().addBreakPoint(module, 0x1234);
// 断点触发时进入交互命令行, 可读写寄存器/内存

// 5. HookZz 框架集成
// 使用 QDBI + HookZz 进行 inline hook
IHookZz hook = HookZz.getInstance(emulator);
hook.replace(module.findSymbolByName("check"),
    new ReplaceCallback() {
        public HookStatus onCall(Emulator<?> emulator,
                                long originFunction) {
            System.out.println("Hooked!");
            return HookStatus.RET(emulator, 1);
        }
    });
```

**Unidbg 常见用途:**
```
1. 加密算法提取: 模拟执行 .so 中的加密/解密函数
2. 签名算法还原: 获取动态生成的签名值
3. 反调试绕过: 对检测函数的JNI调用返回假值
4. 混淆还原: 动态跟踪代码执行路径
5. SO脱壳: 执行壳代码后dump解密后的内存
```

---

## 新增: Go 语言逆向要点

### Go 二进制特征
```
1. 静态链接（不依赖系统libc）
2. 函数名保留（除非strip）
3. 大量 runtime.* 函数
4. 栈大小大（每个goroutine至少2KB）
5. 字符串以 []byte 存储（无终止null）
```

### IDA/Ghidra 逆向 Go
```bash
# Go 二进制的字符串提取
strings binary | grep -E '^[a-z]+\.[a-zA-Z]'  # 包名.函数名

# 恢复函数名（使用 go_parser 插件）
# Ghidra 有 Go 函数识别脚本

# 关键函数定位:
# - main.main → 主入口
# - main.checkFlag → 校验函数

# Go 中的字符串比较:
# runtime.memequal / reflect.DeepEqual
```

### Go 反调试
```go
// Go 可能有 Goroutine 反调试
// 检查: runtime.NumGoroutine() 数量异常
// 或 time.Ticker 周期性检查
```

---

## 新增: Rust 逆向要点

### Rust 二进制特征
```
1. 静态链接 + libc 依赖
2. 函数名 mangling (如 _ZN3std...)
3. 枚举/Result类型使用标签联合
4. Option/Result 大量 match
5. 字符串: &str / String 两种
```

### 关键识别
```
# 字符串定位
# Rust 的字符串有长度前缀（不一定是 null-terminated）

# panic/unwrap → 分支判断
# 大量 match 对应 Option::Some/None

# 工具:
# - rustc demangler 恢复函数名
# - IDA/Ghidra 的 rust 脚本
```

---

## 新增: 反调试与反虚拟机

### 反调试检测点
```python
# 1. ptrace (Linux)
# ptrace(PTRACE_TRACEME, ...) 只能被attach一次
# 绕过: LD_PRELOAD 劫持 ptrace

# 2. IsDebuggerPresent (Windows)
# 读取 PEB.BeingDebugged 标志
# 绕过: NOP掉函数 / 修改EFlags

# 3. NtGlobalFlag (Windows)
# PEB+0x68 的 Flags 在调试下为 0x70

# 4. 时间差检测
# rdtsc / GetTickCount / QueryPerformanceCounter
# 绕过: 记录时间并修改

# 5. 名称检查
# /proc/self/status → TracerPid
# 检查父进程名
```

### 反虚拟机检测
```python
# 常用检测:
# - MAC地址前缀: 00:0C:29 (VMware), 08:00:27 (VirtualBox)
# - 注册表: HKLM\HARDWARE\DEVICEMAP\Scsi\...
# - 进程名: vmtoolsd.exe, VBoxService.exe
# - CPUID: 检查 hypervisor bit
# - 硬盘型号: VBOX HARDDISK, VMware Virtual S

# 绕过:
# - 修改检测点返回值
# - 使用真实的物理机环境调试
```

### 反调试绕过通用方法
```
1. Patch（修改二进制）:
   - 将反调试函数开头改为 xor eax,eax / ret
   - 或直接 NOP 掉所有调用
   
2. Hook:
   - LD_PRELOAD 劫持 ptrace (Linux)
   - API Monitor 拦截 IsDebuggerPresent (Windows)
   
3. 跳过:
   - x64dbg 中跳过检测函数的执行
   - 修改 EFlags/ZF 跳转到正确分支

4. 动态 Patch:
   - 用 Frida / x64dbg 脚本自动 Patch
```

---

## 典型解题流程（完整版）

```
EXE/APK/ELF
  ↓ file / Exeinfo / checksec
  ↓ 查壳
  ├── 有壳 → 脱壳(工具/ESP/单步)
  └── 无壳或已脱壳
  ↓
  ├── PE → IDA / x64dbg
  ├── ELF → IDA / gdb / pwntools
  ├── APK → jadx / Frida / JEB
  ├── Go → 识别函数名 → 逆向
  ├── Rust → demangle → 逆向
  ├── .NET → dnSpy → 直接反编译
  ├── Python .pyc → uncompyle6 / pycdc
  ├── WASM → wasm2wat / wasm-decompile
  └── 固件 → binwalk → 提取文件系统
  ↓
  定位 main / WinMain / onFlagCheck
  搜索字符串 (Shift+F12)
  定位关键比较/加密函数
  ↓
  ├── 逐字节比较 → 直接提取flag
  ├── 编码/变换 → 反向算法 → 解密
  ├── 加密 → 找key/算法常量 → 解密
  ├── 控制流混淆 → 去平坦化工具
  ├── VM → 分析指令集映射
  └── 反调试 → Patch / Hook / NOP
  ↓
  编写 Python 解算脚本（Z3/angr）
  或 Patch 后动态调试直接获取flag
  ↓
  Flag

---

## Custom VM 分析进阶（新增V4）

### VMProtect / Themida 分析流程
```
特征: 大量PUSH/POP模拟栈操作、VM handler表、变形代码

分析步骤:
1. 追踪VM入口 → 记录所有handler地址
2. x64dbg脚本 dump每条handler的输入/输出
3. 分类handler: 算术(ADD/SUB/XOR/SHL/SHR)、内存(LOAD/STORE)、控制流(JMP/JCC/CALL/RET)
4. 构建VM指令集映射 → 写lifting脚本转中间表示

工具: Triton (动态符号执行), Miasm (IR提升), Qiling (模拟执行)
```

### 用 Triton 跟踪 VM 执行
```python
from triton import *
ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setConcreteRegisterValue(ctx.registers.rip, entry_point)
while instruction.getAddress() != vm_exit:
    ctx.processing(instruction)
    vm_regs = extract_vm_state(ctx)  # 记录VM寄存器变化
    log_vm_instruction(instruction, vm_regs)
    ctx.executeNextInstruction()
# 分析trace → 恢复每条VM指令的语义
```

---

## 游戏引擎逆向（新增V4）

### Unity IL2CPP
```bash
# IL2CPP: C# → IL → C++ 原生代码
# 特征: global-metadata.dat + libil2cpp.so
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/
# → 恢复类名/方法名/字段偏移

# Frida hook:
Java.perform(function() {
    var Player = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Player");
    Player.method("getFlag").implementation = function() {
        return Il2Cpp.String("FLAG{...}");
    };
});
```

### Unreal Engine
```
// UObject体系: GObjects → UObject数组 → FName Pool → 字符串查找
// 特征文件: *.uasset / *.uexp (序列化UObject)
// 工具: UE4SS / UnrealContainers / FModel
```

---

## macOS / iOS 逆向（新增V4）

### Mach-O 分析
```bash
lipo -info binary              # Fat Binary检测
lipo -extract arm64 binary -o binary_arm64
class-dump binary              # ObjC类信息提取
jtool --sig app.ipa            # iOS签名检查
codesign -dvvv app.app         # macOS签名检查
```

### iOS Frida 注入
```bash
# 无需重签名即可注入 (越狱设备)
frida -U -f com.target.app -l hook.js
# hook ObjC方法:
# var cls = ObjC.classes.ClassName;
# Interceptor.attach(cls['- methodName'].implementation, { ... });
```

---

## MBA (Mixed Boolean-Arithmetic) 识别（新增V4）

```python
# MBA: 用布尔运算隐藏算术运算
# x+y → (x^y)+2*(x&y)
# x-y → (x^~y)+2*(x&~y)+1
# ~(~a|~b) → a&b (DeMorgan)

# 识别模式:
mba_patterns = {
    '(a^b)+2*(a&b)':            'a+b',       # 加法
    '(a^~b)+2*(a&~b)+1':        'a-b',       # 减法
    '(a|b)-(a&~b)-(~a&b)':      'a&b',       # AND
    '~(~a|~b)':                 'a&b',       # DeMorgan
}
# 工具: msynth (GitHub: mrphrazer/msynth), Triton AST简化
```

---

## Godot / Roblox 游戏资产提取（新增V4）

```bash
# Godot: .pck文件 → godot-unpacker提取
# Roblox: .rbxlx/.rbxl → Roblox Studio读取Lua脚本
# 常见flag位置: 隐藏场景对象、特殊GameObject名称
```

## Haskell / Swift / Kotlin 逆向要点（新增V4）

```
// Haskell GHC: C--中间语言 → STG → 递归结构分析
// Swift: 名称修饰(demangling)、protocol witness table
// Kotlin/JVM: 协程状态机、inline函数展开
// Rust: 无RTTI但panic字符串位置固定
```
```
