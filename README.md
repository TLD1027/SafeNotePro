## SafeNote Pro

### 序

**题目描述**：
In the sprawling, high-rise labyrinth of Neo-Kyoto, where neon streams bleed into the perpetually rain-soaked streets, a new challenge echoes through the digital aether. They say the city's most guarded secrets, the very truths of its elite, are locked away within the pristine, impenetrable core of "Safenote Pro" — a legendary, unhackable data sanctuary. But now, a cryptic breach has fractured its defenses, leaving its supposed invulnerability a chilling legend.

Your mission, if you choose to accept it, is to navigate the "Neon Nexus" of bytes and exploit the very fabric of Safenote Pro's compromised system. Unravel the intricate memory pathways, manipulate the classified data structures, and dance with the ephemeral keys that shift like ghosts in the machine. Bypass the system's stringent security protocols and exploit the delicate balance of its output routines to reveal the hidden "Magic Number" that governs this fractured domain. The "Session ID," a mosaic of fragmented emojis, hints at a deeper, more volatile truth. Can you sort through the chaos, craft your own digital signature, and ultimately uncover the encrypted 'flag' — the hidden secret file — before the city's pulse drowns out your last connection? The future of Neo-Kyoto, and perhaps your own, hinges on revealing this elusive truth.

**分值**：929 pts

**解数**：9 solves

### 分析

程序一开始就加载了一个沙箱，禁用了`execve`和`execveat`，同时关闭了错误输出，把标准输出复制到一个随机的文件描述符中，每一次输出都会重新刷新这个文件描述符。

程序中主要使用了两个函数作为输出函数，一个是`printf_`一个是`puts_`，逻辑都很简单，前后三个参数都是随机字节作为check，第四个参数是实际的参数直接传递给了`printf`和`puts`函数，乍一看这里可能会存在fmt漏洞，但是实际动态调试会发现无法触发（）

程序的主体部分有6个功能，分别是传统的增删改查和排序、设置`Sessionid`，分析add功能可以恢复出结构体：

```c
struct Namelist
{
    char *name;
    uint32_t size;
    char *fmt;
    void (*show_func)(uint8_t, uint8_t, uint8_t, char*, uint8_t, uint8_t, uint8_t);
    float *magic_num;
};
```

`Namelist`是一个0x28的堆块，`name`和`fmt`是用户可控size的堆块，`magic_num`是一个8字节长度的存放浮点数的堆块，`show_func`是从`printf_`和`puts_`中二选一的函数指针。读入浮点数函数是由`strtof`函数实现的，要求除去`+`和`-`之外第一个字节必须是数字。

在删除函数中会释放堆块并清空指针，修改功能只能修改`magic_num`，查询函数会调用`show_func`输出`fmt`并将存储的浮点数作为整数直接输出，每次读写`magic_num`的时候都会检查其所在的地址的高位与`0x114514000`存储的是否一致。排序函数则是给了一次计算除法的机会，可以将`a/b`的结果写入`c`中，但是前提是`a*b!=0 & c==0`，计算完成后使用`qsort`进行排序，排序的规则是根据`magic_num`。最后是一个设置`Sessionid`函数，这个是根据排序后的数组找到最大的数和最小的数，使用`(num - min)/(max - min) * 0x1f`来计算出id并将随机数的最后一字节写入指定id的`Sessionid`中。

#### 漏洞点

很明显的漏洞在于设置`Sessionid`函数，如果排序函数没有达到预期的效果（即max并非最大值或者min并非最小值），就能实现越界写堆列表。由于`nan`有一个特性，任意判断只要包含`nan`都会返回失败，因此如果我们可以构造一个`nan`在数组中就能实现排序异常，但是由于输入的check不能直接输入`nan`，我们选择通过排序时的那一次除法来实现，正常来说能处理出`nan`的运算有`0/0`或者`inf/inf`，而`inf`只需要输入一个较大的数即可实现，这里选择使用`10e2222222222222222`绕过对于输入长度的限制设计输入一个超级大数实现对于`inf`的写入。接着使用简单的爆破脚本就能实现伪造随机数在指定偏移（`offset`）写入指定字节（`code`）：

```c
// g++ -std=c++17 -O2 -pthread -o brute brute.cpp
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <cstdint>

struct Task {
    uint32_t start;
    uint32_t end;
    int offset;
    uint8_t code;
    std::atomic<bool>* found;
    float* result;

    void operator()() const {
        for (uint32_t u = start; u < end && !found->load(); ++u) {
            if ((u & 0xFF) != code)
                continue;
            float num;
            std::memcpy(&num, &u, 4);
            if (!std::isfinite(num))
                continue;

            float product = num * 0x1f;
            if ((int)product == offset) {
                *result = num;
                found->store(true);
                break;
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <offset> <code>" << std::endl;
        return 1;
    }

    int offset = std::stoi(argv[1]);
    int code = std::stoi(argv[2]);

    if (code < 0 || code > 255) {
        std::cerr << "Code must be between 0 and 255." << std::endl;
        return 1;
    }

    int thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0)
        thread_count = 4;

    std::atomic<bool> found{false};
    float result = 0.0f;
    std::vector<std::thread> threads;

    uint64_t total = 1ULL << 32;
    uint64_t chunk = total / thread_count;

    for (int i = 0; i < thread_count; ++i) {
        uint32_t start = static_cast<uint32_t>(i * chunk);
        uint32_t end = (i == thread_count - 1) ? 0xFFFFFFFF : static_cast<uint32_t>(start + chunk);

        threads.emplace_back(Task{
            start,
            end,
            offset,
            static_cast<uint8_t>(code),
            &found,
            &result
        });
    }

    for (auto& t : threads)
        t.join();

    if (found) {
        std::cout << std::fixed << std::setprecision(10)
                << result << std::endl;
    } else {
        std::cout << "Error: not found." << std::endl;
    }

    return 0;
}

```

#### 分析自定义函数

前面提到，我们可以利用越界改写堆列表的地址，但是动调发现分配的堆地址和预期不符，跟踪之后很容易发现程序中的`malloc`函数和`free`函数都是自定义函数（包括`printf`函数和`puts`函数——这也是为什么fmt漏洞无法触发），分析`libtiny.so`中的函数很容易可以理清自定义的分配和释放逻辑：

##### Slab 分配策略

- 将堆空间划分为多个 **slab**，每个 slab 大小为 `64 KiB`。
- 每个 slab 被切成固定大小的 slot，比如：8, 16, 32, ..., 65536 字节。
- slot 的大小通过 `class` 确定，总共支持 `14` 种大小 class（指数增长）。

##### 元数据管理

- 每个 slab 用一个 `SlabMeta` 结构记录起始地址、结束地址、slot class、前后指针。

  ```c
  typedef struct SlabMeta
  {
      uint32_t slab_start_low32;
      uint32_t slab_end_low32;
      int class;
      struct SlabMeta *prev;
      struct SlabMeta *next;
  } SlabMeta;
  ```

- 所有 SlabMeta 链成一个双向链表，便于通过地址反查对应的 class（释放时需要）。

------

##### `malloc()` 分配流程分析

1. 计算 class

   - `alignment = 1 << SMP_MIN_CLASS = 8`（默认对齐 8 字节）

   - 根据所需大小 `len` 找到最小满足需求的 `slot` 大小

2. 优先从`freelist`中取

   - 如果对应 class 的` freelist` 非空，取出链表头节点返回。

   - 同时验证：
     - 其高 32 位地址是否和当前 heap 高位一致。
     - `freelist` 的计数器是否和实际节点数一致（防止链表损坏）。

3. 当前 slab 分配不足，则新建 slab

   - 如果 slab 空了，从 `sbrk` 申请 `64KiB` 内存。

   - 第一次使用时初始化高 32 位映射，保存在只读 mmap 区域（`0x114514000`）。

   - 注册新 slab 到 `slab_meta` 链表，记录地址范围。

4. 分配 slot

   - 直接返回当前 slab 上的一块 slot。

   - 校验高 32 位，清零再返回。

------

##### `free()` 释放逻辑分析

1. 地址合法性验证

   - 地址必须非空。

   - 地址的高 32 位必须与 `get_heap_high32()` 返回值一致。

2. 查找 slab class

   - 遍历 slab_meta 链表，找出该地址对应的 class。

   - 如果找不到 slab，说明非法释放（未分配或越界）。

3. 加入` freelist`
   - 把当前指针插入指定 class 的 `freelist` 链表头。

4. 检查 `freelist` 的合法性

   - 利用快慢指针判断是否出现链表环（防止 double free）。

   - 同时统计链表节点总数，和 `freelist_count` 对比，确保没有内存破坏。

##### 输出函数逻辑

两个输出函数唯一的区别就是`puts`函数会多一个回车，和glibc中的函数区别是，这两个函数都只能输出可见字符。

#### 泄漏地址

搞清楚了堆的释放逻辑之后，我们可以通过错位释放让前一个分配的`Namelist`结构体的`magic_num`结构和下一个`Namelist`结构体的`name`结构重合，分配第二个`Namelist`的时候就会使用`name`堆块覆盖掉原本的`magic_num`堆块，释放第二个`Namelist`的时候把`name`堆块释放放入`freelist`，此时第一个`Namelist`的`magic_num`就会指向一个堆地址，可以泄露出堆地址的低位。

为了便于后续的利用，我们构建了这样一个numlist：

> 0, ... 0, `nan`, `num`, `nan`, 1, ... 1,

这样夹在两个`nan`中间的`num`就可以任意编辑都不会破坏被排序好的`Namelist`了。由于已经获得了堆地址的低位，我们可以把堆列表改成任意堆地址了，我们考虑下面一种情况：

存在一个四级的堆指针链表（比如`freelist`）：

> A --> B --> C --> D

将A作为某个`Namelist`的`magic_num`，那么C的低位就是可以被用户任意编辑的，因为B是一个合法的“堆地址”，

此时如果B也恰好被修改为某个`Namelist`的`magic_num`，由于只能修改C的低位，C依旧是一个合法的"堆地址"，因此我们可以利用这两个`Namelist`配合可以实现任意elf地址和heap地址的读写操作（因为大部分情况下这两个地址的高位都是相同的），这样就能顺利泄露出heap地址，elf地址，libc地址。

#### 劫持程序执行流

由于堆里面存在一个`show_func`指针，我们只需要劫持这个指针就可以劫持程序执行流，但是由于沙箱的存在不能直接通过ogg拿到shell，观察此时的寄存器状态，很容易发现`rcx`是fmt的地址，`r12`是一个可写的栈地址，找到这样一个gadget：

```assembly
.text:0000000000162DA3                 mov     rdi, xdrs
.text:0000000000162DA6                 call    rcx
.text:0000000000162DA8                 test    eax, eax
.text:0000000000162DAA                 jz      loc_162F10
.text:0000000000162DB0                 mov     esi, [rsp+0F8h+shipnow] ; sendnow
.text:0000000000162DB4                 mov     rdi, xdrs       ; xdrs
.text:0000000000162DB7                 call    __GI_xdrrec_endofrecord
```

如果我们将rcx设置为`gets`函数，那么执行完之后就会向下去执行`__GI_xdrrec_endofrecord`函数，此时的`rdi`就是刚刚被写入数据的`r12`，继续跟踪这个函数：

```assembly
# 1606DA
mov    rbx, qword ptr [rdi + 0x18]
mov    rdx, qword ptr [rbx + 0x20] # rdx->0x20
mov    rcx, qword ptr [rbx + 0x30] # rcx->0x30
mov    rax, rdx
sub    rax, rcx
sub    rax, 4
or     eax, 0x80000000
bswap  eax
test   esi, esi
jne    xdrrec_endofrecord+88      

mov    rsi, qword ptr [rbx + 0x18] # rsi->0x18
mov    rdi, qword ptr [rbx]        # rdi->0x0
mov    dword ptr [rbx + 0x38], 0
mov    dword ptr [rcx], eax
sub    rdx, rsi
mov    rbp, rdx
call   qword ptr [rbx + 0x10]      # func->0x10
```

这里我们通过控制`rdi`，也就是我们上一步写入的东西，就可以控制一系列的寄存器，这里我们选择这样的gadget：

> 0x000000000005a120: mov rsp, rdx; ret;

这样我们就可以成功将栈迁移到我们可控的地址去写rop并执行了，这里最后还需要注意的点是要输出flag需要将被随机化的fd作为`write`系统调用的fd，至此就可以顺利拿到我们的flag文件了。

### 非预期

这道题目的本意是，如果只能在`heap`和`elf`的地址范围内读写，能不能通过一个刁钻的函数指针实现任意函数执行。这样设计的目的其实是因为出题人希望选手可以跳出曾经做堆相关题目固化的操作，不考虑任何`io`相关的利用，结合题目本身寻找合适的gadget解题。

然而在实际比赛中还是有队伍绕过了我的检测：在排序函数中，前面提到会将`a/b`的结果写入`c`中，只要`c`为0即可，这里并没有检查`a`、`b`、`c`的指针是否是一个合法的指针，如果将`a`的指针设置为任意地址，`b`的值为1，就能实现将任意地址的内容写入的堆地址中进行泄漏，反之亦然，如果将`c`的指针指向一个值为0的任意地址，就能实现任意地址（该地址原本无数据）写入。其中来自`Lilac`战队的选手就是采用了这样的方式，改写`_IO_2_1_stdin→file→_chain`，最后劫持指针为`exit`函数触发。

另外，来自`laogong`战队的选手则是通过一条特殊的gadget：

> 0x00000000001ba784 : add byte ptr [rcx - 0x7b], cl ; ret

通过多次累加(?)，设置了`__io_list_all`，最后一次劫持指针为`exit`触发。

### 一些有趣的gadget

首先是来自`Friendly Maltese Citizens`战队的一🩸exp，他们选择了：

> #libc.so.6
>
> .text:000000000015D357                 mov     rdi, xdrs
> .text:000000000015D35A                 call    rcx

同时将`rcx`设置为：

> #pwn
> .text:0000000000002AD5                 mov     [rbp+var_18], rdi
> .text:0000000000002AD9                 mov     [rbp+var_1C], esi
> .text:0000000000002ADC                 mov     [rbp+var_4], 0
> .text:0000000000002AE3                 mov     [rbp+var_4], 0
> .text:0000000000002AEA                 jmp     short loc_2B35
> .text:0000000000002AEC ; ---------------------------------------------------------------------------
> .text:0000000000002AEC
> .text:0000000000002AEC loc_2AEC:                               ; CODE XREF: sub_2AC9+72↓j
> .text:0000000000002AEC                 mov     eax, [rbp+var_4]
> .text:0000000000002AEF                 movsxd  rdx, eax
> .text:0000000000002AF2                 mov     rax, [rbp+var_18]
> .text:0000000000002AF6                 add     rax, rdx
> .text:0000000000002AF9                 mov     edx, 1          ; nbytes
> .text:0000000000002AFE                 mov     rsi, rax        ; buf
> .text:0000000000002B01                 mov     edi, 0          ; fd
> .text:0000000000002B06                 call    _read
> .text:0000000000002B0B                 mov     eax, [rbp+var_4]
> .text:0000000000002B0E                 movsxd  rdx, eax
> .text:0000000000002B11                 mov     rax, [rbp+var_18]
> .text:0000000000002B15                 add     rax, rdx
> .text:0000000000002B18                 movzx   eax, byte ptr [rax]
> .text:0000000000002B1B                 cmp     al, 0Ah
> .text:0000000000002B1D                 jnz     short loc_2B31
> .text:0000000000002B1F                 mov     eax, [rbp+var_4]
> .text:0000000000002B22                 movsxd  rdx, eax
> .text:0000000000002B25                 mov     rax, [rbp+var_18]
> .text:0000000000002B29                 add     rax, rdx
> .text:0000000000002B2C                 mov     byte ptr [rax], 0
> .text:0000000000002B2F                 jmp     short loc_2B3D
> .text:0000000000002B31 ; ---------------------------------------------------------------------------
> .text:0000000000002B31
> .text:0000000000002B31 loc_2B31:                               ; CODE XREF: sub_2AC9+54↑j
> .text:0000000000002B31                 add     [rbp+var_4], 1
> .text:0000000000002B35
> .text:0000000000002B35 loc_2B35:                               ; CODE XREF: sub_2AC9+21↑j
> .text:0000000000002B35                 mov     eax, [rbp+var_4]
> .text:0000000000002B38                 cmp     eax, [rbp+var_1C]
> .text:0000000000002B3B                 jl      short loc_2AEC
> .text:0000000000002B3D
> .text:0000000000002B3D loc_2B3D:                               ; CODE XREF: sub_2AC9+66↑j
> .text:0000000000002B3D                 mov     eax, [rbp+var_4]
> .text:0000000000002B40                 leave
> .text:0000000000002B41                 retn
> .text:0000000000002B41 ; } // starts at 2AC9

这里是利用了源程序的读入字符串函数，将`rbp`作为`rdi`，`rsi`为随机生成的`key`值，只要`key`稍大就可以实现直接写入`rop`实现二次读入，再将完整的`rop`写入栈，很巧妙的利用手法😘。

接着是来自`Air2top`战队的题解，他选择了三个不同的`gadget`进行组合来完成这个利用：

```python
gad1 = libc_base + 0x72D44 # mov rdi, r14; call qword ptr [rcx+38h]
gad2 = libc_base + 0x167420# mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
gad3 = libc_base + 0x29EAC # add r14, 8; mov qword ptr [rsp], rdx; mov rsi, r12; mov edi, ebp; call qword ptr [rcx];
```

第三个`gadget`用来多次触发实现将`r14`寄存器累加到`bss`上，接着使用第一个`gadget`，在`[rcx+38h]`的位置提前写入第二个`gadget`的地址，跳转到第二个`gadget`，此时的`rdi`是我们可以任意读写的`bss`地址，因此`rdx`是可控的，结合经典的控制`rcx`的`gadget`——`setcontext`就可以完成后续的利用了。这种方法虽然很复杂但是很有趣🥳我很喜欢这种解法～
