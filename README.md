## 引用 ##

>这篇文章的目的是介绍基于Windows Hyper-V虚拟机平台Hypervisor Platform API实现的魔改版Unicorn Engine模拟器和调试引擎开发心得

[toc]

## 简介 ## 

跨平台模拟器unicorn框架基于Qemu的TCG模式(Tiny Code Generator),以无硬件虚拟化支持方式实现全系统的虚拟化,支持跨平台和架构的CPU指令模拟,本文讨论是一款笔者的实验性项目采用Windows Hypervisor Platform虚拟机模式提供了另一种CPU指令的模拟方式,在保持原有unicorn导出接口不变的情况下,采用Hyper-V支持带硬件虚拟化支持的Windows Hypervisor Platform API接口扩展了底层CPU模拟环境实现,支持X86指令集的二进制程序模拟平台和调试器.

## unicorn框架qemu之Hyper-v模式比较 ## 

Windows Hypervisor Platform是微软在Hyper-V平台提供一种新的API库,用于允许第三方开发者创建和管理EXO分区.EXO分区是一种与Hyper-V兼容并可以同时运行的虚拟机分区,用于支持第三方开发者的虚拟化解决方案，如VirtualBox、Qemu、VMware等,采用虚拟机容器的方式模拟客户机整个操作系统虚拟环境.
跨平台模拟执行unicorn框架和上层qiling框架都是基于qemu的TCG模式(Tiny Code Generator),支持无硬件虚拟化支持方式在源ISA(处理器架构)和目标ISA不同的情况下CPU指令模拟,类似一个jit解释器,一个循环中不断的读入源ISA程序指令,QEMU先转换成源ISA的IR,反汇编并用代码在目标ISA编译后的IR在模拟TranslationBlock指令中执行,当然这些指令也是转换后的汇编模式比起直接调用c函数模拟可以优化效率,qemu对TranslationBlock在分支执行返回后切换到Qemu上下文保存虚拟环境状态继续下个分支执行,转换过程采用内联汇编的方式支持hook断点与内存监视trace等功能.如果切换成Windows Hypervisor Platform(以下简称Hyper-v虚拟机)模式就省去了模拟cpu指令的环节,真实的物理cpu被虚拟化成vcpu,这个逻辑封装成由Hypervisor API创建虚拟机的调度者调度和物理机共享cpu资源,API底层实现又由Hyper-v自己的调度器(Hypervisor)的Hvix64.exe模块实现,源ISA的指令运行在vcpu上,看起来就像在物理cpu一样.每个hyper-v分区实例是一个相对于其他分区隔离的虚拟环境,由WHvCreatePartition函数创建分区,这个分区通过VID.sys(Virtualization Infrastructure Driver)驱动向管理者也就是是被创建分区的父分区hv(Hypervisor)模块通信抽象成上层api交给调用者调度,hv模块同样也有自己的分区与其他分区隔离,如果要调试hv模块可以通过bcdedit /set hypervisordebug on方式(具体见引用节)启用2个windbg实例调试内核和hv.如果是在物理机上,物理机的操作系统运行在由根分区hv管理创建的虚拟机容器中,嵌套的子分区由它的父分区hv模块管理,所有的虚拟机陷入陷出都首先交给根分区的hv处理,再分发给父分区hv处理完成后回到子分区继续执行,即使被调度的是一段shellcode,整个虚拟环境也具备一个完整的操作系统拥有x86体系虚拟化资源.一个分区允许创建多个可以同时执行调度的vcpu通过WHvCreateVirtualProcessor,每个vcpu都可以设置自己的寄存器上下文,而内存对象被整个分区共享,进入WHvRunVirtualProcessor开始调度,整个调度过程中对外面的Hypervisor是不透明的,直到遇到一个退出条件比如说断点,内存违规访问,vmcall指令等函数会返回,可以从vmexit的上下文中获取退出原因,Hypervisor可以执行对应的操作继续vcpu运行.qemu无硬件虚拟化采用纯模拟的方式实现缺点是速度较慢.Hyper-v模式主要是陷入陷出调度器需要处理时间,源ISA指令执行速度与真实cpu相当,这种方式速度较快.

## 内存管理分析 ## 

qemu采用MemoryRegion结构体管理所有分配的gva(客户机虚拟内存地址)到hva(宿主机虚拟内存地址)的映射,内部是一个双向链表结构包含了起始,结束gva和映射hva地址,支持先指定gva再分配hva模式,查询链表通过二叉树方式实现,如果新分配的地址位于已分配区域返回UC_ERR_MAP错误需要重新指定gva,对于读取和写入内存则是先通过gva找到hva,直接操作hva相对偏移量数据,这种方式一般仅限于模拟应用层程序的内存管理,对于所有内存操作只是处理所有已经映射的gva,遇到了未被映射的内存直接抛出UC_ERR_WRITE_UNMAPPED错误结束程序.由于对于内核态程序存在虚拟机地址和物理地址映射关系,这种直接的转换映射处理并不适用于这种情况.而Hyper-v模式多出了一个gpa(客户机物理内存地址)的概念,映射宿主机虚拟内存并不能直接通过hva -> gva的方式映射,而是通过WHvMapGpaRange函数先映射gpa再根据当前vcpu的cr3寄存器pde,pte转换到gva,这种模式也就是我们真实x86体系操作系统的内存映射模式,同时适用于用户态和内核态程序.至于cr3寄存器如映何射gva虚拟内存可以参考看雪其他相关文章这里不在赘述,笔者项目沿用了qemu内存管理框架结构体,实现参考WinHvShellcodeEmulator项目,下面这段代码展示了在虚拟机映射gva和方式.
```
HRESULT WhSeMapHostToGuestVirtualMemory(whpx_state *Partition, uintptr_t HostVa,
                                        uintptr_t *GuestVa, size_t Size,
                                        WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    auto size = ALIGN_UP(Size);
    PWHSE_ALLOCATION_NODE existingNode = nullptr;
    auto hresult =
        WhSeFindAllocationNodeByGva(Partition, *GuestVa, &existingNode);
    uintptr_t suggestedGva = 0;
    if (*GuestVa == 0 || existingNode != nullptr) {
        auto hresult = WhSiSuggestVirtualAddress(
            Partition, size, &suggestedGva, Partition->VirtualProcessor.Mode);     
    } else
        suggestedGva = ALIGN(*GuestVa);
    existingNode = nullptr;
    hresult = WhSeFindAllocationNodeByGva(Partition, suggestedGva, &existingNode);
    auto startingGva = ALIGN(suggestedGva);
    auto endingGva = ALIGN_UP(startingGva + size);
    uintptr_t suggestedGpa = 0;
    hresult = WhSiSuggestPhysicalAddress(Partition, size, &suggestedGpa);
    WHSE_ALLOCATION_NODE node{.BlockType =
                                  MEMORY_BLOCK_TYPE::MemoryBlockVirtual,
                              .HostVirtualAddress = HostVa,
                              .GuestPhysicalAddress = suggestedGpa,
                              .GuestVirtualAddress = startingGva,
                              .Size = size};
    hresult = WhSeInsertAllocationTrackingNode(Partition, node);
     // Setup matching PTEs
    for (auto gva = startingGva, page = suggestedGpa; gva < endingGva;
         gva += PAGE_SIZE, page += PAGE_SIZE) {
        hresult = WhSiInsertPageTableEntry(Partition, gva, page);     
    hresult = ::WHvMapGpaRange(
        Partition->partition, reinterpret_cast<PVOID>(HostVa),
        static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(suggestedGpa), size, Flags);    
    *GuestVa = startingGva;
    return hresult;
}
HRESULT WhSiInsertPageTableEntry(whpx_state *Partition,
                                 uintptr_t VirtualAddress,
                                 uintptr_t PhysicalAddress)
{
    // "Explode" the VA into translation indexes
    uint16_t pml4Idx;
    uint16_t pdpIdx;
    uint16_t pdIdx;
    uint16_t ptIdx;
    uint16_t phyOffset;
    auto hresult = WhSiDecomposeVirtualAddress(
        VirtualAddress, &pml4Idx, &pdpIdx, &pdIdx, &ptIdx, &phyOffset);
    // Search entry in PML4
    auto pml4e = reinterpret_cast<PMMPTE_HARDWARE>(
        Partition->MemoryLayout.Pml4HostVa)[pml4Idx];
    if (pml4e.Valid == FALSE) {
        // Shouldn't happen as we initialized all PLM4 entries upfront
          return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);
    }
    // Search entry in Page Directory Pointers
    uintptr_t pdpHva = 0;
    hresult = WhSpLookupHVAFromPFN(Partition, pml4e.PageFrameNumber, &pdpHva);
    auto pdp = reinterpret_cast<PMMPTE_HARDWARE>(pdpHva);
    auto pdpe = pdp[pdpIdx];
    if (pdpe.Valid == FALSE) {
        // Allocate a Page Directory page
        //
        hresult = WhSpInsertPageTableEntry(Partition, pdp, pdpIdx);
        pdpe = pdp[pdpIdx];
    }
    // Search entry in Page Directories
    uintptr_t pdHva = 0;
    hresult = WhSpLookupHVAFromPFN(Partition, pdpe.PageFrameNumber, &pdHva);
    if (FAILED(hresult))
        return hresult;
    auto pd = reinterpret_cast<PMMPTE_HARDWARE>(pdHva);
    auto pde = pd[pdIdx];
    if (pde.Valid == FALSE) {
        // Allocate a Page Table page
         hresult = WhSpInsertPageTableEntry(Partition, pd, pdIdx);
        pde = pd[pdIdx];
    }
    // Add entry in Page Tables
    uintptr_t ptHva = 0;
    hresult = WhSpLookupHVAFromPFN(Partition, pde.PageFrameNumber, &ptHva);
    if (FAILED(hresult))
        return hresult;
    auto pt = reinterpret_cast<PMMPTE_HARDWARE>(ptHva);
    auto ppte = &pt[ptIdx];
    if (ppte->Valid == FALSE) {
        /*PWHSE_ALLOCATION_NODE found = nullptr;
        hresult = WhSeFindAllocationNodeByGpa( Partition, PhysicalAddress,
        &found ); if ( hresult != HRESULT_FROM_WIN32( ERROR_NOT_FOUND ) &&
        FAILED( hresult ) ) return hresult;
        // Create a valid PTE 
        MMPTE_HARDWARE pte{};
        pte.AsUlonglong = 0; // Ensure zeroed
        pte.Valid = 1;       // Intel's Present bit
        pte.Write = 1;       // Intel's Read/Write bit
        pte.Owner = 1; // Intel's User/Supervisor bit, let's say it is a user
                       // accessible frame
        pte.PageFrameNumber =
            (PhysicalAddress / PAGE_SIZE); // Physical address of PDP page
        *ppte = pte;
        WHSE_ALLOCATION_NODE node{.BlockType =
                                      MEMORY_BLOCK_TYPE::MemoryBlockPte,
                                  .HostVirtualAddress = 0,
                                  .GuestPhysicalAddress = PhysicalAddress,
                                  .GuestVirtualAddress = 0,
                                  .Size = PAGE_SIZE};
        hresult = WhSeInsertAllocationTrackingNode(Partition, node);
      }
    return S_OK;
}

```
由于Hyper-v模式模拟的是整个虚拟机环境,在初始化分区时构建512个pde项,对需要映射的gva需要先对齐到一个页大小,对每个要申请的gva,使用其中一个可用的pde,计算出索引PageFrameNumber分对应的pte项,插入这些页的gpa,最后把vcpu初始化的cr3基址指向pde的物理地址.除了初始化内存分配,还要加载进内存要执行之前都会初始化段寄存器的值,包括全局描述符表(GDT)，局部描述符表(LDT)和中断描述符表(IDT),这里只需要根据当前模拟的是用户态还是内核态选择对应的段选择子和DescriptorPrivilegeLevel,还有根据否是64位和32位模式设置段寄存器cs的Long位就可以了.虚拟机本身对32位和64位模式没有限制,这些都通过x86平台自身的段属性配置,这里还存在一种特殊情况,类似在模拟器中执行VirtualAlloc由于实际申请到的gva是未知的,如果传入一个随机的内存地址,传给模拟器可能返回一个已映射地址错误,导致分配失败,解决方法是先申请宿主机hva,然后找到一个已释放的页或者计算一个新的页索引PageFrameNumber分配页得到一个可以用的gva和gpa地址映射hva的pte项,把计算出的gva返回给调用者.这种方式可以模拟任何虚拟内存申请函数.
原WinHvShellcodeEmulator项目默认配置不支持xmm寄存器指令,解决方法是需要开启cr4的OSXSAVE位和xcr的XSTATE相关位,开启后就可以正常执行sse指令集了.
```
先设置cr4的这些位
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK (1U << 10)
 RegisterName = WHvX64RegisterCr4;
    uint64_t cr4val = 0;
    whpx_get_reg(RegisterName, &cr4val);
    cr4val = (cr4val | (1ULL << 5)) & ~(1 << 24);
    cr4val |= CR4_OSXSAVE_MASK;
    cr4val |= CR4_OSFXSR_MASK;
    cr4val |= CR4_OSXMMEXCPT_MASK;
    whpx_set_reg(RegisterName, cr4val);
    //再设置WHvX64RegisterXCr0的这些位
    #define XSTATE_FP_BIT                   0
#define XSTATE_SSE_BIT                  1
#define XSTATE_FP_MASK                  (1ULL << XSTATE_FP_BIT)
#define XSTATE_SSE_MASK                 (1ULL << XSTATE_SSE_BIT)
WHV_REGISTER_VALUE xcr0;
    WHV_REGISTER_NAME xcr0_name = WHvX64RegisterXCr0;
    if (!whpx_has_xsave()) {
        return;
    }
    env->xcr0 |= XSTATE_FP_MASK;
    env->xcr0 |= XSTATE_SSE_MASK;
    /* Only xcr0 is supported by the hypervisor currently */
    xcr0.Reg64 = env->xcr0;
    hr = WHvSetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         &xcr0_name, 1, &xcr0);                                     
```
笔者为项目添加了一个支持导入windbg的dump文件模拟应用程序的功能,支持在加载dump文件后自动映射入口点所有寄存器的值,对已经dump的相关内存自动映射相关gva,包括所有已加载模块镜像的内存,并且设置退出条件ExceptionExitBitmap包含WHvX64ExceptionTypePageFault位,这样模拟shellcode时即使未完成全部内存映射,设置为内核模式,如果模拟运行遇到了未映射的内存Hypervisor会去idt中查找缺页异常的handler,实际上的这个异常所在的handler的内存是个已释放的页面,导致最终产生了一个WHvX64ExceptionTypePageFault类型的退出错误在,在vcpu->exit_ctx.VpException.ExceptionParameter这个字段中包含的就是未映射的内存地址,这样只要从dump文件中把那片内存读出来,恢复模拟器运行就能修复常见的违规内存访问错误.Windows Hypervisor Platform 还提供了一种机制用于修复WHvRunVpExitReasonMemoryAccess错误,称为WHvEmulatorTryMmioEmulation函数,会模拟当前指令的汇编代码在传给WHvEmulatorCreateEmulator回调函数中返回的Emulator句柄,如果通过模拟汇编代码找到一个映射关系在WHvEmulatorTranslateGvaPage回调函数中得到得到解析出来的gva和WHvTranslateGva的gpa,这种方式也提供了类似的逻辑修复违规内存访问错误.其他类型退出异常比如说cpuid,apic等可以参考qemu的Windows Hypervisor Platform实现具体见引用节.

## 调试器功能开发 ## 

qiling框架实现了一套基于gdb远程调试协议的ida调试插件支持,gdb远程调试协议文档详见引用节,调试插件在一个循环中读取ida发过来是请求包,初始化调试环境在入口处停下来,ida读取当前状态的寄存器和内存数据,用户可以在这个时候设置断点,直到用户执行continue,把所有的断点请求包发送调试器完成后.到了continue发送handle_c包调用uc_emu_start,这个时候模拟器开始执行并设置当前启用的断点,直到遇到一个退出条件,模拟器遍历符合条件的导致退出执行的断点,上报至调试插件,调试插件再根据不同的断点类型确定是要跳过的中断还是暂停调试中断到调试器,如果要中断到调试器,在断点回调中调用uc_emu_stop终止模拟循环,这里需要注意的一点是uc_emu_start是主线程,断点回调只是在线程的执行过程中向上层回调,回调完成后handle_c函数才会返回{SIGTRAP:02x},在ida中看到的现象是调试运行位置切换到断点位置中断,用户可以选择读取数据,设置断点或者继续运行.对于普通断点的实现采用的方法是把断点位置的第一个字节替换成INT1=0xf1,这样运行得到断点处就会抛出一个WHvX64ExceptionTypeDebugTrapOrFault,如果vcpu->exit_ctx.VpException.InstructionBytes[0]=0xf1就可以确定是触发INT1断点中断到调试器,但是如果直接继续运行会发现这个断点会无限触发导致死循环,解决方法是先恢复断点处指令为原始数据字节,然后设置单步执行修复方法解决.,等单步指令执行完触发单步异常时,再来重启断点,这个步骤在内部执行对上层调试器没有影响,再根据当前调试器是继续执行还是单步模式继续处理,笔者参考了其它调试器的文章也是这样实现的.笔者还为调试器新加入了硬件断点的功能,在gdb远程调试协议中如果收到一个Z1-Z3的包,表示是一个硬件断点,可以采用x86架构的DR0-7调试寄存器的方式实现.启用断点,调试寄存器DR7的0~7位的L位和G位分别表示对应的断点是否启用局部还是全局,第8位和第9位是L位和G位的大开关,16~31位表示断点类型和长度.DR0~3寄存器保存的是断点的地址,断点触发后DR6寄存器的B0~3置位表示断点的索引.硬件断点同样也存在死循环问题可以单步执行修复方法解决,具体方法如下:.
```
#define RT_BIT_64(bit) (UINT64_C(1) << (bit))
#define RT_BIT_64_FIND(val, bit) (val & (UINT64_C(1) << (bit)))
#define RT_BIT_64_SLOT(bit) (UINT64_C(1) << (bit << 1))
#define RT_BIT_64_FIND_SLOT(val, bit) (val & (UINT64_C(1) << (bit << 1)))
static void
whpx_apply_hardware_breakpoint(struct whpx_breakpoint_collection *breakpoints,
                               CPUState *cpu, uintptr_t addrskip)
{
  uint8_t hwbpslot = 0;
   uint64_t dr7val=0;
    uint64_t dr7valrw = 0;
  for (int i = 0; i < breakpoints->used; i++) {
        struct whpx_breakpoint *breakpoint = &breakpoints->data[i];
        WhpxBreakpointState state = breakpoint->state;
        if (breakpoint->bptype & 0xff0000) {
            if (state == WHPX_BP_SET_PENDING) {                
                for (uint8_t j = 0; j < 4; j++) {
                    //如果有使用槽置位详见源码
                    if (!RT_BIT_64_FIND_SLOT(dr7val, j)) {                      
                        breakpoint->original_instruction = j;
                        hwbpslot |= RT_BIT_64(breakpoint->original_instruction);                          
                        whpx_set_reg(WHvX64RegisterDr0+j, breakpoint->address);
                       
                    }
                }
                if (breakpoint->bptype == UC_HOOK_HARDWARE_READ) {
                    dr7valrw |=
                        RT_BIT_64(breakpoint->original_instruction << 2);
                    dr7valrw |=
                        RT_BIT_64((breakpoint->original_instruction << 2) + 1);
                }
                if (breakpoint->bptype == UC_HOOK_HARDWARE_WRITE) {
                    dr7valrw |=
                        RT_BIT_64(breakpoint->original_instruction << 2);
                }
                breakpoint->state = WHPX_BP_SET;
               
            }
        }
    }
     dr7val = 0;
    if (hwbpslot) {
        for (uint8_t j = 0; j < 4; j++) {
            if (hwbpslot & RT_BIT_64(j)) {
                dr7val |= (RT_BIT_64_SLOT(j));
            }
        }
        dr7val |= dr7valrw << 16;
        //启用大标志
        dr7val |= RT_BIT_64(8);
    }
    whpx_set_reg(WHvX64RegisterDr7, dr7val);
    }
```
笔者项目目前只支持单线程(1个vcpu)模拟,有兴趣的读者可以自行开发多线程功能实现.原qiling框架有自己的pe加载器设置的gdtr和idt寄存器和笔者项目有冲突暂时未使用,模拟了常用的winapi函数,这种模拟方式同样在笔者项目使用用于api模拟,留给读者自行尝试.


## 编译方式 ## 

添加工程文件至Unicorn Engine在修改CMakeLists.txt新建unicorn-whpx静态库,添加"Winhvplatform.lib"和 "WinHvEmulation.lib"库依赖,使用如下方式创建模拟器实例,导出api形式和原工程相同:
```
 uc_err err = uc_open(UC_ARCH_X86_WHPX, UC_MODE_64, &uc);
```
## 运行效果 ##

以下是笔者模拟器运行的效果,如图:

![查看大图](img/unifix.gif)

##  相关引用 ##

[Unicorn Engine](https://github.com/unicorn-engine/unicorn)

[Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/)

[hypervisor implementation for Bochs](https://github.com/gamozolabs/applepie)

[参考qemu实现](https://github.com/kata-containers/qemu/blob/cdcb7dcb401757b5853ca99c1967a6d66e1deea5/target/i386/whpx/whpx-all.c)

[WinHvShellcodeEmulator](https://github.com/Midi12/whse/tree/master)

[看雪Qemu的tcg分析](https://bbs.kanxue.com/thread-277163.htm)

[看雪hyper-v分析](https://bbs.kanxue.com/thread-278784.htm)

[gdt](https://bbs.kanxue.com/thread-270476.htm)

[段模式](https://bbs.kanxue.com/thread-279127.htm)

[看雪调试器](https://bbs.kanxue.com/thread-276162.htm)

[gdb远程调试协议](https://sourceware.org/gdb/current/onlinedocs/gdb.html/index.html)

[硬件断点文档](https://en.wikipedia.org/wiki/X86_debug_register)

[hv模块调试](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--hypervisorsettings)

[笔者模拟器项目](https://github.com/cbwang505/unicorn-whpx)


## 参与贡献 ##


作者来自ZheJiang Guoli Security Technology,邮箱cbwang505@hotmail.com