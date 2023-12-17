#include <windows.h>


#include <winhvplatform.h>

#include "WinHvDefs.hpp"


#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>


size_t PAGE_SIZE = 4096;

size_t inline ALIGN_UP(size_t x)
{
    return ((PAGE_SIZE - 1) & x) ? ((x + PAGE_SIZE) & ~(PAGE_SIZE - 1)) : x;
}

typedef struct _RUN_OPTIONS {
    uint8_t *Code;
    size_t CodeSize;
    uintptr_t BaseAddress;
} RUN_OPTIONS, *PRUN_OPTIONS;

WHV_PARTITION_HANDLE gpartition = nullptr;



static void getByteString(UINT32 startaddr, UINT8 *bytesbuf, size_t bytesread)
{
    wchar_t debugStr[FILENAME_MAX];
    char bytestr[65];
    char charstr[20];

    if (bytesread < 1) {
        return;
    }

    if (bytesread > 16) {
        return;
    }
    unsigned int i;

    char *bytestr_tmp = bytestr;
    unsigned char c;
    for (i = 0; i < bytesread; i++) {
        c = *(bytesbuf + i);
        _snprintf(bytestr_tmp, 4, "%02x ", c);
        bytestr_tmp += 3;
    }
    if (bytesread < 16) {
        for (int i = bytesread; i < 16; i++) {
            *bytestr_tmp = 0x20;
            bytestr_tmp += 1;
            *bytestr_tmp = 0x20;
            bytestr_tmp += 1;
            *bytestr_tmp = 0x20;
            bytestr_tmp += 1;
        }
        *bytestr_tmp = '\0';
    }
    char *charstr_tmp = charstr;
    for (i = 0; i < bytesread; i++) {
        c = *(bytesbuf + i);
        if ((c < 127) && (c > 31) && (c != 92) &&
            (c != 34)) // exclude '\'=92 and "=34 for JSON comp.
        {
            _snprintf(charstr_tmp++, 2, "%c", c);
        }

        else {
            _snprintf(charstr_tmp++, 2, ".");
        }
    }

    wsprintfW(debugStr, L"%08x %S   %S\n", startaddr, bytestr, charstr);
    wprintf(debugStr);
    return;
}

static void hexdump(UINT8 *bytesbufRef, size_t size_len)
{

    for (int i = 0; i <= size_len / 16; i++) {

        getByteString((i * 16), bytesbufRef + (i * 16),
                      (i * 16) + 16 > size_len ? size_len % 16 : 16);
    }
}


void dumpbuf(LPVOID buf, size_t len)
{
    hexdump((UINT8 *)buf, len);

}

HRESULT whpx_get_reg_value1(const WHV_REGISTER_NAME RegisterName,
                           WHV_REGISTER_VALUE *RegisterValues)
{
    HRESULT hr;
    hr = WHvGetVirtualProcessorRegisters(gpartition, 0, &RegisterName, 1,
                                         RegisterValues);
    if (FAILED(hr)) {
        printf("WHPX: Failed to get virtual processor registers,"
               " hr=%08lx",
               hr);
    }

    return hr;
}

#define DumpGpr1(name)                                                          \
    whpx_get_reg_value1(name, &regvalue);                                       \
    printf(#name##"\t= %016llx\n", regvalue.Reg64)

#define DumpSeg1(name)                                                          \
    whpx_get_reg_value1(name, &regvalue);                                       \
    printf(#name##"\tSel= %04lx\tBase= %016llx\tLimit= %04lx\n",               \
           regvalue.Segment.Selector, regvalue.Segment.Base,                   \
           regvalue.Segment.Limit)

#define DumpTbl1(name)                                                          \
    whpx_get_reg_value1(name, &regvalue);                                       \
    printf(#name##"\tBase= %016llx\tLimit= %04lx\n", regvalue.Table.Base,      \
           regvalue.Table.Limit)

void DumpRegs1()
{

    WHV_REGISTER_VALUE regvalue = {0};
    //// Get stack HVA
    ////
    // auto rspGva = registers[ Rsp ].Reg64;
    // WHSE_ALLOCATION_NODE* node = nullptr;
    // if ( FAILED( WhSeFindAllocationNodeByGva( Partition, rspGva, &node ) ) )
    //	return false;

    // auto rspHva = node->HostVirtualAddress;
    // printf( "RSP = %llx (hva = %llx)\n", rspGva, rspHva );

    DumpGpr1(WHvX64RegisterRip);

    DumpGpr1(WHvX64RegisterRsp);
    DumpGpr1(WHvX64RegisterRbp);

    DumpGpr1(WHvX64RegisterRax);
    DumpGpr1(WHvX64RegisterRbx);
    DumpGpr1(WHvX64RegisterRcx);
    DumpGpr1(WHvX64RegisterRdx);
    DumpGpr1(WHvX64RegisterRdi);
    DumpGpr1(WHvX64RegisterRsi);
    DumpGpr1(WHvX64RegisterR8);
    DumpGpr1(WHvX64RegisterR9);
    DumpGpr1(WHvX64RegisterR10);
    DumpGpr1(WHvX64RegisterR11);
    DumpGpr1(WHvX64RegisterR12);
    DumpGpr1(WHvX64RegisterR13);
    DumpGpr1(WHvX64RegisterR14);
    DumpGpr1(WHvX64RegisterR15);
    DumpGpr1(WHvX64RegisterRflags);

    DumpGpr1(WHvX64RegisterCr0);
    DumpGpr1(WHvX64RegisterCr2);
    DumpGpr1(WHvX64RegisterCr3);
    DumpGpr1(WHvX64RegisterCr4);

    DumpSeg1(WHvX64RegisterCs);
    DumpSeg1(WHvX64RegisterDs);
    DumpSeg1(WHvX64RegisterSs);
    DumpSeg1(WHvX64RegisterEs);
    DumpSeg1(WHvX64RegisterFs);
    DumpSeg1(WHvX64RegisterGs);
    DumpSeg1(WHvX64RegisterTr);

    DumpTbl1(WHvX64RegisterGdtr);
    DumpTbl1(WHvX64RegisterIdtr);

    return;
}

#define CHECK(x)                                                               \
    do {                                                                       \
        if (!(x)) {                                                            \
            std::cerr << "Error: " #x " is false!" << std::endl;               \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

// Read input file
//
bool ReadInputFile(const char *Filename, uint8_t **Code, size_t *CodeSize)
{
    if (Code == NULL) {
        return false;
    }

    // Open the input file
    //
    FILE *fp = NULL;
    if (fopen_s(&fp, Filename, "rb") != 0)
        return false;

    if (fp == NULL)
        return false;

    // Get the file size
    //
    fseek(fp, 0, SEEK_END);
    *CodeSize = ALIGN_UP(ftell(fp));
    *Code = (uint8_t *)(VirtualAlloc(NULL, *CodeSize, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE));
    if (*Code == NULL) {
        fclose(fp);
        return false;
    }

    fseek(fp, 0, SEEK_SET);

    fread(*Code, *CodeSize, 1, fp);

    fclose(fp);

    return true;
}


EXTERN_C int setuphv(WHV_PARTITION_HANDLE* partition)
{


    // 检查是否启用了 Hyper-V
    BOOL hypervisorPresent = false;
    CHECK(WHvGetCapability(WHvCapabilityCodeHypervisorPresent,
                           &hypervisorPresent, sizeof(hypervisorPresent),
                           nullptr) == S_OK);
    if (!hypervisorPresent) {
        std::cerr << "Hyper-V is not available" << std::endl;
        return 1;
    }

    // 创建一个 Hyper-V 分区，把它看作一个虚拟机就行了

    CHECK(WHvCreatePartition(partition) == S_OK);
    UINT32 processorCount = 1; // 只需要一个处理器核心就够了
    CHECK(WHvSetPartitionProperty(
              *partition, WHvPartitionPropertyCodeProcessorCount,
              &processorCount, sizeof(processorCount)) == S_OK);
    CHECK(WHvSetupPartition(*partition) == S_OK);
    CHECK(WHvCreateVirtualProcessor(*partition, 0, 0) == S_OK);

     WHV_REGISTER_NAME name = WHvX64RegisterCs;
    WHV_REGISTER_VALUE value = {};
    value.Segment.Base = 0x00000000;
    value.Segment.Limit = 0x0000FFFF;
    value.Segment.Selector = 0x0000;
    value.Segment.Attributes =
        0x009B; // 代码段的属性，详情可以参考该字段的定义和 Intel 手册
    whpx_set_reg_value(name, value);

    return 0;
}

EXTERN_C  int mainfake()
{
    RUN_OPTIONS opt;

    if (ReadInputFile("E:\\git\\HyperVResearch\\ida\\qiling-"
                      "master\\examples\\rootfs\\x8664_windows\\bin\\fake.exe",
                      &opt.Code, &opt.CodeSize)) {
        {
            setuphv(&gpartition);

            
            std::uint64_t memorySize = opt.CodeSize, memoryOffset = 0x00001000;
            /*std::uint64_t memorySize = 0x00001000, memoryOffset = 0x00001000;
            // 分配一个 4KiB 的内存页，注意这段内存要对齐到页边界，随便 malloc
            或者 new 出来是不行的 void* memory = VirtualAlloc(nullptr,
            memorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); CHECK(memory
            != nullptr); std::memcpy(memory, code.data(), code.size()); //
            把代码复制进去
            // 将刚刚分配的内存页设置到虚拟机的地址 0x00001000 上（0x00000000
            被实模式的中断向量表占用了） CHECK(WHvMapGpaRange(partition, memory,
            memoryOffset, memorySize, WHvMapGpaRangeFlagRead |
            WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute) == S_OK);*/

            CHECK(WHvMapGpaRange(gpartition, opt.Code, memoryOffset, memorySize,
                                 WHvMapGpaRangeFlagRead |
                                     WHvMapGpaRangeFlagWrite |
                                     WHvMapGpaRangeFlagExecute) == S_OK);

            /*
            //初始化 CS 寄存器（代码段寄存器）
            WHV_REGISTER_NAME name = WHvX64RegisterCs;
            WHV_REGISTER_VALUE value = {};
            value.Segment.Base = 0x00000000;
            value.Segment.Limit = 0x0000FFFF;
            value.Segment.Selector = 0x0000;
            value.Segment.Attributes =
                0x009B; // 代码段的属性，详情可以参考该字段的定义和 Intel 手册
            CHECK(WHvSetVirtualProcessorRegisters(gpartition, 0, &name, 1,
                                                  &value) == S_OK);*/

            // 获取与设置 RIP 寄存器（程序指针寄存器）的函数
            auto getRIP = []() -> std::uint64_t {
                WHV_REGISTER_NAME name = WHvX64RegisterRip;
                WHV_REGISTER_VALUE value = {};
                CHECK(WHvGetVirtualProcessorRegisters(gpartition, 0, &name, 1,
                                                      &value) == S_OK);
                return value.Reg64;
            };
            auto setRIP = [](std::uint64_t rip) {
                WHV_REGISTER_NAME name = WHvX64RegisterRip;
                WHV_REGISTER_VALUE value = {};
                value.Reg64 = rip;
                CHECK(WHvSetVirtualProcessorRegisters(gpartition, 0, &name, 1,
                                                      &value) == S_OK);
            };
            // 从创建的内存页的首地址开始执行代码
            // setRIP(memoryOffset);
            setRIP(memoryOffset + 0x400);

            // 虚拟机的主循环
            while (true) {
                DumpRegs1();
                WHV_RUN_VP_EXIT_CONTEXT context = {};
                // 启动虚拟机处理器
                CHECK(WHvRunVirtualProcessor(gpartition, 0, &context,
                                             sizeof(context)) == S_OK);
                // 虚拟机 Exit 了，可能是由于 IO
                // 操作、停机指令或者各种其他原因造成的
                switch (context.ExitReason) {
                case WHvRunVpExitReasonX64IoPortAccess: {
                    // 如果是往 0x3F8 端口里写一个字节的数据，就输出出来
                    if (context.IoPortAccess.AccessInfo.IsWrite &&
                        context.IoPortAccess.AccessInfo.AccessSize == 1 &&
                        !context.IoPortAccess.AccessInfo.StringOp &&
                        context.IoPortAccess.PortNumber == 0x3F8)
                        std::cout << char(context.IoPortAccess.Rax);
                    // Hyper-V 在 IO 时处理方式与 KVM
                    // 不同，不会自动指向下一条指令，所以需要手动改 RIP
                    setRIP(getRIP() + context.VpContext.InstructionLength);
                    break; // 处理完了，继续运行虚拟机处理器
                }
                case WHvRunVpExitReasonX64Halt: { // 停机了，删库跑路
                    std::cerr << "VM Halt" << std::endl;
                    WHvDeletePartition(gpartition);
                    return 0;
                }
                default: {
                    std::cerr
                        << "Unexpected Exit Reason: " << context.ExitReason
                        << std::endl;
                    return 1;
                }
                }
            }
        }
    }
}


bool WhSeIsHypervisorPresent() {
	auto capabilities = WHV_CAPABILITY { 0 };
	uint32_t written = 0;

	// Check if hypervisor is present
	//
	auto hresult = ::WHvGetCapability( WHvCapabilityCodeHypervisorPresent, &capabilities, sizeof( decltype( capabilities ) ), &written );
	if ( FAILED( hresult ) || !capabilities.HypervisorPresent ) {
		return false;
	}

	hresult = ::WHvGetCapability( WHvCapabilityCodeExtendedVmExits, &capabilities, sizeof( decltype( capabilities ) ), &written );
	if ( FAILED( hresult )
		|| !capabilities.ExtendedVmExits.X64CpuidExit
		|| !capabilities.ExtendedVmExits.X64MsrExit
		|| !capabilities.ExtendedVmExits.X64RdtscExit ) {
		return false;
	}

	return true;
}

/**
 * @brief Wrapper around GetLastError
 *
 * @return A code indicating the last error
 */
uint32_t WhSeGetLastError() {
	return ::GetLastError();
}

/**
 * @brief Wrapper around GetLastError and HRESULT_FROM_WIN32
 *
 * @return A code indicating the last error
 */
HRESULT WhSeGetLastHresult() {
	auto lasterror = WhSeGetLastError();
	return HRESULT_FROM_WIN32( lasterror );
}

#define ARCH_X64_HIGHESTORDER_BIT_IMPLEMENTED 47
#define ARCH_X64_CANONICAL_BITMASK  ~( ( 1ull << ( ARCH_X64_HIGHESTORDER_BIT_IMPLEMENTED + 1 ) ) - 1 )

/**
 * @brief An helper function to know if a virtual address is canonical
 *
 * @return A boolean indicating if the virtual address <VirtualAddress> is canonical (true) or not (false)
 */
bool WhSeIsCanonicalAddress( uintptr_t VirtualAddress ) {
	bool highest_bit_set = ( ( VirtualAddress & ( 1ull << ARCH_X64_HIGHESTORDER_BIT_IMPLEMENTED ) ) >> ARCH_X64_HIGHESTORDER_BIT_IMPLEMENTED ) == 1;

	uintptr_t masked = VirtualAddress & ARCH_X64_CANONICAL_BITMASK;

	return highest_bit_set ? masked == ARCH_X64_CANONICAL_BITMASK : masked == 0x00000000'00000000;
}
