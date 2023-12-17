#include "WinHvMemory.hpp"
#include "WinHvMemoryInternal.hpp"
#include "WinHvHelpers.hpp"
#include "WinHvUtils.hpp"
#include "winbase.h"
#include "WinHvAllocationTracker.hpp"
#include <comdef.h>
/*
HRESULT WhSeSetProcessorRegisters(whpx_state *Partition,
                                  WHSE_REGISTERS Registers)
{
    return 0;
}
HRESULT WhSeGetProcessorRegisters(whpx_state *Partition,
                                  WHSE_REGISTERS Registers)
{
    return 0;
}*/
/**
 * @brief A routine to translate a <WHSE_MEMORY_ACCESS_FLAGS>
 *
 * Internal routine
 * A routine to translate a <WHSE_MEMORY_ACCESS_FLAGS> to a
 * Protection Flags value compatible with the <VirtualAlloc> API
 *
 * @param Flags The flags to translate
 * @return The translated flags
 */
constexpr uint32_t AccessFlagsToProtectionFlags(WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    uint32_t protectionFlags = 0;

    if (Flags == WHvMapGpaRangeFlagNone)
        return PAGE_NOACCESS;

    if (HAS_FLAGS(Flags, WHvMapGpaRangeFlagRead))
        protectionFlags |= (1 << 1);

    if (HAS_FLAGS(Flags, WHvMapGpaRangeFlagWrite))
        protectionFlags <<= 1;

    if (HAS_FLAGS(Flags, WHvMapGpaRangeFlagExecute))
        protectionFlags <<= 4;

    return protectionFlags;
}

/**
 * @brief Allocate memory in guest physical address space (backed by host
 * memory)
 *
 * Allocate memory in guest physical address space (backed by host memory),
 * mapping twice on the same guest physical memory address will replace any
 * existing mapping but will not free the existing host backing memory.
 *
 * @param Partition The VM partition
 * @param HostVa The host virtual memory address backing the guest physical
 * memory
 * @param GuestPa The guest physical memory address
 * @param Size The size of the allocated memory
 * @param Flags The flags that describe the allocated memory (Read Write
 * Execute)
 * @return A result code
 */
HRESULT WhSeAllocateGuestPhysicalMemory(whpx_state *Partition,
                                        uintptr_t *HostVa, uintptr_t *GuestPa,
                                        size_t Size,
                                        WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (*HostVa != 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (GuestPa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto size = ALIGN_UP(Size);

    uintptr_t suggestedGpa = 0;
    if (*GuestPa == 0) {
        auto hresult =
            WhSiSuggestPhysicalAddress(Partition, size, &suggestedGpa);
        if (FAILED(hresult))
            return hresult;
    } else
        suggestedGpa = ALIGN(*GuestPa);

    PWHSE_ALLOCATION_NODE existingNode = nullptr;
    auto hresult =
        WhSeFindAllocationNodeByGpa(Partition, suggestedGpa, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    if (existingNode != nullptr)
        return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);

    // Allocate memory into host
    //
    auto protectionFlags = AccessFlagsToProtectionFlags(Flags);
    auto allocatedHostVa = ::VirtualAlloc(
        nullptr, Size, MEM_COMMIT | MEM_RESERVE, protectionFlags);
    if (allocatedHostVa == nullptr)
        return WhSeGetLastHresult();

    WHSE_ALLOCATION_NODE node{
        .BlockType = MEMORY_BLOCK_TYPE::MemoryBlockPhysical,
        .HostVirtualAddress = reinterpret_cast<uintptr_t>(allocatedHostVa),
        .GuestPhysicalAddress = suggestedGpa,
        .GuestVirtualAddress = 0,
        .Size = size};

    hresult = WhSeInsertAllocationTrackingNode(Partition, node);
    if (FAILED(hresult))
        return hresult;

    // Create the allocated range into the guest physical address space
    //
    hresult = ::WHvMapGpaRange(
        Partition->partition, allocatedHostVa,
        static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(suggestedGpa), size, Flags);
    if (FAILED(hresult)) {
        if (allocatedHostVa != nullptr)
            ::VirtualFree(allocatedHostVa, 0, MEM_RELEASE);

        return hresult;
    }

    *HostVa = reinterpret_cast<uintptr_t>(allocatedHostVa);
    *GuestPa = suggestedGpa;

    return hresult;
}

/**
 * @brief Map memory from host to guest physical address space (backed by host
 * memory)
 *
 * Map host memory to guest physical memory, mapping twice
 * on the same guest physical memory address will replace any existing mapping
 * but will not free the existing host backing memory.
 *
 * @param Partition The VM partition
 * @param HostVa The host virtual memory address backing the guest physical
 * memory
 * @param GuestPa The guest physical memory address
 * @param Size The size of the allocated memory
 * @param Flags The flags that describe the allocated memory (Read Write
 * Execute)
 * @return A result code
 */
HRESULT WhSeMapHostToGuestPhysicalMemory(whpx_state *Partition,
                                         uintptr_t HostVa, uintptr_t *GuestPa,
                                         size_t Size,
                                         WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (GuestPa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto size = ALIGN_UP(Size);

    uintptr_t suggestedGpa = 0;
    if (*GuestPa == 0) {
        auto hresult =
            WhSiSuggestPhysicalAddress(Partition, size, &suggestedGpa);
        if (FAILED(hresult))
            return hresult;
    } else
        suggestedGpa = ALIGN(*GuestPa);

    PWHSE_ALLOCATION_NODE existingNode = nullptr;
    auto hresult =
        WhSeFindAllocationNodeByGpa(Partition, suggestedGpa, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    if (existingNode != nullptr)
        return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);

    WHSE_ALLOCATION_NODE node{.BlockType =
                                  MEMORY_BLOCK_TYPE::MemoryBlockPhysical,
                              .HostVirtualAddress = HostVa,
                              .GuestPhysicalAddress = suggestedGpa,
                              .GuestVirtualAddress = 0,
                              .Size = size};

    hresult = WhSeInsertAllocationTrackingNode(Partition, node);
    if (FAILED(hresult))
        return hresult;

    // Map the memory range into the guest physical address space
    //
    hresult = ::WHvMapGpaRange(
        Partition->partition, reinterpret_cast<PVOID>(HostVa),
        static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(suggestedGpa), size, Flags);
    if (FAILED(hresult))
        return hresult;

    *GuestPa = suggestedGpa;

    return hresult;
}

/**
 * @brief Allocate memory in guest virtual address space (backed by host memory)
 *
 * Allocate memory in guest virtual address space (backed by host memory),
 * mapping twice on the same guest physical memory address will replace any
 * existing physical memory mapping but will not free the host virtual memory
 * nor update the guest PTEs.
 *
 * @param Partition The VM partition
 * @param HostVa The host virtual memory address backing the guest physical
 * memory
 * @param GuestVa The guest virtual memory address
 * @param Size The size of the allocated memory
 * @param Flags The flags that describe the allocated memory (Read Write
 * Execute)
 * @return A result code
 */
HRESULT WhSeAllocateGuestVirtualMemory(whpx_state *Partition, uintptr_t *HostVa,
                                       uintptr_t *GuestVa, size_t Size,
                                       WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (*HostVa != 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (GuestVa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto size = ALIGN_UP(Size);

    PWHSE_ALLOCATION_NODE existingNode = nullptr;
    auto hresult =
        WhSeFindAllocationNodeByGva(Partition, *GuestVa, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    uintptr_t suggestedGva = 0;
    if (*GuestVa == 0 || existingNode != nullptr) {
        auto hresult = WhSiSuggestVirtualAddress(
            Partition, size, &suggestedGva, Partition->VirtualProcessor.Mode);
        if (FAILED(hresult))
            return hresult;
    } else
        suggestedGva = ALIGN(*GuestVa);

    existingNode = nullptr;
    hresult =
        WhSeFindAllocationNodeByGva(Partition, suggestedGva, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    if (existingNode != nullptr)
        return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);

    // Compute starting and ending guest virtual addresses
    //
    auto startingGva = ALIGN(suggestedGva);
    auto endingGva = ALIGN_UP(startingGva + size);

    // Allocate memory into host
    //
    auto protectionFlags = AccessFlagsToProtectionFlags(Flags);
    auto allocatedHostVa = ::VirtualAlloc(
        nullptr, size, MEM_COMMIT | MEM_RESERVE, protectionFlags);
    if (allocatedHostVa == nullptr)
        return WhSeGetLastHresult();

    uintptr_t suggestedGpa = 0;
    hresult = WhSiSuggestPhysicalAddress(Partition, size, &suggestedGpa);
    if (FAILED(hresult))
        return hresult;

    WHSE_ALLOCATION_NODE node{
        .BlockType = MEMORY_BLOCK_TYPE::MemoryBlockVirtual,
        .HostVirtualAddress = reinterpret_cast<uintptr_t>(allocatedHostVa),
        .GuestPhysicalAddress = suggestedGpa,
        .GuestVirtualAddress = startingGva,
        .Size = size};

    hresult = WhSeInsertAllocationTrackingNode(Partition, node);
    if (FAILED(hresult))
        return hresult;

    // Setup matching PTEs
    //
    for (auto gva = startingGva, page = suggestedGpa; gva < endingGva;
         gva += PAGE_SIZE, page += PAGE_SIZE) {
        hresult = WhSiInsertPageTableEntry(Partition, gva, page);
        if (FAILED(hresult))
            return hresult;
    }

    hresult = ::WHvMapGpaRange(
        Partition->partition, allocatedHostVa,
        static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(suggestedGpa), size, Flags);
    if (FAILED(hresult)) {
        if (allocatedHostVa != nullptr)
            ::VirtualFree(allocatedHostVa, 0, MEM_RELEASE);

        return hresult;
    }

    *HostVa = reinterpret_cast<uintptr_t>(allocatedHostVa);
    *GuestVa = startingGva;

    return hresult;
}

/**
 * @brief Map memory from host to guest virtual address space (backed by host
 * memory)
 *
 * Map host memory to guest virtual memory, mapping twice
 * on the same guest physical memory address will replace any existing physical
 * memory mapping but will not free the host virtual memory nor update the guest
 * PTEs.
 *
 * @param Partition The VM partition
 * @param HostVa The host virtual memory address backing the guest physical
 * memory
 * @param GuestVa The guest virtual memory address
 * @param Size The size of the allocated memory
 * @param Flags The flags that describe the allocated memory (Read Write
 * Execute)
 * @return A result code
 */
HRESULT WhSeMapHostToGuestVirtualMemory(whpx_state *Partition, uintptr_t HostVa,
                                        uintptr_t *GuestVa, size_t Size,
                                        WHSE_MEMORY_ACCESS_FLAGS Flags)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (GuestVa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto size = ALIGN_UP(Size);

    PWHSE_ALLOCATION_NODE existingNode = nullptr;
    auto hresult =
        WhSeFindAllocationNodeByGva(Partition, *GuestVa, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    uintptr_t suggestedGva = 0;
    if (*GuestVa == 0 || existingNode != nullptr) {
        auto hresult = WhSiSuggestVirtualAddress(
            Partition, size, &suggestedGva, Partition->VirtualProcessor.Mode);
        if (FAILED(hresult))
            return hresult;
    } else
        suggestedGva = ALIGN(*GuestVa);

    existingNode = nullptr;
    hresult =
        WhSeFindAllocationNodeByGva(Partition, suggestedGva, &existingNode);
    if (hresult != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && FAILED(hresult))
        return hresult;

    if (existingNode != nullptr)
        return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);

    // Compute starting and ending guest virtual addresses
    //
    auto startingGva = ALIGN(suggestedGva);
    auto endingGva = ALIGN_UP(startingGva + size);

    uintptr_t suggestedGpa = 0;
    hresult = WhSiSuggestPhysicalAddress(Partition, size, &suggestedGpa);
    if (FAILED(hresult))
        return hresult;

    WHSE_ALLOCATION_NODE node{.BlockType =
                                  MEMORY_BLOCK_TYPE::MemoryBlockVirtual,
                              .HostVirtualAddress = HostVa,
                              .GuestPhysicalAddress = suggestedGpa,
                              .GuestVirtualAddress = startingGva,
                              .Size = size};

    hresult = WhSeInsertAllocationTrackingNode(Partition, node);
    if (FAILED(hresult))
        return hresult;

    // Setup matching PTEs
    //
    for (auto gva = startingGva, page = suggestedGpa; gva < endingGva;
         gva += PAGE_SIZE, page += PAGE_SIZE) {
        hresult = WhSiInsertPageTableEntry(Partition, gva, page);
        if (FAILED(hresult))
            return hresult;
    }

    hresult = ::WHvMapGpaRange(
        Partition->partition, reinterpret_cast<PVOID>(HostVa),
        static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(suggestedGpa), size, Flags);
    if (FAILED(hresult))
        return hresult;

    *GuestVa = startingGva;

    return hresult;
}

/**
 * @brief Free memory in guest physical address space
 *
 * @param Partition The VM partition
 * @param HostVa The host memory virtual address backing the physical guest
 * memory
 * @param GuestPa The guest memory physical address
 * @param Size The size of the allocation
 * @return A result code
 */
HRESULT WhSeFreeGuestPhysicalMemory(whpx_state *Partition, uintptr_t HostVa,
                                    uintptr_t GuestPa, size_t Size)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    /*WHSE_ALLOCATION_NODE* node = nullptr;
    auto hresult = WhSeFindAllocationNodeByGpa( Partition, GuestPa, &node );
    if ( FAILED( hresult ) )
            return hresult;*/

    auto hresult = ::WHvUnmapGpaRange(
        Partition->partition, static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(GuestPa),
        ALIGN_UP(Size));
    if (FAILED(hresult))
        return hresult;

    auto result =
        ::VirtualFree(reinterpret_cast<PVOID>(HostVa), 0, MEM_RELEASE);
    if (!result)
        return WhSeGetLastHresult();

    return hresult;
}

/**
 * @brief Free memory in guest virtual address space
 *
 * @param Partition The VM partition
 * @param HostVa The host memory virtual address backing the physical guest
 * memory
 * @param GuestVa The guest memory virtual address
 * @param Size The size of the allocation
 * @return A result code
 */
HRESULT WhSeFreeGuestVirtualMemory(whpx_state *Partition, uintptr_t HostVa,
                                   uintptr_t GuestVa, size_t Size)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (HostVa == 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    /*WHSE_ALLOCATION_NODE* node = nullptr;
    auto hresult = WhSeFindAllocationNodeByGva( Partition, GuestVa, &node );
    if ( FAILED( hresult ) )
            return hresult;*/

    uintptr_t gpa{};
    auto hresult = WhSeTranslateGvaToGpa(Partition, GuestVa, &gpa, nullptr);
    if (FAILED(hresult))
        return hresult;

    hresult = ::WHvUnmapGpaRange(Partition->partition,
                                 static_cast<WHV_GUEST_PHYSICAL_ADDRESS>(gpa),
                                 ALIGN_UP(Size));
    if (FAILED(hresult))
        return hresult;

    auto result =
        ::VirtualFree(reinterpret_cast<PVOID>(HostVa), 0, MEM_RELEASE);
    if (!result)
        return WhSeGetLastHresult();

    return hresult;
}
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK (1U << 10)
/**
 * @brief Initialize paging and other memory stuff for the partition
 *
 * @param Partition The VM partition
 * @return A result code
 */
EXTERN_C HRESULT WhSeInitializeMemoryLayout(whpx_state *Partition)
{
    HRESULT hresult = S_OK;
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    Partition->VirtualProcessor.Mode = KernelMode;

    hresult = WhSiInitializeMemoryArena(Partition);
    if (FAILED(hresult))
        return hresult;

    uintptr_t pml4Address = 0;
    Partition->MemoryLayout.Pml4HostVa = 0;

    // Build paging tables
    //
    hresult = WhSiSetupPaging(Partition, &pml4Address);
    if (FAILED(hresult))
        return hresult;

    Partition->MemoryLayout.Pml4PhysicalAddress = pml4Address;
    WHV_REGISTER_NAME RegisterName = WHvX64RegisterCr0;
    uint64_t cr0val = 0;

    whpx_get_reg(RegisterName, &cr0val);

    cr0val = (cr0val | (1ULL << 31) | (1 << 0)) & UINT32_MAX;

    whpx_set_reg(RegisterName, cr0val);

    whpx_set_reg(WHvX64RegisterCr3, pml4Address);
    RegisterName = WHvX64RegisterCr4;

    uint64_t cr4val = 0;

    whpx_get_reg(RegisterName, &cr4val);

    cr4val = (cr4val | (1ULL << 5)) & ~(1 << 24);
    cr4val |= CR4_OSXSAVE_MASK;
    cr4val |= CR4_OSFXSR_MASK;
    cr4val |= CR4_OSXMMEXCPT_MASK;
    whpx_set_reg(RegisterName, cr4val);
    uint64_t Eferval = 0;

    RegisterName = WHvX64RegisterEfer;
    whpx_get_reg(RegisterName, &Eferval);
    Eferval = (Eferval | (1ULL << 0) | (1ULL << 8)) & ~(1 << 16);
    whpx_set_reg(RegisterName, Eferval);
    printf("Cr0 :%016llx,Cr3:%016llx,Cr4:%016llx,Efer:%016llx\r\n", cr0val,
           pml4Address, cr4val, Eferval);

    uintptr_t rflagval =
        MAKE_RFLAGS(0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    whpx_set_reg(WHvX64RegisterRflags, rflagval);

    hresult = WhSiSetupGlobalDescriptorTable(Partition);
    if (FAILED(hresult))
        return hresult;

    hresult = WhSiSetupInterruptDescriptorTable(Partition);
    if (FAILED(hresult))
        return hresult;

    hresult = WhSpSwitchProcessor(Partition->VirtualProcessor.Mode);
    if (FAILED(hresult))
        return hresult;

    return hresult;
    /*
    auto registers = Partition->VirtualProcessor.Registers;
    hresult = WhSeGetProcessorRegisters( Partition, registers );
    if ( FAILED( hresult ) )
            return hresult;

    // Enable paging and protected mode
    //
    registers[ Cr0 ].Reg64 = ( registers[ Cr0 ].Reg64 | ( 1ULL << 31 ) | ( 1 <<
    0 ) ) & UINT32_MAX;

    // Set the pml4 physical address
    //
    registers[ Cr3 ].Reg64 = pml4Address;

    // Enable PAE
    //
    registers[ Cr4 ].Reg64 = ( registers[ Cr4 ].Reg64 | ( 1ULL << 5 ) ) & ~( 1
    << 24 );

    // Enable Long Mode and Syscall
    //
    registers[ Efer ].Reg64 = ( registers[ Efer ].Reg64 | ( 1ULL << 0 ) | ( 1ULL
    << 8 ) ) & ~( 1 << 16 );

    // Update registers at this point
    //
    hresult = WhSeSetProcessorRegisters( Partition, registers );
    if ( FAILED( hresult ) )
            return hresult;

    // Setup GDT
    //


    // Setup IDT
    //
    hresult = WhSiSetupInterruptDescriptorTable( Partition, registers );
    if ( FAILED( hresult ) )
            return hresult;

    /#1#/ Setup Syscall
    //
    hresult = WhSiSetupSyscalls( Partition, registers );
    if ( FAILED( hresult ) )
            return hresult;
            #1#

    return WhSeSetProcessorRegisters( Partition, registers );*/
}

/**
 * @brief Translate guest virtual address to guest physical address
 *
 * @param Partition The VM partition
 * @param VirtualAddress The guest virtual address to be translated
 * @param PhysicalAddress The guest physical address backing the guest virtual
 * address
 * @param TranslationResult The translation result
 * @return A result code
 */
HRESULT WhSeTranslateGvaToGpa(whpx_state *Partition, uintptr_t VirtualAddress,
                              uintptr_t *PhysicalAddress,
                              WHV_TRANSLATE_GVA_RESULT *TranslationResult)
{
    if (PhysicalAddress == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    WHV_GUEST_PHYSICAL_ADDRESS gpa;
    WHV_TRANSLATE_GVA_RESULT translationResult{};

    WHV_TRANSLATE_GVA_FLAGS flags = WHvTranslateGvaFlagValidateRead |
                                    WHvTranslateGvaFlagValidateWrite |
                                    WHvTranslateGvaFlagPrivilegeExempt;

    auto hresult = ::WHvTranslateGva(
        Partition->partition, Partition->VirtualProcessor.Index, VirtualAddress,
        flags, &translationResult, &gpa);
    if (FAILED(hresult))
        return hresult;

    if (TranslationResult != nullptr)
        *TranslationResult = translationResult;

    *PhysicalAddress = gpa;

    return hresult;
}
