#include <comdef.h>
#include "WinHvMemoryInternal.hpp"
#include "WinHvMemory.hpp"
#include "WinHvUtils.hpp"
#include "winbase.h"
#include "winerror.h"
#include "winnt.h"
#include <cstdint>
#include "WinHvMemoryPrivate.hpp"
#include "WinHvAllocationTracker.hpp"
#include "WinHvHelpers.hpp"

// Allocation strategy :
// * Allocate by block
// * To get base, find holes (due to deallocation) between nodes (need sorting
// periodically)
// * A hole : b1 base + size <-- n free bytes there --> b2 base + size
// * If a requested allocation can fit in the free bytes (the hole) then pick a
// block in this hole
// * Else allocate at the tail (highest base + size)

void FilterNodesByPhysicalAddress(PDLIST_HEADER Destination,
                                  PDLIST_HEADER Source)
{
    if (Destination == NULL)
        return;

    if (Source == NULL)
        return;

    WHSE_ALLOCATION_NODE *head = (WHSE_ALLOCATION_NODE *)GetDListHead(Source);
    for (WHSE_ALLOCATION_NODE *current = head; current != NULL;
         current = (WHSE_ALLOCATION_NODE *)current->Next) {
        if (current->BlockType == MemoryBlockPhysical ||
            current->BlockType == MemoryBlockVirtual) {
            WHSE_ALLOCATION_NODE *entry =
                (WHSE_ALLOCATION_NODE *)malloc(sizeof(WHSE_ALLOCATION_NODE));
            if (entry == nullptr)
                return;

            memcpy(entry, current, sizeof(WHSE_ALLOCATION_NODE));

            entry->Prev = nullptr;
            entry->Next = nullptr;

            PushBackDListEntry(Destination, entry);
        }
    }
}

int ComparePhysNode(const WHSE_ALLOCATION_NODE **a,
                    const WHSE_ALLOCATION_NODE **b)
{
    return static_cast<int>((*a)->GuestPhysicalAddress -
                            (*b)->GuestPhysicalAddress);
}

void SortNodesByPhysicalAddress(PDLIST_HEADER Header)
{
    if (Header == NULL)
        return;

    SortDListBy(Header, (PDLIST_COMPARATOR)ComparePhysNode);
}

void FilterNodesByVirtualAddress(PDLIST_HEADER Destination,
                                 PDLIST_HEADER Source, uintptr_t Lowest,
                                 uintptr_t Highest)
{
    if (Destination == NULL)
        return;

    if (Source == NULL)
        return;

    WHSE_ALLOCATION_NODE *head = (WHSE_ALLOCATION_NODE *)GetDListHead(Source);

    for (WHSE_ALLOCATION_NODE *current = head; current != NULL;
         current = (WHSE_ALLOCATION_NODE *)current->Next) {
        if (current->BlockType == MemoryBlockVirtual &&
            current->GuestVirtualAddress >= Lowest &&
            current->GuestVirtualAddress < Highest) {
            PDLIST_ENTRY entry =
                (PDLIST_ENTRY)malloc(sizeof(WHSE_ALLOCATION_NODE));
            if (entry == nullptr)
                return;

            memcpy(entry, current, sizeof(WHSE_ALLOCATION_NODE));

            entry->Prev = nullptr;
            entry->Next = nullptr;

            PushBackDListEntry(Destination, entry);
        }
    }
}

int CompareVirtNode(const WHSE_ALLOCATION_NODE **a,
                    const WHSE_ALLOCATION_NODE **b)
{
    return static_cast<int>((*a)->GuestVirtualAddress -
                            (*b)->GuestVirtualAddress);
}

void SortNodesByVirtualAddress(PDLIST_HEADER Header)
{
    if (Header == NULL)
        return;

    SortDListBy(Header, (PDLIST_COMPARATOR)CompareVirtNode);
}

/**
 * @brief Break down a virtual address to paging indexes
 *
 * @param VirtualAddress The virtual address
 * @param Pml4Index The Page Map Level Four (PML4) index
 * @param PdpIndex The Page Directory Pointers index
 * @param PdIndex The Page Directory index
 * @param PtIndex The Page Table index
 * @param Offset The physical page offset
 * @return A result code
 */
HRESULT WhSiDecomposeVirtualAddress(uintptr_t VirtualAddress,
                                    uint16_t *Pml4Index, uint16_t *PdpIndex,
                                    uint16_t *PdIndex, uint16_t *PtIndex,
                                    uint16_t *Offset)
{

    *Offset = VirtualAddress & 0xFFF;
    *PtIndex = (VirtualAddress >> 12) & 0x1FF;
    *PdIndex = (VirtualAddress >> (12 + 9)) & 0x1FF;
    *PdpIndex = (VirtualAddress >> (12 + 9 * 2)) & 0x1FF;
    *Pml4Index = (VirtualAddress >> (12 + 9 * 3)) & 0x1FF;

    return S_OK;
}

/**
 * @brief Suggest a physical address depending on allocation size
 *
 * @param Partition The VM partition
 * @param Size The allocation size
 * @param PhysicalPageAddress The returned guest physical address
 * @return A result code
 */
HRESULT WhSiSuggestPhysicalAddress(whpx_state *Partition, size_t Size,
                                   uintptr_t *PhysicalPageAddress)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (PhysicalPageAddress == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (*PhysicalPageAddress != 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto arena = &(Partition->MemoryLayout.MemoryArena);

    uintptr_t lowest = arena->PhysicalAddressSpace.LowestAddress;
    uintptr_t highest = arena->PhysicalAddressSpace.HighestAddress;

    uintptr_t suggestedAddress = 0;

    // Initialize temporary list
    //
    DLIST_HEADER physicalNodesList;
    memset(&physicalNodesList, 0, sizeof(DLIST_HEADER));
    InitializeDListHeader(&physicalNodesList);

    // Build the filtered list
    //
    FilterNodesByPhysicalAddress(&physicalNodesList,
                                 &(arena->AllocatedMemoryBlocks));

    // Sort the filtered list
    //
    SortNodesByPhysicalAddress(&physicalNodesList);
    // SortNodesByPhysicalAddress( &( arena->AllocatedMemoryBlocks ) );

    // Iterate nodes from head to the one before the tail
    //
    WHSE_ALLOCATION_NODE *head =
        (WHSE_ALLOCATION_NODE *)GetDListHead(&physicalNodesList);
    // WHSE_ALLOCATION_NODE* head = ( WHSE_ALLOCATION_NODE* ) GetDListHead( &(
    // arena->AllocatedMemoryBlocks ) );
    if (head != NULL) {
        WHSE_ALLOCATION_NODE *current = NULL;
        for (current = head; current->Next != NULL;
             current = (WHSE_ALLOCATION_NODE *)current->Next) {
            WHSE_ALLOCATION_NODE *next = (WHSE_ALLOCATION_NODE *)current->Next;

            if (ALIGN_UP(
                    ALIGN_UP(current->GuestPhysicalAddress + current->Size) +
                    Size) < next->GuestPhysicalAddress) {
                suggestedAddress =
                    ALIGN_UP(current->GuestPhysicalAddress + current->Size);
                break;
            }
        }

        if (suggestedAddress == 0 &&
            current ==
                (WHSE_ALLOCATION_NODE *)GetDListTail(&physicalNodesList)) {
            // if ( suggestedAddress == 0 && current == ( WHSE_ALLOCATION_NODE*
            // ) GetDListTail( &( arena->AllocatedMemoryBlocks ) ) ) {
            // Suggest address at the tail
            //
            suggestedAddress =
                ALIGN_UP(current->GuestPhysicalAddress + current->Size);
        }
    } else {
        suggestedAddress = lowest;
    }

    FlushDList(&physicalNodesList);

    if (suggestedAddress < lowest || suggestedAddress >= (highest - Size))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    *PhysicalPageAddress = suggestedAddress;

    return S_OK;
}

/**
 * @brief Suggest a virtual address depending on allocation size
 *
 * @param Partition The VM partition
 * @param Size The allocation size
 * @param VirtualAddress The returned guest physical address
 * @return A result code
 */
HRESULT WhSiSuggestVirtualAddress(whpx_state *Partition, size_t Size,
                                  uintptr_t *VirtualAddress,
                                  WHSE_PROCESSOR_MODE Mode)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (VirtualAddress == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (*VirtualAddress != 0)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto arena = &(Partition->MemoryLayout.MemoryArena);

    uintptr_t lowest = 0;
    uintptr_t highest = 0;

    if (Mode == WHSE_PROCESSOR_MODE::KernelMode) {
        lowest = arena->VirtualAddressSpace.SystemSpace.LowestAddress;
        highest = arena->VirtualAddressSpace.SystemSpace.HighestAddress;
    } else if (Mode == WHSE_PROCESSOR_MODE::UserMode) {
        lowest = arena->VirtualAddressSpace.UserSpace.LowestAddress;
        highest = arena->VirtualAddressSpace.UserSpace.HighestAddress;
    } else
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    uintptr_t suggestedAddress = 0;

    // Initialize temporary list
    //
    DLIST_HEADER virtualNodesList;
    memset(&virtualNodesList, 0, sizeof(DLIST_HEADER));
    InitializeDListHeader(&virtualNodesList);

    // Build the filtered list
    //
    FilterNodesByVirtualAddress(
        &virtualNodesList, &(arena->AllocatedMemoryBlocks), lowest, highest);

    // Sort the filtered list
    //
    SortNodesByVirtualAddress(&virtualNodesList);

    // Iterate nodes from head to the one before the tail
    //
    WHSE_ALLOCATION_NODE *head =
        (WHSE_ALLOCATION_NODE *)GetDListHead(&virtualNodesList);
    if (head != NULL) {
        WHSE_ALLOCATION_NODE *current = NULL;
        for (current = head; current->Next != NULL;
             current = (WHSE_ALLOCATION_NODE *)current->Next) {
            WHSE_ALLOCATION_NODE *next = (WHSE_ALLOCATION_NODE *)current->Next;

            if (ALIGN_UP(
                    ALIGN_UP(current->GuestVirtualAddress + current->Size) +
                    Size) < next->GuestVirtualAddress) {
                suggestedAddress =
                    ALIGN_UP(current->GuestVirtualAddress + current->Size);
                break;
            }
        }

        if (suggestedAddress == 0 &&
            current ==
                (WHSE_ALLOCATION_NODE *)GetDListTail(&virtualNodesList)) {
            // Suggest address at the tail
            //
            suggestedAddress =
                ALIGN_UP(current->GuestVirtualAddress + current->Size);
        }
    } else {
        suggestedAddress = lowest;
    }

    FlushDList(&virtualNodesList);

    if (suggestedAddress < lowest || suggestedAddress >= (highest - Size))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    *VirtualAddress = suggestedAddress;

    return S_OK;
}

/**
 * @brief Internal function to setup paging
 *
 * @param Partition The VM partition
 * @param Pml4PhysicalAddress
 * @return A result code
 */
HRESULT WhSiSetupPaging(whpx_state *Partition, uintptr_t *Pml4PhysicalAddress)
{
    // Check if already initialized
    //
    if (Partition->MemoryLayout.Pml4HostVa != 0)
        return HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED);

    // Allocate PML4 on physical memory
    //
    uintptr_t pml4Gpa = 0;
    uintptr_t pml4Hva = 0;
    auto hresult = WhSeAllocateGuestPhysicalMemory(
        Partition, &pml4Hva, &pml4Gpa, PAGE_SIZE,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hresult))
        return hresult;

    Partition->MemoryLayout.Pml4HostVa = pml4Hva;

    auto pml4 = reinterpret_cast<PMMPTE_HARDWARE>(pml4Hva);

    for (auto i = 0; i < 512; i++) {
        // Allocate a Page Directory Pointers page
        // The memory is zeroed so every PDP entries will have the Valid
        // (Present) bit set to 0
        //
        hresult = WhSpInsertPageTableEntry(Partition, pml4, i);
        if (FAILED(hresult))
            return hresult;
    }

    *Pml4PhysicalAddress = pml4Gpa;

    return hresult;
}

/**
 * @brief Internal function to insert page table in the paging directory
 *
 * Internal function to insert page table in the paging directory
 * Allocate PML4 entry, PDP entry, PD entry and PT entry
 *
 * @param Partition The VM partition
 * @param VirtualAddress
 * @param PhysicalAddress
 * @return A result code
 */
HRESULT WhSiInsertPageTableEntry(whpx_state *Partition,
                                 uintptr_t VirtualAddress,
                                 uintptr_t PhysicalAddress)
{
    // "Explode" the VA into translation indexes
    //
    uint16_t pml4Idx;
    uint16_t pdpIdx;
    uint16_t pdIdx;
    uint16_t ptIdx;
    uint16_t phyOffset;

    auto hresult = WhSiDecomposeVirtualAddress(
        VirtualAddress, &pml4Idx, &pdpIdx, &pdIdx, &ptIdx, &phyOffset);
    if (FAILED(hresult))
        return hresult;

    // Search entry in PML4
    //
    auto pml4e = reinterpret_cast<PMMPTE_HARDWARE>(
        Partition->MemoryLayout.Pml4HostVa)[pml4Idx];
    if (pml4e.Valid == FALSE) {
        // Shouldn't happen as we initialized all PLM4 entries upfront
        //
        DebugBreak();
        return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);
    }

    // Search entry in Page Directory Pointers
    //
    uintptr_t pdpHva = 0;
    hresult = WhSpLookupHVAFromPFN(Partition, pml4e.PageFrameNumber, &pdpHva);
    if (FAILED(hresult))
        return hresult;

    auto pdp = reinterpret_cast<PMMPTE_HARDWARE>(pdpHva);
    auto pdpe = pdp[pdpIdx];
    if (pdpe.Valid == FALSE) {
        // Allocate a Page Directory page
        //
        hresult = WhSpInsertPageTableEntry(Partition, pdp, pdpIdx);

        if (FAILED(hresult))
            return hresult;

        pdpe = pdp[pdpIdx];
    }

    // Search entry in Page Directories
    //
    uintptr_t pdHva = 0;
    hresult = WhSpLookupHVAFromPFN(Partition, pdpe.PageFrameNumber, &pdHva);
    if (FAILED(hresult))
        return hresult;

    auto pd = reinterpret_cast<PMMPTE_HARDWARE>(pdHva);
    auto pde = pd[pdIdx];
    if (pde.Valid == FALSE) {
        // Allocate a Page Table page
        //
        hresult = WhSpInsertPageTableEntry(Partition, pd, pdIdx);

        if (FAILED(hresult))
            return hresult;

        pde = pd[pdIdx];
    }

    // Add entry in Page Tables
    //
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

        if ( found != nullptr )
                return HRESULT_FROM_WIN32( ERROR_INTERNAL_ERROR );*/

        // Create a valid PTE
        //
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
        if (FAILED(hresult))
            return hresult;
    }

    return S_OK;
}

/**
 * @brief Find a suitable Guest VA
 *
 * @param Partition The VM partition
 * @param GuestVa
 * @param Size
 * @return A result code
 */
HRESULT WhSiFindBestGVA(whpx_state *Partition, uintptr_t *GuestVa, size_t Size)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    if (GuestVa == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto tracker = &(Partition->MemoryLayout.MemoryArena.AllocatedMemoryBlocks);

    auto first =
        reinterpret_cast<WHSE_ALLOCATION_NODE *>(GetDListHead(tracker));
    if (first == nullptr)
        return HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS);

    uintptr_t highestExistingGva = 0;
    size_t highestExistingGvaSize = 0;
    auto current = first;
    while (current != nullptr) {
        uintptr_t currentGva = current->GuestVirtualAddress;
        if (currentGva > highestExistingGva) {
            highestExistingGva = currentGva;
        }

        current = reinterpret_cast<WHSE_ALLOCATION_NODE *>(current->Next);
    }

    if (current == nullptr)
        return HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS);

    auto va = ALIGN_UP(highestExistingGva + highestExistingGvaSize);

    *GuestVa = va;

    return S_OK;
}

constexpr uint8_t MAKE_IDT_ATTRS(uint8_t Dpl, uint8_t GateType)
{
    return ((1 << 7)                         // Present bit
            | ((Dpl << 6) & 0b11) | (0 << 4) // Reserved bit
            | (GateType & 0b1111));
}

HRESULT WhSpSwitchProcessor(WHSE_PROCESSOR_MODE Mode)
{

    int ring;
    int codeSelector;
    int dataSelector;

    switch (Mode) {
        using enum WHSE_PROCESSOR_MODE;
    case UserMode:
        ring = 3;
        codeSelector = 0x18;
        dataSelector = 0x20;
        break;
    case KernelMode:
        ring = 0;
        codeSelector = 0x08;
        dataSelector = 0x10;
        break;
    default:
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    WHV_REGISTER_VALUE CsReg = {0};
    WHV_REGISTER_VALUE SsReg = {0};
    // Setup segment registers
    whpx_get_reg_value(WHvX64RegisterCs, &CsReg);
    whpx_get_reg_value(WHvX64RegisterSs, &SsReg);
    CsReg.Segment.Selector = (codeSelector | ring);
    CsReg.Segment.DescriptorPrivilegeLevel = ring;
    CsReg.Segment.Long = 1;

    SsReg.Segment.Selector = (dataSelector | ring);
    SsReg.Segment.DescriptorPrivilegeLevel = ring;
    SsReg.Segment.Default = 1;
    SsReg.Segment.Granularity = 1;

    printf("Cs Selector:%08x,DescriptorPrivilegeLevel:%08x,Long:%08x\r\n",
           CsReg.Segment.Selector, CsReg.Segment.DescriptorPrivilegeLevel,
           CsReg.Segment.Long);
    printf("Ss "
           "Selector:%08x,DescriptorPrivilegeLevel:%08x,Default:%08x,"
           "Granularity:%08x\r\n",
           SsReg.Segment.Selector, SsReg.Segment.DescriptorPrivilegeLevel,
           SsReg.Segment.Default, SsReg.Segment.Granularity);

    // 初始化 CS 寄存器（代码段寄存器）
    /*WHV_REGISTER_NAME name = WHvX64RegisterCs;
    WHV_REGISTER_VALUE value = {};
    value.Segment.Base = 0x00000000;
    value.Segment.Limit = 0x0000FFFF;
    value.Segment.Selector = 0x0000;
    value.Segment.Attributes =
        0x009B; // 代码段的属性，详情可以参考该字段的定义和 Intel 手册*/

  //  whpx_set_reg_value(WHvX64RegisterCs, value);
    //return S_OK;
    whpx_set_reg_value(WHvX64RegisterCs, CsReg);
    whpx_set_reg_value(WHvX64RegisterSs, SsReg);
    whpx_set_reg_value(WHvX64RegisterDs, SsReg);
    whpx_set_reg_value(WHvX64RegisterEs, SsReg);
    // whpx_set_reg_value(WHvX64RegisterFs, SsReg);
    whpx_set_reg_value(WHvX64RegisterGs, SsReg);

    return S_OK;
}

/** @brief Setup GDT
*
* @param Partition The VM partition
* @param Registers
* @return A result code
#2#*/
HRESULT WhSiSetupGlobalDescriptorTable(whpx_state *Partition)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    // Allocate GDT
    //
    uintptr_t gdtHva = 0;
    // uintptr_t gdtGva = 0xfffff800'00000000;
    uintptr_t gdtGva = 0;
    auto hresult = WhSeAllocateGuestVirtualMemory(
        Partition, &gdtHva, &gdtGva, PAGE_SIZE,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hresult))
        return hresult;

    // Create the descriptors
    //
    uintptr_t base = 0;
    ptrdiff_t limit = 0xfffff;

    GDT_ENTRY nullDesc{0};
    hresult = WhSpCreateGdtEntry(&nullDesc, 0, 0, 0x00, 0x0);
    if (FAILED(hresult))
        return hresult;

    GDT_ENTRY kernelModeCodeSegmentDesc{0};
    hresult =
        WhSpCreateGdtEntry(&kernelModeCodeSegmentDesc, base, limit, 0x9a, 0xa);
    if (FAILED(hresult))
        return hresult;

    GDT_ENTRY kernelModeDataSegmentDesc{0};
    hresult =
        WhSpCreateGdtEntry(&kernelModeDataSegmentDesc, base, limit, 0x92, 0xc);
    if (FAILED(hresult))
        return hresult;

    GDT_ENTRY userModeCodeSegmentDesc{0};
    hresult =
        WhSpCreateGdtEntry(&userModeCodeSegmentDesc, base, limit, 0xfa, 0xa);
    if (FAILED(hresult))
        return hresult;

    GDT_ENTRY userModeDataSegmentDesc{0};
    hresult =
        WhSpCreateGdtEntry(&userModeDataSegmentDesc, base, limit, 0xf2, 0xc);
    if (FAILED(hresult))
        return hresult;

    // Allocate a page for the TSS
    //
    uintptr_t tssHva = 0;
    // uintptr_t tssGva = 0xfffff800'00001000;
    uintptr_t tssGva = 0;
    hresult = WhSeAllocateGuestVirtualMemory(
        Partition, &tssHva, &tssGva, sizeof(X64_TASK_STATE_SEGMENT),
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hresult))
        return hresult;

    hresult = WhSpInitializeTss(
        Partition, reinterpret_cast<PX64_TASK_STATE_SEGMENT>(tssHva));
    if (FAILED(hresult))
        return hresult;

    X64_TSS_ENTRY tssSegmentDesc{0};
    hresult = WhSpCreateTssEntry(&tssSegmentDesc, tssGva,
                                 sizeof(X64_TASK_STATE_SEGMENT) - 1, 0x89, 0);
    if (FAILED(hresult))
        return hresult;

    // Load the temp descriptors in memory
    //
    PGDT_ENTRY gdt = reinterpret_cast<PGDT_ENTRY>(gdtHva);

    // Offset : 0x0000	Use : Null Descriptor
    //
    gdt[0] = nullDesc;

    // Offset : 0x0008	Use : Kernel Mode Code Segment
    //
    gdt[1] = kernelModeCodeSegmentDesc;

    // Offset : 0x0010	Use : Kernel Mode Data Segment
    //
    gdt[2] = kernelModeDataSegmentDesc;

    // Offset : 0x0018	Use : User Mode Code Segment
    //
    gdt[3] = userModeCodeSegmentDesc;

    // Offset : 0x0020	Use : User Mode Data Segment
    //
    gdt[4] = userModeDataSegmentDesc;

    // Offset : 0x0028	Use : 64-bit Task State Segment
    //
    *reinterpret_cast<PX64_TSS_ENTRY>(&(gdt[5])) = tssSegmentDesc;

    WHV_REGISTER_VALUE GdtrReg = {0};

    whpx_get_reg_value(WHvX64RegisterGdtr, &GdtrReg);

    // Load GDTR
    //
    GdtrReg.Table.Base = gdtGva;
    GdtrReg.Table.Limit = static_cast<uint16_t>(
        (sizeof(X64_TSS_ENTRY) +
         (sizeof(GDT_ENTRY) * NUMBER_OF_GDT_DESCRIPTORS)) -
        1);
    whpx_set_reg_value(WHvX64RegisterGdtr, GdtrReg);
    // Load TR
    //
    printf("Gdtr Selector:%08x,Base:%016llx,Limit:%08x\r\n",
           GdtrReg.Segment.Selector, GdtrReg.Table.Base, GdtrReg.Table.Limit);
    

    /*WHV_REGISTER_VALUE TrReg = {0};
    whpx_get_reg_value(WHvX64RegisterTr, &TrReg);
    TrReg.Segment.Selector = 0x0028;
    //TrReg.Segment.Selector = 0;
    whpx_set_reg_value(WHvX64RegisterTr, TrReg);*/
    // Registers[ Tr ].Segment.Base = Registers[ Gdtr ].Table.Base;
    // Registers[ Tr ].Segment.Limit = Registers[ Gdtr ].Table.Limit;

    Partition->VirtualProcessor.Gdt = reinterpret_cast<PGDT_ENTRY>(gdtHva);
    Partition->VirtualProcessor.Tss =
        reinterpret_cast<PX64_TASK_STATE_SEGMENT>(tssHva);

    return S_OK;
}

/**
 * @brief Setup IDT
 *
 * @param Partition The VM partition
 * @param Registers
 * @return A result code
 */
HRESULT WhSiSetupInterruptDescriptorTable(whpx_state *Partition)
{
    if (Partition == nullptr) {
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }

    // Allocate two pages, one for the IDT
    //
    uintptr_t idtHva = 0;
    // uintptr_t idtGva = 0xfffff800'00002000;
    uintptr_t idtGva = 0;
    auto hresult = WhSeAllocateGuestVirtualMemory(
        Partition, &idtHva, &idtGva, PAGE_SIZE,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hresult))
        return hresult;

    // The other one to trap ISR access
    //
    uintptr_t idtTrapHva = 0;
    // uintptr_t idtTrapGva = 0xfffff800'00003000;
    uintptr_t idtTrapGva = 0;
    hresult = WhSeAllocateGuestVirtualMemory(
        Partition, &idtTrapHva, &idtTrapGva, PAGE_SIZE,
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hresult))
        return hresult;

    // Unmap the 2nd page immediately, keeping paging information butreleasing
    // the backing memory, thus it will generate a memory access exception when
    // trying to jumpto the Interrupt Service Routine
    //
    hresult = WhSeFreeGuestVirtualMemory(Partition, idtTrapHva, idtTrapGva,
                                         PAGE_SIZE);
    if (FAILED(hresult))
        return hresult;

    // Fill IDT
    //
    auto ptr = idtTrapGva;
    auto idt = reinterpret_cast<PIDT_ENTRY>(idtHva);
    for (auto idx = 0; idx < NUMBER_OF_IDT_DESCRIPTORS; idx++) {
        auto entry = IDT_ENTRY{
            .Low = static_cast<uint16_t>(ptr & UINT16_MAX),
            .Selector =
                0x0008, // Kernel CS index .InterruptStackTable = 0, .Attributes
            .Attributes = MAKE_IDT_ATTRS(0b00, 0b1110),
            .Mid = static_cast<uint16_t>((ptr >> 16) & UINT16_MAX),
            .High = static_cast<uint32_t>((ptr >> 32) & UINT32_MAX),
            .Reserved = 0};

        idt[idx] = entry;
        ptr += sizeof(decltype(ptr));
    }
    WHV_REGISTER_VALUE IdtrReg = {0};
    whpx_get_reg_value(WHvX64RegisterIdtr, &IdtrReg);
    // Load IDTR
    //
    IdtrReg.Table.Base = idtGva;
    IdtrReg.Table.Limit = static_cast<uint16_t>(
        (sizeof(IDT_ENTRY) * NUMBER_OF_IDT_DESCRIPTORS) - 1);

    Partition->MemoryLayout.InterruptDescriptorTableVirtualAddress = idtTrapGva;
    whpx_set_reg_value(WHvX64RegisterIdtr, IdtrReg);
    return S_OK;
}

/**
 * @brief Setup memory arena
 *
 * @param Partition The VM partition
 * @return A result code
 */
HRESULT WhSiInitializeMemoryArena(whpx_state *Partition)
{
    if (Partition == nullptr)
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

    auto arena = &(Partition->MemoryLayout.MemoryArena);

    // Get available physical memory
    //
    uint64_t totalMemInKib = 0;
    if (::GetPhysicallyInstalledSystemMemory(&totalMemInKib) == FALSE &&
        totalMemInKib == 0)
        return WhSeGetLastHresult();

    // Initialize Physical Address Space (PAS)
    //
    arena->PhysicalAddressSpace.LowestAddress = 0x00000000'00000000;
    arena->PhysicalAddressSpace.HighestAddress = (totalMemInKib << 10) - 1;
    arena->PhysicalAddressSpace.Size = totalMemInKib << 10;

    // Initialize Virtual Address Space (VAS)
    //
    uintptr_t lowestUserVa = 0x00000000'00000000;
    uintptr_t highestUserVa = 0x00007fff'ffff0000;
    arena->VirtualAddressSpace.UserSpace.LowestAddress = lowestUserVa;
    arena->VirtualAddressSpace.UserSpace.HighestAddress = highestUserVa;
    arena->VirtualAddressSpace.UserSpace.Size =
        (highestUserVa - lowestUserVa) - 1;

    uintptr_t lowestSystemVa = 0xffff8000'00000000;
    uintptr_t highestSystemVa = 0xffffffff'ffff0000;
    arena->VirtualAddressSpace.SystemSpace.LowestAddress = lowestSystemVa;
    arena->VirtualAddressSpace.SystemSpace.HighestAddress = highestSystemVa;
    arena->VirtualAddressSpace.SystemSpace.Size =
        (highestSystemVa - lowestSystemVa) - 1;

    // Initialize the doubly linked list that will maintain
    // our allocated memory regions
    //
    InitializeDListHeader(&(arena->AllocatedMemoryBlocks));

    return S_OK;
}

/*
/**
 * @brief Setup syscalls
 *
 * @param Partition The VM partition
 * @param VirtualAddress The guest virtual address to be translated
 * @param PhysicalAddress The guest physical address backing the guest virtual
address
 * @param TranslationResult The translation result
 * @return A result code
 #1#
HRESULT WhSiSetupSyscalls( whpx_state* Partition, WHSE_REGISTERS Registers ) {
        if ( Partition == nullptr )
                return HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );

        if ( Registers == nullptr )
                return HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );

        uintptr_t syscallTrapHva = 0;
        auto hresult = WhSiSuggestVirtualAddress( Partition, PAGE_SIZE,
&syscallTrapHva, WHSE_PROCESSOR_MODE::KernelMode ); if ( FAILED( hresult ) )
                return hresult;

        WHSE_ALLOCATION_NODE node {
                .BlockType = MEMORY_BLOCK_TYPE::MemoryBlockVirtual,
                .HostVirtualAddress = 0,
                .GuestPhysicalAddress = 0,
                .GuestVirtualAddress = syscallTrapHva,
                .Size = PAGE_SIZE
        };

        hresult = WhSeInsertAllocationTrackingNode( Partition, node );
        if ( FAILED( hresult ) )
                return hresult;

        auto vp = &Partition->VirtualProcessor;

        vp->SyscallData.Eip = 0; // Must be ZERO
        vp->SyscallData.LongModeRip = syscallTrapHva;
        vp->SyscallData.CompModeRip = syscallTrapHva + sizeof( uintptr_t );

        Registers[ Star ].Reg64 =
                // base selector for SYSRET CS / SS : bits 63:48
                //
                ( static_cast< uint64_t >( 0x0018 ) /*R3 CS Selector#1# << 48 )
                // base selector for SYSCALL CS / SS : bits 47:32
                //
                | ( static_cast< uint64_t >( 0x0008 ) /*R0 CS Selector#1# << 32
)
                // target EIP : bits 31:0
                // This field is reserved in Long Mode
                //
                | vp->SyscallData.Eip;
        Registers[ Lstar ].Reg64 = vp->SyscallData.LongModeRip;
        Registers[ Cstar ].Reg64 = vp->SyscallData.CompModeRip;
        //Registers[ Sfmask ].Reg64 = 0;

        return S_OK;
}
*/
