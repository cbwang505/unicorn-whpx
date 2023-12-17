#ifndef WINHVMEMORYALLOCATIONTRACKER_HPP
#define WINHVMEMORYALLOCATIONTRACKER_HPP

#include <windows.h>
#include "WinHvDefs.hpp"


/**
 * @brief A structure to represent a guest memory allocation
 *
 * This structure a guest memory allocation.
 * In case of physical memory allocation, the <GuestVirtualAddress> field is set
 * to null and the <GuestPhysicalAddress> field is set with the guest physical
 * memory address. In case of virtual memory allocation, the
 * <GuestVirtualAddress> field is set to the guest address space virtual address
 * and the <GuestPhysicalAddress> field is set with the guest physical memory
 * address backing this virtual address. In either case the <HostVirtualAddress>
 * is set to the host address space virtual address that is backing the
 * allocated guest physical address space. The <Size> field must be set to the
 * size that represent the allocated memory ranges (and must be non zero).
 */
typedef struct _WHSE_ALLOCATION_NODE : DLIST_ENTRY {
    // The type of block
    // A block type of MemoryBlockPhysical represent guest physical memory (a
    // Gpa backed by an Hva) A block type of MemoryBlockVirtual represent guest
    // virtual memory (a Gva backed by a Gpa backed by an Hva)
    //
    MEMORY_BLOCK_TYPE BlockType;

    // The Host Virtual Address (HVA) backing the Guest Physical Address (GPA)
    //
    uintptr_t HostVirtualAddress;

    // The Guest Physical Address (GPA)
    //
    uintptr_t GuestPhysicalAddress;

    // The Guest Virtual Address (GVA)
    //
    uintptr_t GuestVirtualAddress;

    // The size of the allocation
    //
    size_t Size;
} WHSE_ALLOCATION_NODE, *PWHSE_ALLOCATION_NODE;

// Initialize allocation tracker structures
//
//HRESULT  WhSeInitializeAllocationTracker( whpx_state* Partition );

// Free allocation tracker structures
//
HRESULT  WhSeFreeAllocationTracker( whpx_state* Partition );

typedef bool ( *WHSE_ALLOCATION_TRACKER_PREDICATE )( const WHSE_ALLOCATION_NODE* );

// Find the first allocation node matching the predicate
//
HRESULT  WhSeFindAllocationNode( whpx_state* Partition, WHSE_ALLOCATION_TRACKER_PREDICATE Predicate, WHSE_ALLOCATION_NODE** Node );

// Find the first allocation node matching the guest virtual address
//
HRESULT  WhSeFindAllocationNodeByGva( whpx_state* Partition, uintptr_t GuestVa, WHSE_ALLOCATION_NODE** Node );

// Find the first allocation node matching the guest physical address
//
HRESULT  WhSeFindAllocationNodeByGpa( whpx_state* Partition, uintptr_t GuestPa, WHSE_ALLOCATION_NODE** Node );

// Insert a tracking node
//
HRESULT  WhSeInsertAllocationTrackingNode( whpx_state* Partition, WHSE_ALLOCATION_NODE Node );

#endif // !WINHVMEMORYALLOCATIONTRACKER_HPP
