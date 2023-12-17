#ifndef WINHVMEMORYPRIVATE_HPP
#define WINHVMEMORYPRIVATE_HPP

#include <windows.h>

#include "WinHvDefs.hpp"
#include "WinHvMemoryInternal.hpp"

// Private api
//
HRESULT WhSpLookupHVAFromPFN( whpx_state* Partition, uintptr_t PageFrameNumber, uintptr_t* HostVa );

// Private api
//
HRESULT WhSpInsertPageTableEntry( whpx_state* Partition, PMMPTE_HARDWARE ParentLayer, uint16_t Index );

// Private api
//
HRESULT WhSpCreateGdtEntry( GDT_ENTRY* Entry, uintptr_t Base, ptrdiff_t Limit, uint8_t Access, uint8_t Flags );

// Private api
//
HRESULT WhSpCreateTssEntry( X64_TSS_ENTRY* TssSegmentDesc, uintptr_t Base, ptrdiff_t Limit, uint8_t Access, uint8_t Flags );

// Private api
//
HRESULT WhSpInitializeTss( whpx_state* Partition, PX64_TASK_STATE_SEGMENT Tss );

#endif // !WINHVMEMORYPRIVATE_HPP
