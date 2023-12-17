#ifndef WINHVMEMORY_HPP
#define WINHVMEMORY_HPP

#include <windows.h>
#include <winhvplatform.h>

#include "WinHvDefs.hpp"

#include <cstdint>

// Allocate memory in guest physical address space (backed by host memory)
//
HRESULT  WhSeAllocateGuestPhysicalMemory( whpx_state* Partition, uintptr_t* HostVa, uintptr_t* GuestPa, size_t Size, WHSE_MEMORY_ACCESS_FLAGS Flags );

// Map memory from host to guest physical address space (backed by host memory)
//
HRESULT  WhSeMapHostToGuestPhysicalMemory( whpx_state* Partition, uintptr_t HostVa, uintptr_t* GuestPa, size_t Size, WHSE_MEMORY_ACCESS_FLAGS Flags );

// Allocate memory in guest virtual address space (backed by host memory)
//
HRESULT  WhSeAllocateGuestVirtualMemory( whpx_state* Partition, uintptr_t* HostVa, uintptr_t* GuestVa, size_t Size, WHSE_MEMORY_ACCESS_FLAGS Flags );

// Map memory from host to guest virtual address space (backed by host memory)
//
//HRESULT  WhSeMapHostToGuestVirtualMemory( whpx_state* Partition, uintptr_t HostVa, uintptr_t* GuestVa, size_t Size, WHSE_MEMORY_ACCESS_FLAGS Flags );

// Free memory in guest physical address space
//
HRESULT  WhSeFreeGuestPhysicalMemory( whpx_state* Partition, uintptr_t HostVa, uintptr_t GuestPa, size_t Size );

// Free memory in guest virtual address space
//
HRESULT  WhSeFreeGuestVirtualMemory( whpx_state* Partition, uintptr_t HostVa, uintptr_t GuestVa, size_t Size );

// Initialize paging and other stuff for the partition
//
//HRESULT  WhSeInitializeMemoryLayout( whpx_state* Partition );

// Translate guest virtual address to guest physical address
//
HRESULT  WhSeTranslateGvaToGpa( whpx_state* Partition, uintptr_t VirtualAddress, uintptr_t* PhysicalAddress, WHV_TRANSLATE_GVA_RESULT* TranslationResult );

#endif // !WINHVMEMORY_HPP
