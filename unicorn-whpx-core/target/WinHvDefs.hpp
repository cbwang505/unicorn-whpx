#ifndef WINHVDEFS_HPP
#define WINHVDEFS_HPP


#include <windows.h>
#include <winhvplatform.h>

#include <stdint.h>

#include "whpx-internal.h"

#include "DoubleLinkedList.hpp"

#ifdef __cplusplus
extern "C" {
#endif
/** @file
 * @brief This file expose the structure used in the library
 *
 */

typedef WHV_MAP_GPA_RANGE_FLAGS WHSE_MEMORY_ACCESS_FLAGS;

typedef WHV_REGISTER_NAME WHSE_REGISTER_NAME;
typedef WHV_REGISTER_VALUE WHSE_REGISTER_VALUE;

typedef WHV_RUN_VP_EXIT_CONTEXT WHSE_VP_EXIT_CONTEXT;
typedef WHV_RUN_VP_EXIT_REASON WHSE_VP_EXIT_REASON;

/**
 * @brief Enumeration describing the processor mode
 */
typedef enum WHSE_PROCESSOR_MODE{
	None,
	KernelMode,
	UserMode,

	NumberOfModes
} WHSE_PROCESSOR_MODE;

typedef WHV_PROCESSOR_VENDOR WHSE_PROCESSOR_VENDOR;





static size_t NUMBER_OF_GDT_DESCRIPTORS = 5;

#define X64_TASK_STATE_SEGMENT_NUMBER_OF_ISTS 7
#define X64_TASK_STATE_SEGMENT_NUMBER_OF_SPS 3

#pragma pack( push, 1 )
struct _X64_TASK_STATE_SEGMENT {
	uint32_t Reserved00;

	// The Stack pointers used to load the stack on a privilege level change
	// (from a lower privileged ring to a higher one)
	//
	union {
		struct {
			uint64_t Rsp0;
			uint64_t Rsp1;
			uint64_t Rsp2;
		};
		uint64_t Rsp[ X64_TASK_STATE_SEGMENT_NUMBER_OF_SPS ];
	};

	uint32_t Reserved1C;
	uint32_t Reserved20;

	// Interrupt Stack Table
	// The Stack Pointers that are used to load the stack when an entry in the
	// Interrupt Stack Table has an IST value other than 0
	//
	union {
		struct {
			uint64_t Ist1;
			uint64_t Ist2;
			uint64_t Ist3;
			uint64_t Ist4;
			uint64_t Ist5;
			uint64_t Ist6;
			uint64_t Ist7;
		};
		uint64_t Ist[ X64_TASK_STATE_SEGMENT_NUMBER_OF_ISTS ];
	};

	uint32_t Reserved5C;
	uint32_t Reserved60;
	uint16_t Reserved64;

	// I/O Map base Address Field
	// It contains a 16-bit offset from the base of the TSS to the
	// I/O Permission Bit Map
	//
	uint16_t Iopb;
};
#pragma pack( pop )

//static_assert( sizeof( _X64_TASK_STATE_SEGMENT ) == 0x68 );

typedef struct _X64_TASK_STATE_SEGMENT X64_TASK_STATE_SEGMENT;
typedef struct _X64_TASK_STATE_SEGMENT* PX64_TASK_STATE_SEGMENT;

#define X64_TASK_STATE_SEGMENT_IOPB_NONE 0

 uint16_t TssComputeIopbOffset(uint16_t offset);


typedef struct _WHSE_SYSCALL_DATA WHSE_SYSCALL_DATA;
typedef struct _WHSE_SYSCALL_DATA* PWHSE_SYSCALL_DATA;

/**
 * @brief A structure representing a virtual processor
 *
 * This structure represent a virtual processor, its index (number),
 * the exit context upon a virtual processor exit and its registers state
 */
typedef struct _WHSE_VIRTUAL_PROCESSOR {
	uint32_t Index;
	WHSE_PROCESSOR_MODE Mode;
	WHSE_PROCESSOR_VENDOR Vendor;
	PX64_TASK_STATE_SEGMENT Tss;
	LPVOID Gdt;	
	WHSE_VP_EXIT_CONTEXT ExitContext;	
} WHSE_VIRTUAL_PROCESSOR, * PWHSE_VIRTUAL_PROCESSOR;

enum _MEMORY_BLOCK_TYPE {
	MemoryBlockPhysical,
	MemoryBlockVirtual,
	MemoryBlockPte,

	NumberOfMemoryBlockType
};

typedef enum _MEMORY_BLOCK_TYPE MEMORY_BLOCK_TYPE;


/**
 * @brief A structure to represent the boundaries of address space
 */
struct _ADDRESS_SPACE {
	uintptr_t LowestAddress;
	uintptr_t HighestAddress;
	size_t Size;
};

typedef struct _ADDRESS_SPACE ADDRESS_SPACE;
typedef struct _ADDRESS_SPACE* PADDRESS_SPACE;

/**
 * @brief A structure to represent the boundaries of virtual address space
 */
struct _VIRTUAL_ADDRESS_SPACE {
	ADDRESS_SPACE UserSpace;
	ADDRESS_SPACE SystemSpace;
};

typedef struct _VIRTUAL_ADDRESS_SPACE VIRTUAL_ADDRESS_SPACE;
typedef struct _VIRTUAL_ADDRESS_SPACE* PVIRTUAL_ADDRESS_SPACE;

/**
 * @brief A structure maintaining the necessary data to manage memory allocation
 */
struct _MEMORY_ARENA {
	ADDRESS_SPACE PhysicalAddressSpace;
	VIRTUAL_ADDRESS_SPACE VirtualAddressSpace;
	DLIST_HEADER AllocatedMemoryBlocks;
};

typedef struct _MEMORY_ARENA MEMORY_ARENA;
typedef struct _MEMORY_ARENA* PMEMORY_ARENA;

/**
 * @brief A structure to store the memory layout
 *
 * The structure holds the physical memory and virtual memory boundaries.
 * The structure holds a list of host memory allocations backing the physical guest memory.
 * Paging directories guest physical address and host address is available throught <Pml4PhysicalAddress>
 * and <Pml4HostVa> properties.
 */
typedef struct _WHSE_MEMORY_LAYOUT_DESC {
	MEMORY_ARENA MemoryArena;
	uintptr_t Pml4PhysicalAddress;
	uintptr_t Pml4HostVa;
	uintptr_t InterruptDescriptorTableVirtualAddress;
} WHSE_MEMORY_LAYOUT_DESC, * PWHSE_MEMORY_LAYOUT_DESC;

typedef WHV_PARTITION_HANDLE WHSE_PARTITION_HANDLE;

/**
 * @brief Enumeration to represent the virtual processor exits callbacks
 */
typedef enum _WHSE_EXIT_CALLBACK_SLOT{
	// Standard exits caused by operations of the virtual processor
	//
	MemoryAccess,
	IoPortAccess,
	UnrecoverableException,
	InvalidVpRegisterValue,
	UnsupportedFeature,
	InterruptWindow,
	Halt,
	ApicEoi,

	// Additional exits that can be configured through partition properties
	//
	MsrAccess,
	Cpuid,
	Exception,
	Rdtsc,

	// Exits caused by the host
	//
	UserCanceled,

	NumberOfCallbacks
}WHSE_EXIT_CALLBACK_SLOT;

#define WHSECALLBACKAPI *
#define WHSE_CALLBACK_RETURNTYPE bool

typedef void * WHSE_CALLBACK;

#pragma pack(push, 1)
typedef struct _whpx_state {
    uint64_t mem_quota;
    WHV_PARTITION_HANDLE partition;
    int cpu_index;
    uint64_t exception_exit_bitmap;
    int32_t running_cpus;
    struct whpx_breakpoints breakpoints;
    bool step_pending;
    bool kernel_irqchip_allowed;
    bool kernel_irqchip_required;
    bool apic_in_platform;
    WHSE_MEMORY_LAYOUT_DESC MemoryLayout;
    WHSE_VIRTUAL_PROCESSOR VirtualProcessor;
}whpx_state, *whpx_state_ptr;
#pragma pack(pop)

extern  whpx_state whpx_global;


void DumpRegs();
    // Initialize paging and other stuff for the partition
//
HRESULT WhSeInitializeMemoryLayout(whpx_state *Partition);

HRESULT WhSeInitializeAllocationTracker(whpx_state *Partition);

HRESULT whpx_get_reg_value(const WHV_REGISTER_NAME RegisterName,
                           WHV_REGISTER_VALUE *RegisterValues);

HRESULT whpx_get_reg(const WHV_REGISTER_NAME RegisterName, uint64_t *regval);

 HRESULT whpx_set_reg_value(const WHV_REGISTER_NAME RegisterName,
                     const WHV_REGISTER_VALUE RegisterValues);
HRESULT whpx_set_reg(const WHV_REGISTER_NAME RegisterName, uint64_t regval);

HRESULT WhSeMapHostToGuestVirtualMemory(whpx_state *Partition, uintptr_t HostVa,
                                        uintptr_t *GuestVa, size_t Size,
                                        WHSE_MEMORY_ACCESS_FLAGS Flags);

int setuphv(WHV_PARTITION_HANDLE *partition);
HRESULT WhSeFindAllocationGvaByGpa(whpx_state *Partition, uintptr_t GuestPa,
                                   uintptr_t *GuestVa);
HRESULT  WhSeFindAllocationGpaByGva(whpx_state *Partition, uintptr_t GuestVa,
                               uintptr_t *GuestPa);
void dumpbuf(LPVOID buf,
                                                                size_t len);


#ifdef __cplusplus
}
#endif
#endif
