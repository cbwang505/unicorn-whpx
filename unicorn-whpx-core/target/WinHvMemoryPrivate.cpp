#include "WinHvMemoryPrivate.hpp"
#include "WinHvUtils.hpp"
#include "WinHvAllocationTracker.hpp"
#include "WinHvMemory.hpp"

/**
 * @brief Private api
 *
 * @param Partition The VM partition
 * @param ParentLayer
 * @param Index
 * @return A result code
 */
HRESULT WhSpInsertPageTableEntry( whpx_state* Partition, PMMPTE_HARDWARE ParentLayer, uint16_t Index ) {
	uintptr_t gpa = 0;
	uintptr_t hva = 0;

	auto hresult = WhSeAllocateGuestPhysicalMemory( Partition, &hva, &gpa, PAGE_SIZE, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite );
	if ( FAILED( hresult ) )
		return hresult;

	// Create a valid PTE
	//
	MMPTE_HARDWARE pte { };

	pte.AsUlonglong = 0;							// Ensure zeroed
	pte.Valid = 1;									// Intel's Present bit
	pte.Write = 1;									// Intel's Read/Write bit
	pte.Owner = 1;									// Intel's User/Supervisor bit, let's say it is a user accessible frame
	pte.PageFrameNumber = ( gpa / PAGE_SIZE );		// Physical address of PDP page

	ParentLayer[ Index ] = pte;

	return hresult;
}

/**
 * @brief Private api
 *
 * @param Partition The VM partition
 * @param PageFrameNumber
 * @param HostVa
 * @return A result code
 */
HRESULT WhSpLookupHVAFromPFN( whpx_state* Partition, uintptr_t PageFrameNumber, uintptr_t* HostVa ) {
	WHSE_ALLOCATION_NODE* node = nullptr;
	auto hresult = WhSeFindAllocationNodeByGpa( Partition, PageFrameNumber * PAGE_SIZE, &node );
	if ( FAILED( hresult ) )
		return hresult;

	*HostVa = node->HostVirtualAddress;

	return hresult;
}

/**
 * @brief Private api
 *
 * @param Entry The returned GDT entry
 * @param Base
 * @param Limit
 * @param Access
 * @param Flags
 * @return A result code
 */
HRESULT WhSpCreateGdtEntry( GDT_ENTRY* Entry, uintptr_t Base, ptrdiff_t Limit, uint8_t Access, uint8_t Flags ) {
	if ( Entry == nullptr )
		return HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );

	Entry->LimitLow = static_cast< uint16_t >( Limit & 0xffff );
	Entry->BaseLow = static_cast< uint16_t >( Base & 0xffff );
	Entry->BaseMid = static_cast< uint8_t >( ( Base >> 16 ) & 0xff );
	Entry->Access = Access;
	Entry->LimitHigh = static_cast< uint8_t >( ( Limit >> 16 ) & 0xf );
	Entry->Flags = static_cast< uint8_t >( Flags & 0xf );
	Entry->BaseHigh = static_cast< uint8_t >( ( Base >> 24 ) & 0xff );

	return S_OK;
}

/**
 * @brief Private api
 *
 * @param TssSegmentDesc The returned TSS entry
 * @param Base
 * @param Limit
 * @param Access
 * @param Flags
 * @return A result code
 */
HRESULT WhSpCreateTssEntry( X64_TSS_ENTRY* TssSegmentDesc, uintptr_t Base, ptrdiff_t Limit, uint8_t Access, uint8_t Flags ) {
	if ( TssSegmentDesc == nullptr )
		return HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );

	auto hresult = WhSpCreateGdtEntry( &( TssSegmentDesc->GdtEntry ), Base, Limit, Access, Flags );
	if ( FAILED( hresult ) )
		return hresult;

	TssSegmentDesc->BaseHigh = ( Base >> 32 ) & UINT32_MAX;

	return S_OK;
}
uint16_t TssComputeIopbOffset(uint16_t offset)
{
    return offset != X64_TASK_STATE_SEGMENT_IOPB_NONE
               ? offset
               : sizeof(X64_TASK_STATE_SEGMENT);
}
/**
 * @brief Private api
 *
 * @param Tss Pointer to the Task State Segment
 * @return A result code
 */
HRESULT WhSpInitializeTss( whpx_state* Partition, PX64_TASK_STATE_SEGMENT Tss ) {
	if ( Tss == nullptr )
		return HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );

	uintptr_t stackHva = 0;
	constexpr size_t stackSize = 1MiB;
	//uintptr_t stackGva = 0xffffb000'00000000;
	uintptr_t stackGva = 0;
	auto hresult = WhSeAllocateGuestVirtualMemory( Partition, &stackHva, &stackGva, stackSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite );
	if ( FAILED( hresult ) )
		return hresult;

	Tss->Rsp0 = stackGva;
	
	Tss->Iopb = TssComputeIopbOffset( X64_TASK_STATE_SEGMENT_IOPB_NONE );

	return S_OK;
}
