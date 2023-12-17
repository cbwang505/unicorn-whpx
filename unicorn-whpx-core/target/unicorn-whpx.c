/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "uc_priv.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include <unicorn/x86.h> /* needed for uc_x86_mmr */
#include "unicorn.h"

//#include "whpx-internal.h"
#include "WinHvDefs.hpp"

#define RT_BIT_64(bit) (UINT64_C(1) << (bit))

#define RT_BIT_64_FIND(val, bit) (val & (UINT64_C(1) << (bit)))

#define RT_BIT_64_SLOT(bit) (UINT64_C(1) << (bit << 1))

#define RT_BIT_64_FIND_SLOT(val, bit) (val & (UINT64_C(1) << (bit << 1)))

#define TARGET_X86_64
/* list iterators for lists of tagged pointers in TranslationBlock */
#define TB_FOR_EACH_TAGGED(head, tb, n, field)                                 \
    for (n = (head)&1, tb = (TranslationBlock *)((head) & ~1); tb;             \
         tb = (TranslationBlock *)tb->field[n], n = (uintptr_t)tb & 1,         \
        tb = (TranslationBlock *)((uintptr_t)tb & ~1))

#define PAGE_FOR_EACH_TB(pagedesc, tb, n)                                      \
    TB_FOR_EACH_TAGGED((pagedesc)->first_tb, tb, n, page_next)

#define TB_FOR_EACH_JMP(head_tb, tb, n)                                        \
    TB_FOR_EACH_TAGGED((head_tb)->jmp_list_head, tb, n, jmp_list_next)

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
#define L1_MAP_ADDR_SPACE_BITS HOST_LONG_BITS
#else
#define L1_MAP_ADDR_SPACE_BITS TARGET_PHYS_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/* Make sure all possible CPU event bits fit in tb->trace_vcpu_dstate */
QEMU_BUILD_BUG_ON(CPU_TRACE_DSTATE_MAX_EVENTS >
                  sizeof_field(TranslationBlock, trace_vcpu_dstate) *
                      BITS_PER_BYTE);

/* The bottom level has pointers to PageDesc, and is indexed by
 * anything from 4 to (V_L2_BITS + 3) bits, depending on target page size.
 */
#define V_L1_MIN_BITS 4
#define V_L1_MAX_BITS (V_L2_BITS + 3)
#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

/*
 * Linux uses int3 (0xCC) during startup (see int3_selftest()) and for
 *
 * debugging user-mode applications. Since the WHPX API does not offer
 * an
 * easy way to pass the intercepted exception back to the guest, we
 * resort to
 * using INT1 instead, and let the guest always handle INT3.
 */
const uint8_t whpx_breakpoint_instruction = 0xF1;

typedef struct PropValue {
    const char *prop, *value;
} PropValue;

typedef struct X86CPUVersionDefinition {
    X86CPUVersion version;
    const char *alias;
    const char *note;
    PropValue *props;
} X86CPUVersionDefinition;

/* Base definition for a CPU model */
typedef struct X86CPUDefinition {
    const char *name;
    uint32_t level;
    uint32_t xlevel;
    /* vendor is zero-terminated, 12 character ASCII string */
    char vendor[CPUID_VENDOR_SZ + 1];
    int family;
    int model;
    int stepping;
    FeatureWordArray features;
    const char *model_id;
    CPUCaches *cache_info;

    /* Use AMD EPYC encoding for apic id */
    bool use_epyc_apic_id_encoding;

    /*
     * Definitions for alternative versions of CPU model.
     * List is terminated by item with version == 0.
     * If NULL, version 1 will be registered automatically.
     */
    const X86CPUVersionDefinition *versions;
} X86CPUDefinition;

/* Reference to a specific CPU model version */
struct X86CPUModel {
    /* Base CPU definition */
    X86CPUDefinition *cpudef;
    /* CPU model version */
    X86CPUVersion version;
    const char *note;
    /*
     * If true, this is an alias CPU model.
     * This matters only for "-cpu help" and query-cpu-definitions
     */
    bool is_alias;
};

void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f)
{
    CPU_LDoubleU temp;

    temp.d = f;
    *pmant = temp.l.lower;
    *pexp = temp.l.upper;
}

floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper)
{
    CPU_LDoubleU temp;

    temp.l.upper = upper;
    temp.l.lower = mant;
    return temp.d;
}

static const WHV_REGISTER_NAME whpx_register_names[] = {

    /* X64 General purpose registers */
    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRbx,
    WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterRsi, WHvX64RegisterRdi,
    WHvX64RegisterR8, WHvX64RegisterR9, WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
    WHvX64RegisterRip, WHvX64RegisterRflags,

    /* X64 Segment registers */
    WHvX64RegisterEs, WHvX64RegisterCs, WHvX64RegisterSs, WHvX64RegisterDs,
    WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterLdtr, WHvX64RegisterTr,

    /* X64 Table registers */
    WHvX64RegisterIdtr, WHvX64RegisterGdtr,

    /* X64 Control Registers */
    WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCr8,

    /* X64 Debug Registers */
    /*
     * WHvX64RegisterDr0,
     * WHvX64RegisterDr1,
     *
       WHvX64RegisterDr2,
     * WHvX64RegisterDr3,
     * WHvX64RegisterDr6,

       * WHvX64RegisterDr7,
     */

    /* X64 Floating Point and Vector Registers */
    WHvX64RegisterXmm0, WHvX64RegisterXmm1, WHvX64RegisterXmm2,
    WHvX64RegisterXmm3, WHvX64RegisterXmm4, WHvX64RegisterXmm5,
    WHvX64RegisterXmm6, WHvX64RegisterXmm7, WHvX64RegisterXmm8,
    WHvX64RegisterXmm9, WHvX64RegisterXmm10, WHvX64RegisterXmm11,
    WHvX64RegisterXmm12, WHvX64RegisterXmm13, WHvX64RegisterXmm14,
    WHvX64RegisterXmm15, WHvX64RegisterFpMmx0, WHvX64RegisterFpMmx1,
    WHvX64RegisterFpMmx2, WHvX64RegisterFpMmx3, WHvX64RegisterFpMmx4,
    WHvX64RegisterFpMmx5, WHvX64RegisterFpMmx6, WHvX64RegisterFpMmx7,
    WHvX64RegisterFpControlStatus, WHvX64RegisterXmmControlStatus,

    /* X64 MSRs */
    WHvX64RegisterEfer,
#ifdef TARGET_X86_64
    WHvX64RegisterKernelGsBase,
#endif
    WHvX64RegisterApicBase,
    /* WHvX64RegisterPat, */
    WHvX64RegisterSysenterCs, WHvX64RegisterSysenterEip,
    WHvX64RegisterSysenterEsp, WHvX64RegisterStar,
#ifdef TARGET_X86_64
    WHvX64RegisterLstar, WHvX64RegisterCstar, WHvX64RegisterSfmask,
#endif

    /* Interrupt / Event Registers */
    /*
     * WHvRegisterPendingInterruption,
     * WHvRegisterInterruptState,

       * WHvRegisterPendingEvent0,
     * WHvRegisterPendingEvent1
     *
       WHvX64RegisterDeliverabilityNotifications,
     */
};
typedef struct whpx_register_set {
    WHV_REGISTER_VALUE values[RTL_NUMBER_OF(whpx_register_names)];
} whpx_register_set;

whpx_state whpx_global;

bool whpx_apic_in_platform = false;
static WHV_PROCESSOR_XSAVE_FEATURES whpx_xsave_cap;
#define FPST(n) (env->fpregs[(env->fpstt + (n)) & 7].d)

#define X86_NON_CS_FLAGS (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK)
void filter_breakpoint_original_instruction(uintptr_t gva, uint8_t *buf,
                                            size_t len);

int cpu_memory_rw_whpx(CPUState *cpu, target_ulong address, void *bytes,
                       target_ulong len, bool is_write)
{
    int result = MEMTX_OK;
    if (is_write) {
        result = cpu->uc->write_mem(&cpu->uc->address_space_memory, address,
                                    bytes, len);
    } else {
        result = cpu->uc->read_mem(&cpu->uc->address_space_memory, address,
                                   bytes, len);
    }

    return result == 0;
}
void tb_flush(CPUState *cpu) {}
bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc, bool will_exit) {}
void tlb_set_page_with_attrs(CPUState *cpu, target_ulong vaddr, hwaddr paddr,
                             MemTxAttrs attrs, int prot, int mmu_idx,
                             target_ulong size)
{
}
void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
}
static void inline store_helper(CPUArchState *env, target_ulong addr,
                                uint64_t val, TCGMemOpIdx oi, uintptr_t retaddr,
                                MemOp op)
{
}
void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val,
                        TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_UB);
}

void helper_le_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEUW);
}

void helper_be_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEUW);
}

void helper_le_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEUL);
}

void helper_be_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEUL);
}

void helper_le_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEQ);
}

void helper_be_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEQ);
}

/*
 * Store Helpers for cpu_ldst.h
 */

static void inline cpu_store_helper(CPUArchState *env, target_ulong addr,
                                    uint64_t val, int mmu_idx,
                                    uintptr_t retaddr, MemOp op) // qq
{
}

void cpu_stb_mmuidx_ra(CPUArchState *env, target_ulong addr, uint32_t val,
                       int mmu_idx, uintptr_t retaddr)
{
    cpu_store_helper(env, addr, val, mmu_idx, retaddr, MO_UB);
}

void cpu_stw_mmuidx_ra(CPUArchState *env, target_ulong addr, uint32_t val,
                       int mmu_idx, uintptr_t retaddr)
{
    cpu_store_helper(env, addr, val, mmu_idx, retaddr, MO_TEUW);
}

void cpu_stl_mmuidx_ra(CPUArchState *env, target_ulong addr, uint32_t val,
                       int mmu_idx, uintptr_t retaddr)
{
    cpu_store_helper(env, addr, val, mmu_idx, retaddr, MO_TEUL);
}

void cpu_stq_mmuidx_ra(CPUArchState *env, target_ulong addr, uint64_t val,
                       int mmu_idx, uintptr_t retaddr)
{
    cpu_store_helper(env, addr, val, mmu_idx, retaddr, MO_TEQ);
}

void cpu_stb_data_ra(CPUArchState *env, target_ulong ptr, uint32_t val,
                     uintptr_t retaddr)
{
    cpu_stb_mmuidx_ra(env, ptr, val, cpu_mmu_index(env, false), retaddr);
}

void cpu_stw_data_ra(CPUArchState *env, target_ulong ptr, uint32_t val,
                     uintptr_t retaddr)
{
    cpu_stw_mmuidx_ra(env, ptr, val, cpu_mmu_index(env, false), retaddr);
}

void cpu_stl_data_ra(CPUArchState *env, target_ulong ptr, uint32_t val,
                     uintptr_t retaddr)
{
    cpu_stl_mmuidx_ra(env, ptr, val, cpu_mmu_index(env, false), retaddr);
}

void cpu_stq_data_ra(CPUArchState *env, target_ulong ptr, uint64_t val,
                     uintptr_t retaddr)
{
    cpu_stq_mmuidx_ra(env, ptr, val, cpu_mmu_index(env, false), retaddr);
}

void cpu_stb_data(CPUArchState *env, target_ulong ptr, uint32_t val)
{
    cpu_stb_data_ra(env, ptr, val, 0);
}

void cpu_stw_data(CPUArchState *env, target_ulong ptr, uint32_t val)
{
    cpu_stw_data_ra(env, ptr, val, 0);
}

void cpu_stl_data(CPUArchState *env, target_ulong ptr, uint32_t val)
{
    cpu_stl_data_ra(env, ptr, val, 0);
}

void cpu_stq_data(CPUArchState *env, target_ulong ptr, uint64_t val)
{
    cpu_stq_data_ra(env, ptr, val, 0);
}

static uint64_t inline load_helper(CPUArchState *env, uint64_t addr,
                                   TCGMemOpIdx oi, uintptr_t retaddr, MemOp op,
                                   bool code_read, void *full_load)
{
}
static inline uint64_t cpu_load_helper(CPUArchState *env, uint64_t addr,
                                       int mmu_idx, uintptr_t retaddr, MemOp op,
                                       void *full_load) // qq
{
}

/*
 * For the benefit of TCG generated code, we want to avoid the
 * complication of ABI-specific return type promotion and always
 * return a value extended to the register size of the host. This is
 * tcg_target_long, except in the case of a 32-bit host and 64-bit
 * data, and for that we always have uint64_t.
 *
 * We don't bother with this widened value for SOFTMMU_CODE_ACCESS.
 */

static uint64_t full_ldub_mmu(CPUArchState *env, target_ulong addr,
                              TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_UB, false, full_ldub_mmu);
}

tcg_target_ulong helper_ret_ldub_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_ldub_mmu(env, addr, oi, retaddr);
}

static uint64_t full_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUW, false,
                       full_le_lduw_mmu);
}

tcg_target_ulong helper_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_lduw_mmu(env, addr, oi, retaddr);
}

static uint64_t full_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUW, false,
                       full_be_lduw_mmu);
}

tcg_target_ulong helper_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_lduw_mmu(env, addr, oi, retaddr);
}

static uint64_t full_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUL, false,
                       full_le_ldul_mmu);
}

tcg_target_ulong helper_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_ldul_mmu(env, addr, oi, retaddr);
}

static uint64_t full_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUL, false,
                       full_be_ldul_mmu);
}

tcg_target_ulong helper_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_ldul_mmu(env, addr, oi, retaddr);
}

uint64_t helper_le_ldq_mmu(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEQ, false,
                       helper_le_ldq_mmu);
}

uint64_t helper_be_ldq_mmu(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEQ, false,
                       helper_be_ldq_mmu);
}

/*
 * Provide signed versions of the load routines as well.  We can of course
 * avoid this for 64-bit data, or for 32-bit data on 32-bit host.
 */

tcg_target_ulong helper_ret_ldsb_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int8_t)helper_ret_ldub_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_le_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_be_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_le_ldul_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_be_ldul_mmu(env, addr, oi, retaddr);
}

uint32_t cpu_ldub_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                            uintptr_t ra)
{
    return cpu_load_helper(env, addr, mmu_idx, ra, MO_UB, full_ldub_mmu);
}

int cpu_ldsb_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                       uintptr_t ra)
{
    return (int8_t)cpu_load_helper(env, addr, mmu_idx, ra, MO_SB,
                                   full_ldub_mmu);
}

uint32_t cpu_lduw_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                            uintptr_t ra)
{
    return cpu_load_helper(env, addr, mmu_idx, ra, MO_TEUW,
                           MO_TE == MO_LE ? full_le_lduw_mmu
                                          : full_be_lduw_mmu);
}

int cpu_ldsw_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                       uintptr_t ra)
{
    return (int16_t)cpu_load_helper(env, addr, mmu_idx, ra, MO_TESW,
                                    MO_TE == MO_LE ? full_le_lduw_mmu
                                                   : full_be_lduw_mmu);
}

uint32_t cpu_ldl_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                           uintptr_t ra)
{
    return cpu_load_helper(env, addr, mmu_idx, ra, MO_TEUL,
                           MO_TE == MO_LE ? full_le_ldul_mmu
                                          : full_be_ldul_mmu);
}

uint64_t cpu_ldq_mmuidx_ra(CPUArchState *env, uint64_t addr, int mmu_idx,
                           uintptr_t ra)
{
    return cpu_load_helper(env, addr, mmu_idx, ra, MO_TEQ,
                           MO_TE == MO_LE ? helper_le_ldq_mmu
                                          : helper_be_ldq_mmu);
}

uint32_t cpu_ldub_data_ra(CPUArchState *env, target_ulong ptr,
                          uintptr_t retaddr)
{
    return cpu_ldub_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

int cpu_ldsb_data_ra(CPUArchState *env, target_ulong ptr, uintptr_t retaddr)
{
    return cpu_ldsb_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

uint32_t cpu_lduw_data_ra(CPUArchState *env, target_ulong ptr,
                          uintptr_t retaddr)
{
    return cpu_lduw_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

int cpu_ldsw_data_ra(CPUArchState *env, target_ulong ptr, uintptr_t retaddr)
{
    return cpu_ldsw_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

uint32_t cpu_ldl_data_ra(CPUArchState *env, target_ulong ptr, uintptr_t retaddr)
{
    return cpu_ldl_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

uint64_t cpu_ldq_data_ra(CPUArchState *env, target_ulong ptr, uintptr_t retaddr)
{
    return cpu_ldq_mmuidx_ra(env, ptr, cpu_mmu_index(env, false), retaddr);
}

uint32_t cpu_ldub_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_ldub_data_ra(env, ptr, 0);
}

int cpu_ldsb_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_ldsb_data_ra(env, ptr, 0);
}

uint32_t cpu_lduw_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_lduw_data_ra(env, ptr, 0);
}

int cpu_ldsw_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_ldsw_data_ra(env, ptr, 0);
}

uint32_t cpu_ldl_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_ldl_data_ra(env, ptr, 0);
}

uint64_t cpu_ldq_data(CPUArchState *env, target_ulong ptr)
{
    return cpu_ldq_data_ra(env, ptr, 0);
}

static void load_seg_16_helper(CPUX86State *env, int seg, uint32_t selector)
{
    cpu_x86_load_seg_cache(env, seg, selector, (selector << 4), 0xffff,
                           X86_NON_CS_FLAGS);
}

static bool whpx_has_xsave(void)
{
    return whpx_xsave_cap.XsaveSupport;
}

void filter_breakpoint_original_instruction(uintptr_t gva, uint8_t *buf,
                                            size_t len)
{
    whpx_state *whpx = &whpx_global;
    struct whpx_breakpoint_collection *breakpoints =
        whpx->breakpoints.breakpoints;
    if (!breakpoints) {
        return;
    }
    for (int i = 0; i < breakpoints->used; i++) {
        uintptr_t bpaddr = breakpoints->data[i].address;
        if (bpaddr >= gva && bpaddr < gva + len) {
            size_t diff = bpaddr - gva;
            if (*(buf + diff) == whpx_breakpoint_instruction) {
                *(buf + diff) = breakpoints->data[i].original_instruction;
                // break;
            }
        }
    }
}

static uint64_t
whpx_find_hardware_breakpoint(struct whpx_breakpoint_collection *breakpoints,
                              uint8_t idx)
{
    for (int i = 0; i < breakpoints->used; i++) {
        if (breakpoints->data[i].bptype & 0xff0000 &&
            breakpoints->data[i].original_instruction == idx) {
            return breakpoints->data[i].address;
        }
    }
    return 0;
}
uint64_t whpx_check_hardware_breakpoint()
{
    whpx_state *whpx = &whpx_global;
    uint64_t dr6val;
    whpx_get_reg(WHvX64RegisterDr6, &dr6val);
    if (dr6val & 0xff) {
        for (uint8_t i = 0; i < 4; i++) {
            if (RT_BIT_64_FIND(dr6val, i)) {
                return whpx_find_hardware_breakpoint(
                    whpx->breakpoints.breakpoints, i);
            }
        }
        return 0;
    }
    return 0;
}

static void
whpx_apply_hardware_breakpoint(struct whpx_breakpoint_collection *breakpoints,
                               CPUState *cpu, uintptr_t addrskip)
{
    bool fixallpass = true;
    uint64_t dr7val;
    uint64_t dr7valrw = 0;
    ;
    
    uint8_t hwbpslot = 0;
    whpx_get_reg(WHvX64RegisterDr7, &dr7val);
    //这里不需要考虑rip
    /*uintptr_t ripval = 0;
    whpx_get_reg(WHvX64RegisterRip, &ripval);*/
    for (int i = 0; i < breakpoints->used; i++) {
        struct whpx_breakpoint *breakpoint = &breakpoints->data[i];
        WhpxBreakpointState state = breakpoint->state;
        if (breakpoint->bptype & 0xff0000) {
            if (state == WHPX_BP_SET) {
                //如果已使用有slot
                if (RT_BIT_64_FIND_SLOT(dr7val,
                                        breakpoint->original_instruction)) {
                    //如果是单步执行回调开始取消
                    if (breakpoints->data[i].address == addrskip) {
                        hwbpslot &=
                            ~(RT_BIT_64(breakpoint->original_instruction));
                        dr7valrw &=
                            ~RT_BIT_64(breakpoint->original_instruction << 2);
                        dr7valrw &= ~RT_BIT_64(
                            (breakpoint->original_instruction << 2) + 1);
                        //如果是普通断点单步模式置位3,非单步模式2,硬件断点要另一种模式单步模式置位5,非单步模式4
                        if (cpu->singlestep_enabled == 1) {
                            cpu->singlestep_enabled = 5;
                        } else {
                            cpu->singlestep_enabled = 4;
                        }
                        cpu->halted = true;
                        //已经设置
                        cpu->mem_io_pc = addrskip;
                        fixallpass = false;
                        uint64_t drval = 0;
                        switch (breakpoint->original_instruction) {
                        case 0: {
                            whpx_set_reg(WHvX64RegisterDr0, drval);
                            break;
                        }
                        case 1: {
                            whpx_set_reg(WHvX64RegisterDr1, drval);
                            break;
                        }
                        case 2: {
                            whpx_set_reg(WHvX64RegisterDr2, drval);
                            break;
                        }
                        case 3: {
                            whpx_set_reg(WHvX64RegisterDr3, drval);
                            break;
                        }
                        default: {
                            break;
                        }
                        }
                    } else {
                        //对于其他硬件断点
                        hwbpslot |= RT_BIT_64(breakpoint->original_instruction);
                        if (breakpoint->bptype == UC_HOOK_HARDWARE_READ) {
                            dr7valrw |= RT_BIT_64(
                                breakpoint->original_instruction << 2);
                            dr7valrw |= RT_BIT_64(
                                (breakpoint->original_instruction << 2) + 1);
                        }
                        if (breakpoint->bptype == UC_HOOK_HARDWARE_WRITE) {
                            dr7valrw |= RT_BIT_64(
                                breakpoint->original_instruction << 2);
                        }
                        //dr已经设置过了不用再次设置
                    }
                    continue;
                } else if (breakpoints->data[i].address == addrskip) {
                    //恢复模式槽已经没有了,重新恢复硬件断点
                    breakpoint->state = WHPX_BP_SET_PENDING;
                }
            } else if (state == WHPX_BP_CLEAR_PENDING) {
                //如果待禁用状态
                uint8_t j = breakpoint->original_instruction;
                hwbpslot &= ~(RT_BIT_64(j));
                uint64_t drval = 0;
                switch (j) {
                case 0: {
                    whpx_set_reg(WHvX64RegisterDr0, drval);
                    break;
                }
                case 1: {
                    whpx_set_reg(WHvX64RegisterDr1, drval);
                    break;
                }
                case 2: {
                    whpx_set_reg(WHvX64RegisterDr2, drval);
                    break;
                }
                case 3: {
                    whpx_set_reg(WHvX64RegisterDr3, drval);
                    break;
                }
                default: {
                    break;
                }
                }
                dr7valrw &= ~RT_BIT_64(breakpoint->original_instruction << 2);
                dr7valrw &=
                    ~RT_BIT_64((breakpoint->original_instruction << 2) + 1);
                breakpoint->original_instruction = 0xff;
                breakpoint->address = 0;
                breakpoint->state = WHPX_BP_CLEARED;
            }
        }
    }
    //全部处理完之后才能处理待设置的
    for (int i = 0; i < breakpoints->used; i++) {
        struct whpx_breakpoint *breakpoint = &breakpoints->data[i];
        WhpxBreakpointState state = breakpoint->state;
        if (breakpoint->bptype & 0xff0000) {
            if (state == WHPX_BP_SET_PENDING) {
                bool fid = false;
                for (uint8_t j = 0; j < 4; j++) {
                    if (!RT_BIT_64_FIND_SLOT(dr7val, j)) {
                        fid = true;
                        breakpoint->original_instruction = j;
                        hwbpslot |= RT_BIT_64(breakpoint->original_instruction);

                        uint64_t drval = breakpoint->address;
                        switch (j) {
                        case 0: {
                            whpx_set_reg(WHvX64RegisterDr0, drval);
                            break;
                        }
                        case 1: {
                            whpx_set_reg(WHvX64RegisterDr1, drval);
                            break;
                        }
                        case 2: {
                            whpx_set_reg(WHvX64RegisterDr2, drval);
                            break;
                        }
                        case 3: {
                            whpx_set_reg(WHvX64RegisterDr3, drval);
                            break;
                        }
                        default: {
                            break;
                        }
                        }
                        break;
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
                if (!fid) {
                    printf("WHPX:reach max hardware breakpoint fatal error "
                           "exit\r\n");
                    exit(0);
                }
            }
        }
    }

    if (fixallpass) {
        //这种情况就是给硬件断点用的
        cpu->mem_io_pc = 0;
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
    printf("WHPX:whpx_apply_hardware_breakpoint hwbpslot=%016llx, "
           "dr7val=%016llx\r\n",
           hwbpslot, dr7val);
}

uint64_t whpx_hardware_breakpoint_config_single_step(CPUState *cpu,
                                                     uintptr_t addr)
{
    whpx_state *whpx = &whpx_global;

    whpx_apply_hardware_breakpoint(whpx->breakpoints.breakpoints, cpu, addr);
    return addr;
}

/*
 * Physically inserts/removes the breakpoints by reading and writing the
 *
 * physical memory, keeping a track of the failed attempts.
 *
 * Passing
 * resuming=true  will try to set all previously unset breakpoints.
 * Passing
 * resuming=false will remove all inserted ones.
 */
static void
whpx_apply_breakpoints(struct whpx_breakpoint_collection *breakpoints,
                       CPUState *cpu)
{
    uintptr_t ripval = 0;

    cpu->halted = false;
    int i, rc;
    if (!breakpoints) {
        return;
    }
    bool hashw = false;
    whpx_get_reg(WHvX64RegisterRip, &ripval);
    for (i = 0; i < breakpoints->used; i++) {
        /* Decide what to do right now based on the last known state. */
        WhpxBreakpointState state = breakpoints->data[i].state;
        int hooktype = breakpoints->data[i].bptype;
        switch (state) {
        case WHPX_BP_CLEARED:

            break;
        case WHPX_BP_SET_PENDING:

            break;
        case WHPX_BP_SET:

            break;
        case WHPX_BP_CLEAR_PENDING:

            break;
        }
        if (hooktype & 0xff0000) {
            hashw = true;
            continue;
        }
        if (state == WHPX_BP_SET_PENDING) {

            /* Remember the original instruction. */
            rc = cpu_memory_rw_whpx(cpu, breakpoints->data[i].address,
                                    &breakpoints->data[i].original_instruction,
                                    1, false);

            if (!rc) {
                /* Write the breakpoint instruction. */
                rc = cpu_memory_rw_whpx(cpu, breakpoints->data[i].address,
                                        (void *)&whpx_breakpoint_instruction, 1,
                                        true);
            }

            if (!rc) {
                state = WHPX_BP_SET;
            }
        } else if (state == WHPX_BP_SET) {
            //如果是set还是set,单步调试置回来,只有断点是当前rip时需要修复
            if (breakpoints->data[i].address == ripval) {
                //如果是单步模式置位3,非单步模式2
                if (cpu->singlestep_enabled == 1) {
                    cpu->singlestep_enabled = 3;
                } else {
                    cpu->singlestep_enabled = 2;
                }
                cpu->halted = true;
                cpu->mem_io_pc = ripval;
                rc = cpu_memory_rw_whpx(
                    cpu, breakpoints->data[i].address,
                    &breakpoints->data[i].original_instruction, 1, true);
            }

        }

        else if (state == WHPX_BP_CLEAR_PENDING) {
            /* Restore the original instruction. */
            rc = cpu_memory_rw_whpx(cpu, breakpoints->data[i].address,
                                    &breakpoints->data[i].original_instruction,
                                    1, true);

            if (!rc) {
                state = WHPX_BP_CLEARED;
            }
        }

        breakpoints->data[i].state = state;
    }
    if (hashw) {
        whpx_apply_hardware_breakpoint(breakpoints, cpu, cpu->mem_io_pc);
    } else {
        cpu->mem_io_pc = 0;
    }
}

/*
 * Controls whether we should intercept various exceptions on the guest,
 *
 * namely breakpoint/single-step events.
 *
 * The 'exceptions' argument accepts
 * a bitmask, e.g:
 * (1 << WHvX64ExceptionTypeDebugTrapOrFault) | (...)
 */
static HRESULT whpx_set_exception_exit_bitmap(UINT64 exceptions)
{
    whpx_state *whpx = &whpx_global;
    WHV_PARTITION_PROPERTY prop = {
        0,
    };
    HRESULT hr;

    if (exceptions == whpx->exception_exit_bitmap) {
        return S_OK;
    }

    prop.ExceptionExitBitmap = exceptions;

    hr = WHvSetPartitionProperty(whpx->partition,
                                 WHvPartitionPropertyCodeExceptionExitBitmap,
                                 &prop, sizeof(WHV_PARTITION_PROPERTY));

    if (SUCCEEDED(hr)) {
        whpx->exception_exit_bitmap = exceptions;
    }

    return hr;
}

/*
 * This function is called before/after stepping over a single instruction.

 * * It will update the CPU registers to arm/disarm the instruction stepping
 *
 * accordingly.
 */
static HRESULT
whpx_vcpu_configure_single_stepping(CPUState *cpu, bool set,
                                    uint64_t *exit_context_rflags)
{

    WHV_REGISTER_NAME reg_name;
    uintptr_t reg_value;
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    WHV_REGISTER_VALUE whpx_reg_value = {0};
    /*
     * If we are trying to step over a single instruction, we need to set
     * the
     * TF bit in rflags. Otherwise, clear it.
     */
    reg_name = WHvX64RegisterRflags;
    hr = whpx_get_reg(WHvX64RegisterRflags, &reg_value);

    if (FAILED(hr)) {
        printf("WHPX: Failed to get rflags, hr=%08lx", hr);
        return hr;
    }

    if (exit_context_rflags) {
        assert(*exit_context_rflags == reg_value);
    }

    if (set) {
        /* Raise WHvX64ExceptionTypeDebugTrapOrFault after each instruction
         */
        reg_value |= TF_MASK;
    } else {
        reg_value &= ~TF_MASK;
    }

    if (exit_context_rflags) {
        *exit_context_rflags = reg_value;
    }

    hr = whpx_set_reg(reg_name, reg_value);

    if (FAILED(hr)) {
        printf("WHPX: Failed to set rflags,"
               " hr=%08lx",
               hr);
        return hr;
    }

    reg_name = WHvRegisterInterruptState;
    whpx_reg_value.Reg64 = 0;

    /* Suspend delivery of hardware interrupts during single-stepping. */
    whpx_reg_value.InterruptState.InterruptShadow = set != 0;

    hr = whpx_set_reg_value(reg_name, whpx_reg_value);

    if (FAILED(hr)) {
        printf("WHPX: Failed to set InterruptState,"
               " hr=%08lx",
               hr);
        return hr;
    }

    if (!set) {
        /*
         * We have just finished stepping over a single instruction,

         * * and intercepted the INT1 generated by it.
         * We need to now
         * hide the INT1 from the guest,
         * as it would not be expecting
         * it.
         */

        reg_name = WHvX64RegisterPendingDebugException;
        hr = whpx_get_reg_value(reg_name, &whpx_reg_value);
        if (FAILED(hr)) {
            printf("WHPX: Failed to get pending debug exceptions,"
                   "hr=%08lx",
                   hr);
            return hr;
        }

        if (whpx_reg_value.PendingDebugException.SingleStep) {
            whpx_reg_value.PendingDebugException.SingleStep = 0;

            hr = whpx_set_reg_value(reg_name, whpx_reg_value);

            if (FAILED(hr)) {
                printf("WHPX: Failed to clear pending debug exceptions,"
                       "hr=%08lx",
                       hr);
                return hr;
            }
        }
    }

    return S_OK;
}

static uint64_t whpx_apic_tpr_to_cr8(uint64_t tpr)
{
    return tpr >> 4;
}

static uint64_t whpx_cr8_to_apic_tpr(uint64_t cr8)
{
    return cr8 << 4;
}

static int x86_msr_read(CPUX86State *env, uc_x86_msr *msr)
{
    uint64_t ecx = env->regs[R_ECX];
    uint64_t eax = env->regs[R_EAX];
    uint64_t edx = env->regs[R_EDX];

    env->regs[R_ECX] = msr->rid;
    helper_rdmsr(env);

    msr->value = ((uint32_t)env->regs[R_EAX]) |
                 ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);

    env->regs[R_EAX] = eax;
    env->regs[R_ECX] = ecx;
    env->regs[R_EDX] = edx;

    /* The implementation doesn't throw exception or return an error if
     * there is one, so we will return 0.  */
    return 0;
}

static int x86_msr_write(CPUX86State *env, uc_x86_msr *msr)
{
    uint64_t ecx = env->regs[R_ECX];
    uint64_t eax = env->regs[R_EAX];
    uint64_t edx = env->regs[R_EDX];

    env->regs[R_ECX] = msr->rid;
    env->regs[R_EAX] = (unsigned int)msr->value;
    env->regs[R_EDX] = (unsigned int)(msr->value >> 32);
    helper_wrmsr(env);

    env->regs[R_ECX] = ecx;
    env->regs[R_EAX] = eax;
    env->regs[R_EDX] = edx;

    /* The implementation doesn't throw exception or return an error if
     * there is one, so we will return 0.  */
    return 0;
}

int x86_cpu_pending_interrupt(CPUState *cs, int interrupt_request) {}
void tb_invalidate_phys_page_range(struct uc_struct *uc, uintptr_t start,
                                   uintptr_t end)
{
}
void tlb_flush(CPUState *cpu) {}
void tlb_flush_page(CPUState *cpu, target_ulong addr) {}
/* exit the current TB, but without causing any exception to be raised */
void cpu_loop_exit_noexc(CPUState *cpu)
{
    /*cpu->exception_index = -1;
    cpu_loop_exit(cpu);*/
}

void cpu_reloading_memory_map(void) {}

void cpu_loop_exit(CPUState *cpu)
{
    /*/* Unlock JIT write protect if applicable. #1#
    tb_exec_unlock(cpu->uc->tcg_ctx);
    /* Undo the setting in cpu_tb_exec.  #1#
    cpu->can_do_io = 1;
    siglongjmp(cpu->uc->jmp_bufs[cpu->uc->nested_level - 1], 1);*/
}

void cpu_loop_exit_restore(CPUState *cpu, uintptr_t pc)
{
    /*if (pc) {
        cpu_restore_state(cpu, pc, true);
    }
    cpu_loop_exit(cpu);*/
}

void cpu_loop_exit_atomic(CPUState *cpu, uintptr_t pc)
{
    /*cpu->exception_index = EXCP_ATOMIC;
    cpu_loop_exit_restore(cpu, pc);*/
}

#define FPST(n) (env->fpregs[(env->fpstt + (n)) & 7].d)

#define X86_NON_CS_FLAGS (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK)

HRESULT whpx_get_reg_value(const WHV_REGISTER_NAME RegisterName,
                           WHV_REGISTER_VALUE *RegisterValues)
{
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    hr = WHvGetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         &RegisterName, 1, RegisterValues);
    if (FAILED(hr)) {
        printf("WHPX: Failed to get virtual processor registers,"
               " hr=%08lx",
               hr);
    }

    return hr;
}

HRESULT whpx_get_reg(const WHV_REGISTER_NAME RegisterName, uint64_t *regval)
{
    HRESULT hr = S_OK;
    whpx_state *whpx = &whpx_global;
    WHV_REGISTER_VALUE RegisterValues;
    hr = whpx_get_reg_value(RegisterName, &RegisterValues);
    if (FAILED(hr)) {
        printf("WHPX: Failed to get virtual processor registers,"
               " hr=%08lx",
               hr);
    } else {

        *regval = RegisterValues.Reg64;
    }

    return hr;
}
HRESULT whpx_set_reg_value(const WHV_REGISTER_NAME RegisterName,
                           const WHV_REGISTER_VALUE RegisterValue)
{
    HRESULT hr = S_OK;

    whpx_state *whpx = &whpx_global;

    hr = WHvSetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         &RegisterName, 1, &RegisterValue);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set virtual processor registers,"
               " hr=%08lx",
               hr);
    }

    return hr;
}

HRESULT whpx_set_reg(const WHV_REGISTER_NAME RegisterName, uint64_t regval)
{
    WHV_REGISTER_VALUE RegisterValue;
    RegisterValue.Reg64 = regval;
    HRESULT hr;
    hr = whpx_set_reg_value(RegisterName, RegisterValue);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set virtual processor registers,"
               " hr=%08lx",
               hr);
    }

    return hr;
}

WHV_X64_SEGMENT_REGISTER whpx_seg_q2h(const SegmentCache *qs, int v86, int r86)
{
    WHV_X64_SEGMENT_REGISTER hs;
    unsigned flags = qs->flags;

    hs.Base = qs->base;
    hs.Limit = qs->limit;
    hs.Selector = qs->selector;

    if (v86) {
        hs.Attributes = 0;
        hs.SegmentType = 3;
        hs.Present = 1;
        hs.DescriptorPrivilegeLevel = 3;
        hs.NonSystemSegment = 1;

    } else {
        hs.Attributes = (flags >> DESC_TYPE_SHIFT);

        if (r86) {
            /* hs.Base &= 0xfffff; */
        }
    }

    return hs;
}

static SegmentCache whpx_seg_h2q(const WHV_X64_SEGMENT_REGISTER *hs)
{
    SegmentCache qs;

    qs.base = hs->Base;
    qs.limit = hs->Limit;
    qs.selector = hs->Selector;

    qs.flags = ((uint32_t)hs->Attributes) << DESC_TYPE_SHIFT;

    return qs;
}
// https://wiki.osdev.org/CPU_Registers_x86
/* X64 Extended Control Registers */
static void whpx_set_xcrs(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    WHV_REGISTER_VALUE xcr0;
    WHV_REGISTER_NAME xcr0_name = WHvX64RegisterXCr0;

    if (!whpx_has_xsave()) {
        return;
    }
    env->xcr0 |= XSTATE_FP_MASK;
    env->xcr0 |= XSTATE_SSE_MASK;
    /*env->xcr0 |= XSTATE_YMM_MASK;
    env->xcr0 |= XSTATE_BNDREGS_MASK;
    env->xcr0 |= XSTATE_BNDCSR_MASK;
    env->xcr0 |= XSTATE_OPMASK_MASK;
    env->xcr0 |= XSTATE_ZMM_Hi256_MASK;
    env->xcr0 |= XSTATE_Hi16_ZMM_MASK;
    env->xcr0 |= XSTATE_PKRU_MASK;*/
    /* Only xcr0 is supported by the hypervisor currently */
    xcr0.Reg64 = env->xcr0;
    hr = WHvSetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         &xcr0_name, 1, &xcr0);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set register xcr0, hr=%08lx", hr);
    } else {
        printf("WHvSetVirtualProcessorRegisters WHvX64RegisterXCr0 %016llx "
               "ok\r\n",
               xcr0.Reg64);
    }
}

static int whpx_set_tsc(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    WHV_REGISTER_NAME tsc_reg = WHvX64RegisterTsc;
    WHV_REGISTER_VALUE tsc_val;
    HRESULT hr;
    whpx_state *whpx = &whpx_global;

    /*
     * Suspend the partition prior to setting the TSC to reduce the
     * variance
     * in TSC across vCPUs. When the first vCPU runs post
     * suspend, the
     * partition is automatically resumed.
     */
    if (WHvSuspendPartitionTime) {

        /*
         * Unable to suspend partition while setting TSC is not a
         * fatal
         * error. It just increases the likelihood of TSC
         * variance between
         * vCPUs and some guest OS are able to
         * handle that just fine.
         */
        hr = WHvSuspendPartitionTime(whpx->partition);
        if (FAILED(hr)) {
            printf("WHPX: Failed to suspend partition, hr=%08lx", hr);
        }
    }

    tsc_val.Reg64 = env->tsc;
    hr = WHvSetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         &tsc_reg, 1, &tsc_val);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set TSC, hr=%08lx", hr);
        return -1;
    }

    return 0;
}

#define DumpGpr(name)                                                          \
    whpx_get_reg_value(name, &regvalue);                                       \
    printf(#name##"\t= %016llx\n", regvalue.Reg64)
#define DumpXmm(name)                                                          \
    whpx_get_reg_value(name, &regvalue);                                       \
    if (regvalue.Reg128.High64 > 0 || regvalue.Reg128.Low64 > 0) {             \
        printf(#name##"\t= %016llx%016llx\n", regvalue.Reg128.High64,          \
               regvalue.Reg128.Low64);                                         \
    }

#define DumpSeg(name)                                                          \
    whpx_get_reg_value(name, &regvalue);                                       \
    printf(#name##"\tSel= %04lx\tBase= %016llx\tLimit= %04lx\n",               \
           regvalue.Segment.Selector, regvalue.Segment.Base,                   \
           regvalue.Segment.Limit)

#define DumpTbl(name)                                                          \
    whpx_get_reg_value(name, &regvalue);                                       \
    printf(#name##"\tBase= %016llx\tLimit= %04lx\n", regvalue.Table.Base,      \
           regvalue.Table.Limit)
#define NEM_LOG_REL_CPU_FEATURE(a_Field)                                       \
    printf(#a_Field##"\ ProcessorFeatures = %08x\n", Caps.a_Field)
#define NEM_LOG_REL_XSAVE_FEATURE(a_Field)                                     \
    printf(#a_Field##"\ ProcessorXsaveFeatures = %08x\n", CapsXSave.a_Field)

void DumpRegsGlobal()
{
    WHV_REGISTER_VALUE regvalue = {0};
    DumpGpr(WHvX64RegisterCr0);
    DumpGpr(WHvX64RegisterCr2);
    DumpGpr(WHvX64RegisterCr3);
    DumpGpr(WHvX64RegisterCr4);
    DumpGpr(WHvX64RegisterXCr0);

    DumpSeg(WHvX64RegisterCs);
    DumpSeg(WHvX64RegisterDs);
    DumpSeg(WHvX64RegisterSs);
    DumpSeg(WHvX64RegisterEs);
    DumpSeg(WHvX64RegisterFs);
    DumpSeg(WHvX64RegisterGs);
    DumpSeg(WHvX64RegisterTr);
    DumpTbl(WHvX64RegisterGdtr);
    DumpTbl(WHvX64RegisterIdtr);
}
void DumpRegs()
{

    WHV_REGISTER_VALUE regvalue = {0};
    //// Get stack HVA
    ////
    // auto rspGva = registers[ Rsp ].Reg64;
    // WHSE_ALLOCATION_NODE* node = nullptr;
    // if ( FAILED( WhSeFindAllocationNodeByGva( Partition, rspGva, &node )
    // ) )
    //	return false;

    // auto rspHva = node->HostVirtualAddress;
    // printf( "RSP = %llx (hva = %llx)\n", rspGva, rspHva );

    DumpGpr(WHvX64RegisterRip);

    DumpGpr(WHvX64RegisterRsp);
    DumpGpr(WHvX64RegisterRbp);

    DumpGpr(WHvX64RegisterRax);
    DumpGpr(WHvX64RegisterRbx);
    DumpGpr(WHvX64RegisterRcx);
    DumpGpr(WHvX64RegisterRdx);
    DumpGpr(WHvX64RegisterRdi);
    DumpGpr(WHvX64RegisterRsi);
    DumpGpr(WHvX64RegisterR8);
    DumpGpr(WHvX64RegisterR9);
    DumpGpr(WHvX64RegisterR10);
    DumpGpr(WHvX64RegisterR11);
    DumpGpr(WHvX64RegisterR12);
    DumpGpr(WHvX64RegisterR13);
    DumpGpr(WHvX64RegisterR14);
    DumpGpr(WHvX64RegisterR15);
    DumpGpr(WHvX64RegisterRflags);

    DumpXmm(WHvX64RegisterXmm0);
    DumpXmm(WHvX64RegisterXmm1);
    DumpXmm(WHvX64RegisterXmm2);
    DumpXmm(WHvX64RegisterXmm3);
    DumpXmm(WHvX64RegisterXmm4);
    DumpXmm(WHvX64RegisterXmm5);
    DumpXmm(WHvX64RegisterXmm6);
    DumpXmm(WHvX64RegisterXmm7);
    DumpXmm(WHvX64RegisterXmm8);
    DumpXmm(WHvX64RegisterXmm9);
    DumpXmm(WHvX64RegisterXmm10);
    DumpXmm(WHvX64RegisterXmm11);
    DumpXmm(WHvX64RegisterXmm12);
    DumpXmm(WHvX64RegisterXmm13);
    DumpXmm(WHvX64RegisterXmm14);
    DumpXmm(WHvX64RegisterXmm15);

    return;
}

static void whpx_set_reg_valueisters(CPUState *cpu, int level)
{
    HRESULT hr = S_OK;
    whpx_state *whpx = &whpx_global;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    whpx_vcpu *vcpu = get_whpx_vcpu(x86_cpu);
    struct whpx_register_set vcxt;

    int idx;
    int idx_next;
    int i;

    assert(cpu_is_stopped(cpu) || qemu_cpu_is_self(cpu));

    /*
     * Following MSRs have side effects on the guest or are too heavy
     * for
     * runtime. Limit them to full state update.
     */
    if (level >= WHPX_SET_RESET_STATE) {
        whpx_set_tsc(cpu);
    }

    memset(&vcxt, 0, sizeof(struct whpx_register_set));
    int v86, r86;
    v86 = (env->eflags & VM_MASK);
    r86 = !(env->cr[0] & CR0_PE_MASK);

    // vcpu->tpr =
    // whpx_apic_tpr_to_cr8(cpu_get_apic_tpr(x86_cpu->apic_state));
    // vcpu->apic_base = cpu_get_apic_base(x86_cpu->apic_state);

    idx = 0;

    /* Indexes for first 16 registers match between HV and QEMU definitions
     */
    idx_next = 16;
    for (idx = 0; idx < CPU_NB_REGS; idx += 1) {
        vcxt.values[idx].Reg64 = (uint64_t)env->regs[idx];
    }
    idx = idx_next;

    /* Same goes for RIP and RFLAGS */
    assert(whpx_register_names[idx] == WHvX64RegisterRip);
    vcxt.values[idx++].Reg64 = env->eip;

    assert(whpx_register_names[idx] == WHvX64RegisterRflags);
    vcxt.values[idx++].Reg64 = env->eflags;

    /* Translate 6+4 segment registers. HV and QEMU order matches  */
    assert(idx == WHvX64RegisterEs);
    for (i = 0; i < 6; i += 1, idx += 1) {
        vcxt.values[idx].Segment = whpx_seg_q2h(&env->segs[i], v86, r86);
    }

    assert(idx == WHvX64RegisterLdtr);
    vcxt.values[idx++].Segment = whpx_seg_q2h(&env->ldt, 0, 0);

    assert(idx == WHvX64RegisterTr);
    vcxt.values[idx++].Segment = whpx_seg_q2h(&env->tr, 0, 0);

    assert(idx == WHvX64RegisterIdtr);
    vcxt.values[idx].Table.Base = env->idt.base;
    vcxt.values[idx].Table.Limit = env->idt.limit;
    idx += 1;

    assert(idx == WHvX64RegisterGdtr);
    vcxt.values[idx].Table.Base = env->gdt.base;
    vcxt.values[idx].Table.Limit = env->gdt.limit;
    idx += 1;

    /* CR0, 2, 3, 4, 8 */
    assert(whpx_register_names[idx] == WHvX64RegisterCr0);
    vcxt.values[idx++].Reg64 = env->cr[0];
    assert(whpx_register_names[idx] == WHvX64RegisterCr2);
    vcxt.values[idx++].Reg64 = env->cr[2];
    assert(whpx_register_names[idx] == WHvX64RegisterCr3);
    vcxt.values[idx++].Reg64 = env->cr[3];
    assert(whpx_register_names[idx] == WHvX64RegisterCr4);
    vcxt.values[idx++].Reg64 = env->cr[4];
    assert(whpx_register_names[idx] == WHvX64RegisterCr8);
    vcxt.values[idx++].Reg64 = vcpu->tpr;

    /* 8 Debug Registers - Skipped */

    /*
     * Extended control registers needs to be handled separately
     * depending
     * on whether xsave is supported/enabled or not.
     */
    whpx_set_xcrs(cpu);

    /* 16 XMM registers */
    assert(whpx_register_names[idx] == WHvX64RegisterXmm0);
    idx_next = idx + 16;
    for (i = 0; i < sizeof(env->xmm_regs) / sizeof(ZMMReg); i += 1, idx += 1) {
        vcxt.values[idx].Reg128.Low64 = env->xmm_regs[i].ZMM_Q(0);
        vcxt.values[idx].Reg128.High64 = env->xmm_regs[i].ZMM_Q(1);
    }
    idx = idx_next;

    /* 8 FP registers */
    assert(whpx_register_names[idx] == WHvX64RegisterFpMmx0);
    for (i = 0; i < 8; i += 1, idx += 1) {
        vcxt.values[idx].Fp.AsUINT128.Low64 = env->fpregs[i].mmx.MMX_Q(0);
        /* vcxt.values[idx].Fp.AsUINT128.High64 =

         * env->fpregs[i].mmx.MMX_Q(1);
        */
    }

    /* FP control status register */
    assert(whpx_register_names[idx] == WHvX64RegisterFpControlStatus);
    vcxt.values[idx].FpControlStatus.FpControl = env->fpuc;
    vcxt.values[idx].FpControlStatus.FpStatus =
        (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    vcxt.values[idx].FpControlStatus.FpTag = 0;
    for (i = 0; i < 8; ++i) {
        vcxt.values[idx].FpControlStatus.FpTag |= (!env->fptags[i]) << i;
    }
    vcxt.values[idx].FpControlStatus.Reserved = 0;
    vcxt.values[idx].FpControlStatus.LastFpOp = env->fpop;
    vcxt.values[idx].FpControlStatus.LastFpRip = env->fpip;
    idx += 1;

    /* XMM control status register */
    assert(whpx_register_names[idx] == WHvX64RegisterXmmControlStatus);
    vcxt.values[idx].XmmControlStatus.LastFpRdp = 0;
    vcxt.values[idx].XmmControlStatus.XmmStatusControl = env->mxcsr;
    vcxt.values[idx].XmmControlStatus.XmmStatusControlMask = 0x0000ffff;
    idx += 1;

    /* MSRs */
    assert(whpx_register_names[idx] == WHvX64RegisterEfer);
    vcxt.values[idx++].Reg64 = env->efer;
#ifdef TARGET_X86_64
    assert(whpx_register_names[idx] == WHvX64RegisterKernelGsBase);
    vcxt.values[idx++].Reg64 = env->kernelgsbase;
#endif

    assert(whpx_register_names[idx] == WHvX64RegisterApicBase);
    vcxt.values[idx++].Reg64 = vcpu->apic_base;

    /* WHvX64RegisterPat - Skipped */

    assert(whpx_register_names[idx] == WHvX64RegisterSysenterCs);
    vcxt.values[idx++].Reg64 = env->sysenter_cs;
    assert(whpx_register_names[idx] == WHvX64RegisterSysenterEip);
    vcxt.values[idx++].Reg64 = env->sysenter_eip;
    assert(whpx_register_names[idx] == WHvX64RegisterSysenterEsp);
    vcxt.values[idx++].Reg64 = env->sysenter_esp;
    assert(whpx_register_names[idx] == WHvX64RegisterStar);
    vcxt.values[idx++].Reg64 = env->star;
#ifdef TARGET_X86_64
    assert(whpx_register_names[idx] == WHvX64RegisterLstar);
    vcxt.values[idx++].Reg64 = env->lstar;
    assert(whpx_register_names[idx] == WHvX64RegisterCstar);
    vcxt.values[idx++].Reg64 = env->cstar;
    assert(whpx_register_names[idx] == WHvX64RegisterSfmask);
    vcxt.values[idx++].Reg64 = env->fmask;
#endif

    /* Interrupt / Event Registers - Skipped */

    assert(idx == RTL_NUMBER_OF(whpx_register_names));

    hr = WHvSetVirtualProcessorRegisters(
        whpx->partition, whpx->cpu_index, whpx_register_names,
        RTL_NUMBER_OF(whpx_register_names), &vcxt.values[0]);

    if (FAILED(hr)) {
        printf("WHPX: Failed to set virtual processor context, hr=%08lx", hr);
    }

    return;
}

static int reg_write(CPUX86State *env, unsigned int regid, const void *value,
                     uc_mode mode)
{

    if (regid == UC_X86_REG_CR0 || regid == UC_X86_REG_CR1 ||
        regid == UC_X86_REG_CR2 || regid == UC_X86_REG_CR3 ||
        regid == UC_X86_REG_CR4 || regid == UC_X86_REG_CS ||
        regid == UC_X86_REG_SS || regid == UC_X86_REG_DS ||
        regid == UC_X86_REG_FS || regid == UC_X86_REG_GS ||
        regid == UC_X86_REG_ES || regid == UC_X86_REG_GDTR ||
        regid == UC_X86_REG_LDTR) {
        return 0;
    }
    uint64_t backregvalue = 0;
    WHV_REGISTER_VALUE regvalue = {0};
    WHV_REGISTER_NAME RegisterName;
    whpx_state *whpx = &whpx_global;

    whpx_register_set vcxt;
    memset(&vcxt, 0, sizeof(struct whpx_register_set));
    int RegisterCount = 1;
    int idx = 0;
    int ret;
    HRESULT hr = S_OK;
    int v86, r86;
    v86 = (env->eflags & VM_MASK);
    r86 = !(env->cr[0] & CR0_PE_MASK);
    switch (regid) {
    default:
        break;
    case UC_X86_REG_FP0:
    case UC_X86_REG_FP1:
    case UC_X86_REG_FP2:
    case UC_X86_REG_FP3:
    case UC_X86_REG_FP4:
    case UC_X86_REG_FP5:
    case UC_X86_REG_FP6:
    case UC_X86_REG_FP7: {
        uint64_t mant = *(uint64_t *)value;
        uint16_t upper = *(uint16_t *)((char *)value + sizeof(uint64_t));
        // env->fpregs[regid - UC_X86_REG_FP0].d
        // =(floatx80)cpu_set_fp80(mant, upper);
    }
        return 0;
    case UC_X86_REG_FPSW: {
        uint16_t fpus = *(uint16_t *)value;
        env->fpus = fpus & ~0x3800;
        env->fpstt = (fpus >> 11) & 0x7;
    }
        return 0;
    case UC_X86_REG_FPCW:
        cpu_set_fpuc(env, *(uint16_t *)value);
        return 0;
    case UC_X86_REG_FPTAG: {
        int i;
        uint16_t fptag = *(uint16_t *)value;
        for (i = 0; i < 8; i++) {
            env->fptags[i] = ((fptag & 3) == 3);
            fptag >>= 2;
        }

        return 0;
    } break;
    case UC_X86_REG_XMM0:
    case UC_X86_REG_XMM1:
    case UC_X86_REG_XMM2:
    case UC_X86_REG_XMM3:
    case UC_X86_REG_XMM4:
    case UC_X86_REG_XMM5:
    case UC_X86_REG_XMM6:
    case UC_X86_REG_XMM7: {
        float64 *src = (float64 *)value;
        ZMMReg *reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
        reg->ZMM_Q(0) = src[0];
        reg->ZMM_Q(1) = src[1];

        assert(whpx_register_names[idx] == WHvX64RegisterFpMmx0);
        for (int i = 0; i < 8; i += 1, idx += 1) {
            // vcxt.values[idx].Fp.AsUINT128.Low64 =
            // env->fpregs[i].mmx.MMX_Q(0);
            /* vcxt.values[idx].Fp.AsUINT128.High64 =

             * env->fpregs[i].mmx.MMX_Q(1);
        */
        }
        RegisterName = WHvX64RegisterXmm0 + regid - UC_X86_REG_XMM0;
        regvalue.Reg128.Low64 = reg->ZMM_Q(0);
        regvalue.Reg128.High64 = reg->ZMM_Q(1);

        whpx_set_reg_value(RegisterName, regvalue);
        return 0;
        break;
        // return 0;
    }
    case UC_X86_REG_ST0:
    case UC_X86_REG_ST1:
    case UC_X86_REG_ST2:
    case UC_X86_REG_ST3:
    case UC_X86_REG_ST4:
    case UC_X86_REG_ST5:
    case UC_X86_REG_ST6:
    case UC_X86_REG_ST7: {
        // value must be big enough to keep 80 bits (10 bytes)
        memcpy(&FPST(regid - UC_X86_REG_ST0), value, 10);
        return 0;
    }
    case UC_X86_REG_YMM0:
    case UC_X86_REG_YMM1:
    case UC_X86_REG_YMM2:
    case UC_X86_REG_YMM3:
    case UC_X86_REG_YMM4:
    case UC_X86_REG_YMM5:
    case UC_X86_REG_YMM6:
    case UC_X86_REG_YMM7:
    case UC_X86_REG_YMM8:
    case UC_X86_REG_YMM9:
    case UC_X86_REG_YMM10:
    case UC_X86_REG_YMM11:
    case UC_X86_REG_YMM12:
    case UC_X86_REG_YMM13:
    case UC_X86_REG_YMM14:
    case UC_X86_REG_YMM15: {
        float64 *src = (float64 *)value;
        ZMMReg *lo_reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_YMM0];
        XMMReg *hi_reg = &env->ymmh_regs[regid - UC_X86_REG_YMM0];
        lo_reg->ZMM_Q(0) = src[0];
        lo_reg->ZMM_Q(1) = src[1];
        // YMM is not supported by QEMU at all
        // As of qemu 5.0.1, ymmh_regs is nowhere used.
        hi_reg->_d[0] = src[2];
        hi_reg->_d[1] = src[3];
        return 0;
    }

    case UC_X86_REG_FIP:
        env->fpip = *(uint64_t *)value;
        return 0;
    case UC_X86_REG_FCS:
        env->fpcs = *(uint16_t *)value;
        return 0;
    case UC_X86_REG_FDP:
        env->fpdp = *(uint64_t *)value;
        return 0;
    case UC_X86_REG_FDS:
        env->fpds = *(uint16_t *)value;
        return 0;
    case UC_X86_REG_FOP:
        env->fpop = *(uint16_t *)value;
        return 0;
    }

    switch (mode) {
    default:
        break;

    case UC_MODE_16:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_ES:
            load_seg_16_helper(env, R_ES, *(uint16_t *)value);
            RegisterName = WHvX64RegisterEs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_ES], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            return 0;
        case UC_X86_REG_SS:
            load_seg_16_helper(env, R_SS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterSs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_SS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            return 0;
        case UC_X86_REG_DS:
            load_seg_16_helper(env, R_DS, *(uint16_t *)value);

            RegisterName = WHvX64RegisterDs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_DS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            return 0;
        case UC_X86_REG_FS:
            load_seg_16_helper(env, R_FS, *(uint16_t *)value);

            RegisterName = WHvX64RegisterFs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_FS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);

            return 0;
        case UC_X86_REG_GS:
            load_seg_16_helper(env, R_GS, *(uint16_t *)value);

            RegisterName = WHvX64RegisterGs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_GS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            return 0;
        }
        // fall-thru
    case UC_MODE_32:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            env->cr[regid - UC_X86_REG_CR0] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterCr0 + regid - UC_X86_REG_CR0;
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            env->dr[regid - UC_X86_REG_DR0] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterDr0 + regid - UC_X86_REG_DR0;
            break;
        case UC_X86_REG_FLAGS:
            cpu_load_eflags(env, *(uint16_t *)value, -1);
            break;
        case UC_X86_REG_EFLAGS:
            cpu_load_eflags(env, *(uint32_t *)value, -1);
            break;
        case UC_X86_REG_EAX:

            env->regs[R_EAX] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AX:
            WRITE_WORD(env->regs[R_EAX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AH:
            WRITE_BYTE_H(env->regs[R_EAX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AL:
            WRITE_BYTE_L(env->regs[R_EAX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EBX:
            env->regs[R_EBX] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BX:
            WRITE_WORD(env->regs[R_EBX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BH:
            WRITE_BYTE_H(env->regs[R_EBX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BL:
            WRITE_BYTE_L(env->regs[R_EBX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_ECX:
            env->regs[R_ECX] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CX:
            WRITE_WORD(env->regs[R_ECX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CH:
            WRITE_BYTE_H(env->regs[R_ECX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CL:
            WRITE_BYTE_L(env->regs[R_ECX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EDX:
            env->regs[R_EDX] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DX:
            WRITE_WORD(env->regs[R_EDX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DH:
            WRITE_BYTE_H(env->regs[R_EDX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DL:
            WRITE_BYTE_L(env->regs[R_EDX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_ESP:
            env->regs[R_ESP] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SP:
            WRITE_WORD(env->regs[R_ESP], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EBP:
            env->regs[R_EBP] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BP:
            WRITE_WORD(env->regs[R_EBP], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BPL:
            WRITE_BYTE_L(env->regs[R_EBP], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_ESI:
            env->regs[R_ESI] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SI:
            WRITE_WORD(env->regs[R_ESI], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EDI:
            env->regs[R_EDI] = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DI:
            WRITE_WORD(env->regs[R_EDI], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EIP:
            env->eip = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_IP:
            env->eip = *(uint16_t *)value;
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CS:
            ret = uc_check_cpu_x86_load_seg(env, R_CS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_CS, *(uint16_t *)value);

            RegisterName = WHvX64RegisterCs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_CS], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_DS:
            ret = uc_check_cpu_x86_load_seg(env, R_DS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_DS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterDs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_DS], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_SS:
            ret = uc_check_cpu_x86_load_seg(env, R_SS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_SS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterSs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_SS], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_ES:
            ret = uc_check_cpu_x86_load_seg(env, R_ES, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_ES, *(uint16_t *)value);
            RegisterName = WHvX64RegisterEs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_ES], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_FS:
            ret = uc_check_cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterFs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_FS], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            return 0;
        case UC_X86_REG_GS:
            ret = uc_check_cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterGs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_GS], v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_IDTR:
            env->idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->idt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            return 0;
            RegisterName = WHvX64RegisterIdtr;
            regvalue.Segment = whpx_seg_q2h(&env->idt, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_GDTR:

            env->gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->gdt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            RegisterName = WHvX64RegisterGdtr;
            regvalue.Segment = whpx_seg_q2h(&env->gdt, v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_LDTR:
            env->ldt.limit = ((uc_x86_mmr *)value)->limit;
            env->ldt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            env->ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->ldt.flags = ((uc_x86_mmr *)value)->flags;
            RegisterName = WHvX64RegisterLdtr;
            regvalue.Segment = whpx_seg_q2h(&env->ldt, v86, r86);
            return 0;
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_TR:
            env->tr.limit = ((uc_x86_mmr *)value)->limit;
            env->tr.base = (uint32_t)((uc_x86_mmr *)value)->base;
            env->tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->tr.flags = ((uc_x86_mmr *)value)->flags;
            RegisterName = WHvX64RegisterTr;
            regvalue.Segment = whpx_seg_q2h(&env->tr, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_MSR:
            x86_msr_write(env, (uc_x86_msr *)value);
            return 0;
            break;
        case UC_X86_REG_MXCSR:
            cpu_set_mxcsr(env, *(uint32_t *)value);
            return 0;
            break;
            /*
        // Don't think base registers are a "thing" on x86
        case UC_X86_REG_FS_BASE:
            env->segs[R_FS].base = *(uint32_t *)value;
            continue;
        case UC_X86_REG_GS_BASE:
            env->segs[R_GS].base = *(uint32_t *)value;
            continue;
            */
        }
        break;

#ifdef TARGET_X86_64
    case UC_MODE_64:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            env->cr[regid - UC_X86_REG_CR0] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterCr0 + regid - UC_X86_REG_CR0;
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            env->dr[regid - UC_X86_REG_DR0] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterDr0 + regid - UC_X86_REG_DR0;
            break;
        case UC_X86_REG_FLAGS:
            cpu_load_eflags(env, *(uint16_t *)value, -1);
            RegisterName = WHvX64RegisterRflags;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_EFLAGS:
            cpu_load_eflags(env, *(uint32_t *)value, -1);
            RegisterName = WHvX64RegisterRflags;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RFLAGS:
            cpu_load_eflags(env, *(uint64_t *)value, -1);
            RegisterName = WHvX64RegisterRflags;
            value = *(uint64_t *)value;
            break;
        case UC_X86_REG_RAX:
            env->regs[R_EAX] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EAX:
            WRITE_DWORD(env->regs[R_EAX], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AX:
            WRITE_WORD(env->regs[R_EAX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AH:
            WRITE_BYTE_H(env->regs[R_EAX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_AL:
            WRITE_BYTE_L(env->regs[R_EAX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RBX:
            env->regs[R_EBX] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EBX:
            WRITE_DWORD(env->regs[R_EBX], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BX:
            WRITE_WORD(env->regs[R_EBX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BH:
            WRITE_BYTE_H(env->regs[R_EBX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BL:
            WRITE_BYTE_L(env->regs[R_EBX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RCX:
            env->regs[R_ECX] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_ECX:
            WRITE_DWORD(env->regs[R_ECX], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CX:
            WRITE_WORD(env->regs[R_ECX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CH:
            WRITE_BYTE_H(env->regs[R_ECX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CL:
            WRITE_BYTE_L(env->regs[R_ECX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RDX:
            env->regs[R_EDX] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EDX:
            WRITE_DWORD(env->regs[R_EDX], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DX:
            WRITE_WORD(env->regs[R_EDX], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DH:
            WRITE_BYTE_H(env->regs[R_EDX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_H(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DL:
            WRITE_BYTE_L(env->regs[R_EDX], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RSP:
            env->regs[R_ESP] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_ESP:
            WRITE_DWORD(env->regs[R_ESP], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SP:
            WRITE_WORD(env->regs[R_ESP], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SPL:
            WRITE_BYTE_L(env->regs[R_ESP], *(uint8_t *)value);
            break;
        case UC_X86_REG_RBP:
            env->regs[R_EBP] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EBP:
            WRITE_DWORD(env->regs[R_EBP], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BP:
            WRITE_WORD(env->regs[R_EBP], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_BPL:
            WRITE_BYTE_L(env->regs[R_EBP], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint16_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RSI:
            env->regs[R_ESI] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_ESI:
            WRITE_DWORD(env->regs[R_ESI], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SI:
            WRITE_WORD(env->regs[R_ESI], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_SIL:
            WRITE_BYTE_L(env->regs[R_ESI], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RDI:
            env->regs[R_EDI] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EDI:
            WRITE_DWORD(env->regs[R_EDI], *(uint32_t *)value);
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DI:
            WRITE_WORD(env->regs[R_EDI], *(uint16_t *)value);
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_DIL:
            WRITE_BYTE_L(env->regs[R_EDI], *(uint8_t *)value);
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_RIP:
            env->eip = *(uint64_t *)value;
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &backregvalue);
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_EIP:
            env->eip = *(uint32_t *)value;
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_IP:
            WRITE_WORD(env->eip, *(uint16_t *)value);
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_CS:
            env->segs[R_CS].selector = *(uint16_t *)value;
            RegisterName = WHvX64RegisterCs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_CS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_DS:
            env->segs[R_DS].selector = *(uint16_t *)value;
            RegisterName = WHvX64RegisterCs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_CS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_SS:
            env->segs[R_SS].selector = *(uint16_t *)value;

            RegisterName = WHvX64RegisterSs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_SS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;

        case UC_X86_REG_ES:
            env->segs[R_ES].selector = *(uint16_t *)value;
            RegisterName = WHvX64RegisterEs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_ES], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_FS:
            ret = uc_check_cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterFs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_FS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_GS:
            ret = uc_check_cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            RegisterName = WHvX64RegisterGs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_GS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_R8:
            env->regs[8] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR8;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R8D:
            WRITE_DWORD(env->regs[8], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R8W:
            WRITE_WORD(env->regs[8], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R8B:
            WRITE_BYTE_L(env->regs[8], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R9:
            env->regs[9] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR9;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R9D:
            WRITE_DWORD(env->regs[9], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R9W:
            WRITE_WORD(env->regs[9], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R9B:
            WRITE_BYTE_L(env->regs[9], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R10:
            env->regs[10] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR10;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R10D:
            WRITE_DWORD(env->regs[10], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R10W:
            WRITE_WORD(env->regs[10], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R10B:
            WRITE_BYTE_L(env->regs[10], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R11:
            env->regs[11] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR11;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R11D:
            WRITE_DWORD(env->regs[11], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R11W:
            WRITE_WORD(env->regs[11], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R11B:
            WRITE_BYTE_L(env->regs[11], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R12:
            env->regs[12] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR12;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R12D:
            WRITE_DWORD(env->regs[12], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R12W:
            WRITE_WORD(env->regs[12], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R12B:
            WRITE_BYTE_L(env->regs[12], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R13:
            env->regs[13] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR13;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R13D:
            WRITE_DWORD(env->regs[13], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R13W:
            WRITE_WORD(env->regs[13], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R13B:
            WRITE_BYTE_L(env->regs[13], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R14:
            env->regs[14] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR14;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R14D:
            WRITE_DWORD(env->regs[14], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R14W:
            WRITE_WORD(env->regs[14], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R14B:
            WRITE_BYTE_L(env->regs[14], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R15:
            env->regs[15] = *(uint64_t *)value;
            RegisterName = WHvX64RegisterR15;
            backregvalue = *(uint64_t *)value;
            value = backregvalue;
            break;
        case UC_X86_REG_R15D:
            WRITE_DWORD(env->regs[15], *(uint32_t *)value);
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_DWORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R15W:
            WRITE_WORD(env->regs[15], *(uint16_t *)value);
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_WORD(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_R15B:
            WRITE_BYTE_L(env->regs[15], *(uint8_t *)value);
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &backregvalue);
            WRITE_BYTE_L(backregvalue, *(uint32_t *)value);
            value = backregvalue;
            break;
        case UC_X86_REG_IDTR:
            env->idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->idt.base = ((uc_x86_mmr *)value)->base;
            RegisterName = WHvX64RegisterIdtr;
            regvalue.Segment = whpx_seg_q2h(&env->idt, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_GDTR:
            env->gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->gdt.base = ((uc_x86_mmr *)value)->base;
            RegisterName = WHvX64RegisterGdtr;
            regvalue.Segment = whpx_seg_q2h(&env->gdt, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_LDTR:
            env->ldt.limit = ((uc_x86_mmr *)value)->limit;
            env->ldt.base = ((uc_x86_mmr *)value)->base;
            env->ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->ldt.flags = ((uc_x86_mmr *)value)->flags;
            RegisterName = WHvX64RegisterLdtr;
            regvalue.Segment = whpx_seg_q2h(&env->ldt, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_TR:
            env->tr.limit = ((uc_x86_mmr *)value)->limit;
            env->tr.base = ((uc_x86_mmr *)value)->base;
            env->tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->tr.flags = ((uc_x86_mmr *)value)->flags;
            RegisterName = WHvX64RegisterTr;
            regvalue.Segment = whpx_seg_q2h(&env->tr, v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_MSR:
            x86_msr_write(env, (uc_x86_msr *)value);
            return 0;
            break;
        case UC_X86_REG_MXCSR:
            cpu_set_mxcsr(env, *(uint32_t *)value);
            return 0;
            break;
        case UC_X86_REG_XMM8:
        case UC_X86_REG_XMM9:
        case UC_X86_REG_XMM10:
        case UC_X86_REG_XMM11:
        case UC_X86_REG_XMM12:
        case UC_X86_REG_XMM13:
        case UC_X86_REG_XMM14:
        case UC_X86_REG_XMM15: {
            float64 *src = (float64 *)value;
            ZMMReg *reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
            reg->ZMM_Q(0) = src[0];
            reg->ZMM_Q(1) = src[1];
            regvalue.Reg128.Low64 = reg->ZMM_Q(0);
            regvalue.Reg128.High64 = reg->ZMM_Q(1);
            RegisterName = WHvX64RegisterXmm0 + regid - UC_X86_REG_XMM0;
            whpx_set_reg_value(RegisterName, regvalue);
            return 0;
            break;
        }
        case UC_X86_REG_FS_BASE:
            env->segs[R_FS].base = *(uint64_t *)value;
            RegisterName = WHvX64RegisterFs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_FS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        case UC_X86_REG_GS_BASE:
            env->segs[R_GS].base = *(uint64_t *)value;
            RegisterName = WHvX64RegisterGs;
            regvalue.Segment = whpx_seg_q2h(&env->segs[R_GS], v86, r86);
            hr = whpx_set_reg_value(RegisterName, regvalue);
            // break;
            return 0;
        }
        break;
#endif
    }
    regvalue.Reg64 = value;
    hr = whpx_set_reg_value(RegisterName, regvalue);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set virtual processor registers,"
               " hr=%08lx",
               hr);
        return 1;
    } else {

        return 0;
    }
}

static void reg_read(CPUX86State *env, unsigned int regid, void *value,
                     uc_mode mode)
{
    WHV_REGISTER_NAME RegisterName;
    WHV_REGISTER_VALUE regvalue = {0};
    switch (regid) {
    default:
        break;
    case UC_X86_REG_FP0:
    case UC_X86_REG_FP1:
    case UC_X86_REG_FP2:
    case UC_X86_REG_FP3:
    case UC_X86_REG_FP4:
    case UC_X86_REG_FP5:
    case UC_X86_REG_FP6:
    case UC_X86_REG_FP7: {
        floatx80 reg = env->fpregs[regid - UC_X86_REG_FP0].d;
        cpu_get_fp80(value, (uint16_t *)((char *)value + sizeof(uint64_t)),
                     reg);
    }
        return;
    case UC_X86_REG_FPSW: {
        uint16_t fpus = env->fpus;
        fpus = fpus & ~0x3800;
        fpus |= (env->fpstt & 0x7) << 11;
        *(uint16_t *)value = fpus;
    }
        return;
    case UC_X86_REG_FPCW:
        *(uint16_t *)value = env->fpuc;
        return;
    case UC_X86_REG_FPTAG: {
#define EXPD(fp) (fp.l.upper & 0x7fff)
#define MANTD(fp) (fp.l.lower)
#define MAXEXPD 0x7fff
        int fptag, exp, i;
        uint64_t mant;
        CPU_LDoubleU tmp;
        fptag = 0;
        for (i = 7; i >= 0; i--) {
            fptag <<= 2;
            if (env->fptags[i]) {
                fptag |= 3;
            } else {
                tmp.d = env->fpregs[i].d;
                exp = EXPD(tmp);
                mant = MANTD(tmp);
                if (exp == 0 && mant == 0) {
                    /* zero */
                    fptag |= 1;
                } else if (exp == 0 || exp == MAXEXPD ||
                           (mant & (1LL << 63)) == 0) {
                    /* NaNs, infinity, denormal */
                    fptag |= 2;
                }
            }
        }
        *(uint16_t *)value = fptag;
    }
        return;
    case UC_X86_REG_XMM0:
    case UC_X86_REG_XMM1:
    case UC_X86_REG_XMM2:
    case UC_X86_REG_XMM3:
    case UC_X86_REG_XMM4:
    case UC_X86_REG_XMM5:
    case UC_X86_REG_XMM6:
    case UC_X86_REG_XMM7: {
        float64 *dst = (float64 *)value;
        RegisterName = WHvX64RegisterXmm0 + regid - UC_X86_REG_XMM0;
        whpx_set_reg_value(RegisterName, regvalue);
        ZMMReg *reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
        reg->ZMM_Q(0) = regvalue.Reg128.Low64;
        reg->ZMM_Q(1) = regvalue.Reg128.High64;
        dst[0] = reg->ZMM_Q(0);
        dst[1] = reg->ZMM_Q(1);
        return;
    }
    case UC_X86_REG_ST0:
    case UC_X86_REG_ST1:
    case UC_X86_REG_ST2:
    case UC_X86_REG_ST3:
    case UC_X86_REG_ST4:
    case UC_X86_REG_ST5:
    case UC_X86_REG_ST6:
    case UC_X86_REG_ST7: {
        // value must be big enough to keep 80 bits (10 bytes)
        memcpy(value, &FPST(regid - UC_X86_REG_ST0), 10);
        return;
    }
    case UC_X86_REG_YMM0:
    case UC_X86_REG_YMM1:
    case UC_X86_REG_YMM2:
    case UC_X86_REG_YMM3:
    case UC_X86_REG_YMM4:
    case UC_X86_REG_YMM5:
    case UC_X86_REG_YMM6:
    case UC_X86_REG_YMM7:
    case UC_X86_REG_YMM8:
    case UC_X86_REG_YMM9:
    case UC_X86_REG_YMM10:
    case UC_X86_REG_YMM11:
    case UC_X86_REG_YMM12:
    case UC_X86_REG_YMM13:
    case UC_X86_REG_YMM14:
    case UC_X86_REG_YMM15: {
        float64 *dst = (float64 *)value;
        ZMMReg *lo_reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_YMM0];
        XMMReg *hi_reg = &env->ymmh_regs[regid - UC_X86_REG_YMM0];
        dst[0] = lo_reg->ZMM_Q(0);
        dst[1] = lo_reg->ZMM_Q(1);
        dst[2] = hi_reg->_d[0];
        dst[3] = hi_reg->_d[1];
        return;
    }

    case UC_X86_REG_FIP:
        *(uint64_t *)value = env->fpip;
        return;
    case UC_X86_REG_FCS:
        *(uint16_t *)value = env->fpcs;
        return;
    case UC_X86_REG_FDP:
        *(uint64_t *)value = env->fpdp;
        return;
    case UC_X86_REG_FDS:
        *(uint16_t *)value = env->fpds;
        return;
    case UC_X86_REG_FOP:
        *(uint16_t *)value = env->fpop;
        return;
    }

    switch (mode) {
    default:
        break;
    case UC_MODE_16:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_ES:
            RegisterName = WHvX64RegisterEs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_ES] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = env->segs[R_ES].selector;
            return;
        case UC_X86_REG_SS:
            RegisterName = WHvX64RegisterSs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_SS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = env->segs[R_SS].selector;
            return;
        case UC_X86_REG_DS:
            RegisterName = WHvX64RegisterDs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_DS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = env->segs[R_DS].selector;
            return;
        case UC_X86_REG_FS:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = env->segs[R_FS].selector;
            return;
        case UC_X86_REG_GS:
            RegisterName = WHvX64RegisterGs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_GS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = env->segs[R_GS].selector;
            return;
        case UC_X86_REG_FS_BASE:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(uint32_t *)value = (uint32_t)env->segs[R_FS].base;
            return;
        }
        // fall-thru
    case UC_MODE_32:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            RegisterName = WHvX64RegisterCr0 + regid - UC_X86_REG_CR0;
            whpx_get_reg(RegisterName, &env->cr[regid - UC_X86_REG_CR0]);
            *(int32_t *)value = env->cr[regid - UC_X86_REG_CR0];
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            RegisterName = WHvX64RegisterDr0 + regid - UC_X86_REG_DR0;
            // whpx_get_reg(RegisterName, &env->dr[regid - UC_X86_REG_DR0]);
            *(int32_t *)value = env->dr[regid - UC_X86_REG_DR0];
            break;
        case UC_X86_REG_FLAGS:
            *(int16_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EFLAGS:
            *(int32_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EAX:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int32_t *)value = env->regs[R_EAX];
            break;
        case UC_X86_REG_AX:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AH:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AL:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EAX]);
            break;
        case UC_X86_REG_EBX:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int32_t *)value = env->regs[R_EBX];
            break;
        case UC_X86_REG_BX:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BH:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BL:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBX]);
            break;
        case UC_X86_REG_ECX:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int32_t *)value = env->regs[R_ECX];
            break;
        case UC_X86_REG_CX:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int16_t *)value = READ_WORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CH:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CL:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ECX]);
            break;
        case UC_X86_REG_EDX:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int32_t *)value = env->regs[R_EDX];
            break;
        case UC_X86_REG_DX:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DH:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DL:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDX]);
            break;
        case UC_X86_REG_ESP:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(int32_t *)value = env->regs[R_ESP];
            break;
        case UC_X86_REG_SP:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(int16_t *)value = READ_WORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_EBP:
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(int32_t *)value = env->regs[R_EBP];
            break;
        case UC_X86_REG_BP:

            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(int16_t *)value = READ_WORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_ESI:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(int32_t *)value = env->regs[R_ESI];
            break;
        case UC_X86_REG_SI:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(int16_t *)value = READ_WORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_EDI:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(int32_t *)value = env->regs[R_EDI];
            break;
        case UC_X86_REG_DI:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(int16_t *)value = READ_WORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_EIP:
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &env->eip);
            *(int32_t *)value = env->eip;
            break;
        case UC_X86_REG_IP:
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &env->eip);
            *(int16_t *)value = READ_WORD(env->eip);
            break;
        case UC_X86_REG_CS:
            RegisterName = WHvX64RegisterCs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_CS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_CS].selector;
            break;
        case UC_X86_REG_DS:
            RegisterName = WHvX64RegisterDs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_DS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_DS].selector;
            break;
        case UC_X86_REG_SS:
            RegisterName = WHvX64RegisterSs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_SS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_SS].selector;
            break;
        case UC_X86_REG_ES:
            RegisterName = WHvX64RegisterEs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_ES] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_ES].selector;
            break;
        case UC_X86_REG_FS:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_FS].selector;
            break;
        case UC_X86_REG_GS:
            RegisterName = WHvX64RegisterGs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_GS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_GS].selector;
            break;
        case UC_X86_REG_IDTR:
            RegisterName = WHvX64RegisterIdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->idt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->idt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->idt.base;
            break;
        case UC_X86_REG_GDTR:
            RegisterName = WHvX64RegisterGdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->gdt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->gdt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->gdt.base;
            break;
        case UC_X86_REG_LDTR:
            RegisterName = WHvX64RegisterLdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->ldt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = env->ldt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->ldt.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->ldt.selector;
            ((uc_x86_mmr *)value)->flags = env->ldt.flags;
            break;
        case UC_X86_REG_TR:
            RegisterName = WHvX64RegisterTr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->tr = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = env->tr.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->tr.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->tr.selector;
            ((uc_x86_mmr *)value)->flags = env->tr.flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_read(env, (uc_x86_msr *)value);
            return 0;
            break;
        case UC_X86_REG_MXCSR:
            *(uint32_t *)value = env->mxcsr;
            return 0;
            break;
        case UC_X86_REG_FS_BASE:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(uint32_t *)value = (uint32_t)env->segs[R_FS].base;
            break;
        }
        break;

#ifdef TARGET_X86_64
    case UC_MODE_64:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            RegisterName = WHvX64RegisterCr0 + regid - UC_X86_REG_CR0;
            whpx_get_reg(RegisterName, &env->cr[regid - UC_X86_REG_CR0]);
            *(int64_t *)value = env->cr[regid - UC_X86_REG_CR0];
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            RegisterName = WHvX64RegisterDr0 + regid - UC_X86_REG_DR0;
            // whpx_get_reg(RegisterName, &env->dr[regid - UC_X86_REG_DR0]);
            *(int64_t *)value = env->dr[regid - UC_X86_REG_DR0];
            break;
        case UC_X86_REG_FLAGS:
            *(int16_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EFLAGS:
            *(int32_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_RFLAGS:
            *(int64_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_RAX:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(uint64_t *)value = env->regs[R_EAX];
            break;
        case UC_X86_REG_EAX:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int32_t *)value = READ_DWORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AX:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AH:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AL:
            RegisterName = WHvX64RegisterRax;
            whpx_get_reg(RegisterName, &env->regs[R_EAX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EAX]);
            break;
        case UC_X86_REG_RBX:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(uint64_t *)value = env->regs[R_EBX];
            break;
        case UC_X86_REG_EBX:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int32_t *)value = READ_DWORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BX:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BH:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BL:
            RegisterName = WHvX64RegisterRbx;
            whpx_get_reg(RegisterName, &env->regs[R_EBX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBX]);
            break;
        case UC_X86_REG_RCX:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(uint64_t *)value = env->regs[R_ECX];
            break;
        case UC_X86_REG_ECX:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int32_t *)value = READ_DWORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CX:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int16_t *)value = READ_WORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CH:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CL:
            RegisterName = WHvX64RegisterRcx;
            whpx_get_reg(RegisterName, &env->regs[R_ECX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ECX]);
            break;
        case UC_X86_REG_RDX:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(uint64_t *)value = env->regs[R_EDX];
            break;
        case UC_X86_REG_EDX:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int32_t *)value = READ_DWORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DX:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int16_t *)value = READ_WORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DH:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DL:
            RegisterName = WHvX64RegisterRdx;
            whpx_get_reg(RegisterName, &env->regs[R_EDX]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDX]);
            break;
        case UC_X86_REG_RSP:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(uint64_t *)value = env->regs[R_ESP];
            break;
        case UC_X86_REG_ESP:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(int32_t *)value = READ_DWORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_SP:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(int16_t *)value = READ_WORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_SPL:
            RegisterName = WHvX64RegisterRsp;
            whpx_get_reg(RegisterName, &env->regs[R_ESP]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ESP]);
            break;
        case UC_X86_REG_RBP:
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(uint64_t *)value = env->regs[R_EBP];
            break;
        case UC_X86_REG_EBP:
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(int32_t *)value = READ_DWORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_BP:
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(int16_t *)value = READ_WORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_BPL:
            RegisterName = WHvX64RegisterRbp;
            whpx_get_reg(RegisterName, &env->regs[R_EBP]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBP]);
            break;
        case UC_X86_REG_RSI:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(uint64_t *)value = env->regs[R_ESI];
            break;
        case UC_X86_REG_ESI:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(int32_t *)value = READ_DWORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_SI:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(int16_t *)value = READ_WORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_SIL:
            RegisterName = WHvX64RegisterRsi;
            whpx_get_reg(RegisterName, &env->regs[R_ESI]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ESI]);
            break;
        case UC_X86_REG_RDI:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(uint64_t *)value = env->regs[R_EDI];
            break;
        case UC_X86_REG_EDI:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(int32_t *)value = READ_DWORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_DI:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(int16_t *)value = READ_WORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_DIL:
            RegisterName = WHvX64RegisterRdi;
            whpx_get_reg(RegisterName, &env->regs[R_EDI]);
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDI]);
            break;
        case UC_X86_REG_RIP:
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &env->eip);
            *(uint64_t *)value = env->eip;
            break;
        case UC_X86_REG_EIP:
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &env->eip);
            *(int32_t *)value = READ_DWORD(env->eip);
            break;
        case UC_X86_REG_IP:
            RegisterName = WHvX64RegisterRip;
            whpx_get_reg(RegisterName, &env->eip);
            *(int16_t *)value = READ_WORD(env->eip);
            break;
        case UC_X86_REG_CS:
            RegisterName = WHvX64RegisterCs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_CS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_CS].selector;
            break;
        case UC_X86_REG_DS:
            RegisterName = WHvX64RegisterDs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_DS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_DS].selector;
            break;
        case UC_X86_REG_SS:
            RegisterName = WHvX64RegisterSs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_SS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_SS].selector;
            break;
        case UC_X86_REG_ES:
            RegisterName = WHvX64RegisterEs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_ES] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_ES].selector;
            break;
        case UC_X86_REG_FS:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_FS].selector;
            break;
        case UC_X86_REG_GS:
            RegisterName = WHvX64RegisterGs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_GS] = whpx_seg_h2q(&regvalue);
            *(int16_t *)value = (uint16_t)env->segs[R_GS].selector;
            break;
        case UC_X86_REG_R8:
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &env->regs[8]);
            *(int64_t *)value = READ_QWORD(env->regs[8]);
            break;
        case UC_X86_REG_R8D:
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &env->regs[8]);
            *(int32_t *)value = READ_DWORD(env->regs[8]);
            break;
        case UC_X86_REG_R8W:
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &env->regs[8]);
            *(int16_t *)value = READ_WORD(env->regs[8]);
            break;
        case UC_X86_REG_R8B:
            RegisterName = WHvX64RegisterR8;
            whpx_get_reg(RegisterName, &env->regs[8]);
            *(int8_t *)value = READ_BYTE_L(env->regs[8]);
            break;
        case UC_X86_REG_R9:
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &env->regs[9]);
            *(int64_t *)value = READ_QWORD(env->regs[9]);
            break;
        case UC_X86_REG_R9D:
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &env->regs[9]);
            *(int32_t *)value = READ_DWORD(env->regs[9]);
            break;
        case UC_X86_REG_R9W:
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &env->regs[9]);
            *(int16_t *)value = READ_WORD(env->regs[9]);
            break;
        case UC_X86_REG_R9B:
            RegisterName = WHvX64RegisterR9;
            whpx_get_reg(RegisterName, &env->regs[9]);
            *(int8_t *)value = READ_BYTE_L(env->regs[9]);
            break;
        case UC_X86_REG_R10:
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &env->regs[10]);
            *(int64_t *)value = READ_QWORD(env->regs[10]);
            break;
        case UC_X86_REG_R10D:
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &env->regs[10]);
            *(int32_t *)value = READ_DWORD(env->regs[10]);
            break;
        case UC_X86_REG_R10W:
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &env->regs[10]);
            *(int16_t *)value = READ_WORD(env->regs[10]);
            break;
        case UC_X86_REG_R10B:
            RegisterName = WHvX64RegisterR10;
            whpx_get_reg(RegisterName, &env->regs[10]);
            *(int8_t *)value = READ_BYTE_L(env->regs[10]);
            break;
        case UC_X86_REG_R11:
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &env->regs[11]);
            *(int64_t *)value = READ_QWORD(env->regs[11]);
            break;
        case UC_X86_REG_R11D:
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &env->regs[11]);
            *(int32_t *)value = READ_DWORD(env->regs[11]);
            break;
        case UC_X86_REG_R11W:
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &env->regs[11]);
            *(int16_t *)value = READ_WORD(env->regs[11]);
            break;
        case UC_X86_REG_R11B:
            RegisterName = WHvX64RegisterR11;
            whpx_get_reg(RegisterName, &env->regs[11]);
            *(int8_t *)value = READ_BYTE_L(env->regs[11]);
            break;
        case UC_X86_REG_R12:
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &env->regs[12]);
            *(int64_t *)value = READ_QWORD(env->regs[12]);
            break;
        case UC_X86_REG_R12D:
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &env->regs[12]);
            *(int32_t *)value = READ_DWORD(env->regs[12]);
            break;
        case UC_X86_REG_R12W:
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &env->regs[12]);
            *(int16_t *)value = READ_WORD(env->regs[12]);
            break;
        case UC_X86_REG_R12B:
            RegisterName = WHvX64RegisterR12;
            whpx_get_reg(RegisterName, &env->regs[12]);
            *(int8_t *)value = READ_BYTE_L(env->regs[12]);
            break;
        case UC_X86_REG_R13:
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &env->regs[13]);
            *(int64_t *)value = READ_QWORD(env->regs[13]);
            break;
        case UC_X86_REG_R13D:
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &env->regs[13]);
            *(int32_t *)value = READ_DWORD(env->regs[13]);
            break;
        case UC_X86_REG_R13W:
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &env->regs[13]);
            *(int16_t *)value = READ_WORD(env->regs[13]);
            break;
        case UC_X86_REG_R13B:
            RegisterName = WHvX64RegisterR13;
            whpx_get_reg(RegisterName, &env->regs[13]);
            *(int8_t *)value = READ_BYTE_L(env->regs[13]);
            break;
        case UC_X86_REG_R14:
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &env->regs[14]);
            *(int64_t *)value = READ_QWORD(env->regs[14]);
            break;
        case UC_X86_REG_R14D:
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &env->regs[14]);
            *(int32_t *)value = READ_DWORD(env->regs[14]);
            break;
        case UC_X86_REG_R14W:
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &env->regs[14]);
            *(int16_t *)value = READ_WORD(env->regs[14]);
            break;
        case UC_X86_REG_R14B:
            RegisterName = WHvX64RegisterR14;
            whpx_get_reg(RegisterName, &env->regs[14]);
            *(int8_t *)value = READ_BYTE_L(env->regs[14]);
            break;
        case UC_X86_REG_R15:
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &env->regs[15]);
            *(int64_t *)value = READ_QWORD(env->regs[15]);
            break;
        case UC_X86_REG_R15D:
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &env->regs[15]);
            *(int32_t *)value = READ_DWORD(env->regs[15]);
            break;
        case UC_X86_REG_R15W:
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &env->regs[15]);
            *(int16_t *)value = READ_WORD(env->regs[15]);
            break;
        case UC_X86_REG_R15B:
            RegisterName = WHvX64RegisterR15;
            whpx_get_reg(RegisterName, &env->regs[15]);
            *(int8_t *)value = READ_BYTE_L(env->regs[15]);
            break;
        case UC_X86_REG_IDTR:
            RegisterName = WHvX64RegisterIdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->idt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->idt.limit;
            ((uc_x86_mmr *)value)->base = env->idt.base;
            break;
        case UC_X86_REG_GDTR:
            RegisterName = WHvX64RegisterGdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->gdt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->gdt.limit;
            ((uc_x86_mmr *)value)->base = env->gdt.base;
            break;
        case UC_X86_REG_LDTR:
            RegisterName = WHvX64RegisterLdtr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->ldt = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = env->ldt.limit;
            ((uc_x86_mmr *)value)->base = env->ldt.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->ldt.selector;
            ((uc_x86_mmr *)value)->flags = env->ldt.flags;
            break;
        case UC_X86_REG_TR:
            RegisterName = WHvX64RegisterTr;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->tr = whpx_seg_h2q(&regvalue);
            ((uc_x86_mmr *)value)->limit = env->tr.limit;
            ((uc_x86_mmr *)value)->base = env->tr.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->tr.selector;
            ((uc_x86_mmr *)value)->flags = env->tr.flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_read(env, (uc_x86_msr *)value);
            return 0;
            break;
        case UC_X86_REG_MXCSR:
            *(uint32_t *)value = env->mxcsr;
            return 0;
            break;
        case UC_X86_REG_XMM8:
        case UC_X86_REG_XMM9:
        case UC_X86_REG_XMM10:
        case UC_X86_REG_XMM11:
        case UC_X86_REG_XMM12:
        case UC_X86_REG_XMM13:
        case UC_X86_REG_XMM14:
        case UC_X86_REG_XMM15: {

            float64 *dst = (float64 *)value;
            RegisterName = WHvX64RegisterXmm0 + regid - UC_X86_REG_XMM0;
            whpx_set_reg_value(RegisterName, regvalue);
            ZMMReg *reg = (ZMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
            reg->ZMM_Q(0) = regvalue.Reg128.Low64;
            reg->ZMM_Q(1) = regvalue.Reg128.High64;
            dst[0] = reg->ZMM_Q(0);
            dst[1] = reg->ZMM_Q(1);
        }
        case UC_X86_REG_FS_BASE:
            RegisterName = WHvX64RegisterFs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_FS] = whpx_seg_h2q(&regvalue);
            *(uint64_t *)value = (uint64_t)env->segs[R_FS].base;
            break;
        case UC_X86_REG_GS_BASE:
            RegisterName = WHvX64RegisterGs;
            whpx_get_reg_value(RegisterName, &regvalue);
            env->segs[R_GS] = whpx_seg_h2q(&regvalue);
            *(uint64_t *)value = (uint64_t)env->segs[R_GS].base;
            break;
        }
        break;
#endif
    }

    return;
}
int x86_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                 int count)
{
    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value, uc->mode);
    }

    return 0;
}

/* Returns the address of the next instruction that is about to be executed.
 */
static uint64_t whpx_vcpu_get_pc(CPUState *cpu)
{
    uint64_t ripval = 0;
    whpx_get_reg(WHvX64RegisterRip, &ripval);
    return ripval;
}

static void whpx_translate_cpu_breakpoints(struct whpx_breakpoints *breakpoints,
                                           CPUState *cpu,
                                           int cpu_breakpoint_count)
{
    HOOK_FOREACH_VAR_DECLARE;
    breakpoints->original_addresses =
        g_renew(vaddr, breakpoints->original_addresses, cpu_breakpoint_count);

    breakpoints->original_address_count = cpu_breakpoint_count;

    int max_breakpoints =
        cpu_breakpoint_count +
        (breakpoints->breakpoints ? breakpoints->breakpoints->used : 0);

    struct whpx_breakpoint_collection *new_breakpoints =
        (struct whpx_breakpoint_collection *)g_malloc0(
            sizeof(struct whpx_breakpoint_collection) +
            max_breakpoints * sizeof(struct whpx_breakpoint));

    new_breakpoints->allocated = max_breakpoints;
    new_breakpoints->used = 0;
    int idx = 0;
    struct hook *hook;
    HOOK_FOREACH(cpu->uc, hook, UC_HOOK_CODE)
    {
        if (hook->to_delete == true) {
            continue;
        }
        new_breakpoints->data[idx].state = WHPX_BP_SET_PENDING;
        new_breakpoints->data[idx].address = hook->begin;
        new_breakpoints->data[idx].bptype = 0;

        idx++;
    }
    HOOK_FOREACH(cpu->uc, hook, UC_HOOK_HARDWARE_EXECUTE)
    {
        if (hook->to_delete == true) {
            continue;
        }
        new_breakpoints->data[idx].state = WHPX_BP_SET_PENDING;
        new_breakpoints->data[idx].address = hook->begin;
        if (hook->type & 0xff0000) {
            new_breakpoints->data[idx].bptype = hook->type;
        } else {
            new_breakpoints->data[idx].bptype = 0;
        }
        idx++;
    }
    HOOK_FOREACH(cpu->uc, hook, UC_HOOK_HARDWARE_READ)
    {
        if (hook->to_delete == true) {
            continue;
        }
        new_breakpoints->data[idx].state = WHPX_BP_SET_PENDING;
        new_breakpoints->data[idx].address = hook->begin;
        if (hook->type & 0xff0000) {
            new_breakpoints->data[idx].bptype = hook->type;
        } else {
            new_breakpoints->data[idx].bptype = 0;
        }
        idx++;
    }
    HOOK_FOREACH(cpu->uc, hook, UC_HOOK_HARDWARE_WRITE)
    {
        if (hook->to_delete == true) {
            continue;
        }
        new_breakpoints->data[idx].state = WHPX_BP_SET_PENDING;
        new_breakpoints->data[idx].address = hook->begin;
        if (hook->type & 0xff0000) {
            new_breakpoints->data[idx].bptype = hook->type;
        } else {
            new_breakpoints->data[idx].bptype = 0;
        }
        idx++;
    }
    HOOK_FOREACH(cpu->uc, hook, UC_HOOK_HARDWARE_READWRITE)
    {
        if (hook->to_delete == true) {
            continue;
        }
        new_breakpoints->data[idx].state = WHPX_BP_SET_PENDING;
        new_breakpoints->data[idx].address = hook->begin;
        if (hook->type & 0xff0000) {
            new_breakpoints->data[idx].bptype = hook->type;
        } else {
            new_breakpoints->data[idx].bptype = 0;
        }
        idx++;
    }
    new_breakpoints->used = idx;
    if (breakpoints->breakpoints) {
        // HOOK_FOREACH(cpu->uc, hook, UC_HOOK_CODE)
        for (int j = 0; j < breakpoints->breakpoints->used; j++) {
            bool found = false;
            for (int i = 0; i < new_breakpoints->used; i++) {
                /*
                 * WARNING: This loop has O(N^2) complexity, where N is the
                 * number of breakpoints. It should not be a bottleneck in
                 * real-world scenarios, since it only needs to run once
                 * after the breakpoints have been modified. If this ever
                 * becomes a concern, it can be optimized by storing
                 * high-level breakpoint objects in a tree or hash map.
                 */

                if (new_breakpoints->data[i].address ==
                    breakpoints->breakpoints->data[j].address) {
                    /* There was already a breakpoint at this address. */
                    if (breakpoints->breakpoints->data[j].state ==
                        WHPX_BP_CLEAR_PENDING) {
                        new_breakpoints->data[i].state = WHPX_BP_SET;
                    } else if (breakpoints->breakpoints->data[j].state ==
                               WHPX_BP_SET) {
                        //如果设置了还是设置过的不需要设置
                        // new_breakpoints->data[i].state =
                        // WHPX_BP_SET_PENDING;
                        new_breakpoints->data[i].state = WHPX_BP_SET;
                    } else if (breakpoints->breakpoints->data[j].state ==
                                   WHPX_BP_CLEARED &&
                               new_breakpoints->data[i].state ==
                                   WHPX_BP_SET_PENDING) {
                        //如果已经被清除了不需要重新清除
                        new_breakpoints->data[i].state = WHPX_BP_SET_PENDING;
                        //  new_breakpoints->data[i].state =
                        //  WHPX_BP_CLEARED;
                    } else if (breakpoints->breakpoints->data[j].state ==
                               WHPX_BP_CLEARED) {
                        //如果已经被清除了不需要重新清除
                        // new_breakpoints->data[i].state =
                        // WHPX_BP_SET_PENDING;
                        new_breakpoints->data[i].state = WHPX_BP_CLEARED;
                    } else if (breakpoints->breakpoints->data[j].state ==
                               WHPX_BP_SET) {
                        //如果已经被清除了不需要重新清除
                        // new_breakpoints->data[i].state =
                        // WHPX_BP_SET_PENDING;
                        new_breakpoints->data[i].state = WHPX_BP_SET;
                    }

                    new_breakpoints->data[i].original_instruction =
                        breakpoints->breakpoints->data[j].original_instruction;
                    found = true;
                    break;
                }
            }

            if (!found) {
                /* No WHPX breakpoint at this address. Create one. */
                new_breakpoints->data[new_breakpoints->used].address =
                    breakpoints->breakpoints->data[j].address;
                //如果没找到需要重新清除

                if (breakpoints->breakpoints->data[j].state !=
                    WHPX_BP_CLEARED) {
                    //如果已经被清除了不需要重新清除
                    new_breakpoints->data[new_breakpoints->used].state =
                        WHPX_BP_CLEAR_PENDING;
                }

                new_breakpoints->data[new_breakpoints->used]
                    .original_instruction =
                    breakpoints->breakpoints->data[j].original_instruction;
                new_breakpoints->used++;
                idx++;
            }
        }
    }
    if (breakpoints->breakpoints) {

        g_free(breakpoints->breakpoints);
    }
    breakpoints->breakpoints = new_breakpoints;

    /*breakpoints->breakpoints->allocated = idx;
    breakpoints->breakpoints->used = idx;*/
}
int whpx_config_nested_breakpoint_restore(CPUState *cpu, uintptr_t restorerip)
{
    whpx_state *whpx = &whpx_global;
    struct whpx_breakpoint_collection *breakpoints =
        whpx->breakpoints.breakpoints;
    for (int i = 0; i < breakpoints->used; i++) {
        /* Decide what to do right now based on the last known state. */
        WhpxBreakpointState state = breakpoints->data[i].state;

        if (state == WHPX_BP_SET) {
            //如果是set还是set,单步调试置回来
            if (breakpoints->data[i].address == restorerip) {
                //普通断点模式
                if (cpu->singlestep_enabled == 2 ||
                    cpu->singlestep_enabled == 3) {
                    //如果是非单步模式=2,取消单步模式
                    if (cpu->singlestep_enabled == 2) {
                        cpu->singlestep_enabled = false;
                    } else {
                        cpu->singlestep_enabled = true;
                    }
                    cpu->halted = false;
                    cpu->mem_io_pc = 0;
                    /* Write the breakpoint instruction. */
                    cpu_memory_rw_whpx(cpu, breakpoints->data[i].address,
                                       (void *)&whpx_breakpoint_instruction, 1,
                                       true);
                }
                if (cpu->singlestep_enabled == 4 ||
                    cpu->singlestep_enabled == 5) {
                    //如果是非单步模式=4,取消单步模式
                    if (cpu->singlestep_enabled == 4) {
                        cpu->singlestep_enabled = false;
                    } else {
                        cpu->singlestep_enabled = true;
                    }
                    cpu->halted = false;
                    cpu->mem_io_pc = 0;
                    whpx_apply_hardware_breakpoint(breakpoints, cpu,
                                                   restorerip);
                }
            }
        }
    }
}

int whpx_first_vcpu_starting(CPUState *cpu)
{
    //
    cpu->uc->size_recur_mem = 0;
    cpu->uc->invalid_error = false;
    whpx_state *whpx = &whpx_global;
    whpx_translate_cpu_breakpoints(&whpx->breakpoints, cpu,
                                   cpu->uc->hooks_count[UC_HOOK_CODE_IDX]);
    whpx_apply_breakpoints(whpx->breakpoints.breakpoints, cpu);
    // uint64_t exception_mask = 1UL << WHvX64ExceptionTypeDebugTrapOrFault;
    uint64_t exception_mask =
        RT_BIT_64(WHvX64ExceptionTypeDebugTrapOrFault) |
        RT_BIT_64(WHvX64ExceptionTypeBreakpointTrap) |
        RT_BIT_64(WHvX64ExceptionTypeInvalidOpcodeFault) |
        RT_BIT_64(WHvX64ExceptionTypeGeneralProtectionFault) |
        RT_BIT_64(WHvX64ExceptionTypePageFault) |
        RT_BIT_64(WHvX64ExceptionTypeFloatingPointErrorFault) |
        RT_BIT_64(WHvX64ExceptionTypeAlignmentCheckFault) |
        RT_BIT_64(WHvX64ExceptionTypeMachineCheckAbort) |
        RT_BIT_64(WHvX64ExceptionTypeSimdFloatingPointFault) |
        RT_BIT_64(WHvX64ExceptionTypeDeviceNotAvailableFault) |
        RT_BIT_64(WHvX64ExceptionTypeDoubleFaultAbort) |
        RT_BIT_64(WHvX64ExceptionTypeBoundRangeFault) |
        RT_BIT_64(WHvX64ExceptionTypeOverflowTrap) |
        RT_BIT_64(WHvX64ExceptionTypeDivideErrorFault) |
        RT_BIT_64(WHvX64ExceptionTypeStackFault);
    whpx_set_exception_exit_bitmap(exception_mask);
    if (cpu->singlestep_enabled) {
        return 0;
    }
    return 0;
}

/* Tries to find a breakpoint at the specified address. */
static struct whpx_breakpoint *whpx_lookup_breakpoint_by_addr(uint64_t address)
{
    whpx_state *whpx = &whpx_global;
    int i;

    if (whpx->breakpoints.breakpoints) {
        for (i = 0; i < whpx->breakpoints.breakpoints->used; i++) {
            if (address == whpx->breakpoints.breakpoints->data[i].address) {
                return &whpx->breakpoints.breakpoints->data[i];
            }
        }
    }

    return NULL;
}

void whpx_vcpu_pre_run(CPUState *cpu)
{

    if (cpu->singlestep_enabled) {
        whpx_vcpu_configure_single_stepping(cpu, true, NULL);
    } else {
        whpx_vcpu_configure_single_stepping(cpu, false, NULL);
    }
    DumpRegs();
}
void whpx_vcpu_post_run(CPUState *cpu)
{
    DumpRegs();

    if (cpu->singlestep_enabled) {
        whpx_vcpu_configure_single_stepping(cpu, true, NULL);
    } else {
        whpx_vcpu_configure_single_stepping(cpu, false, NULL);
    }
}

int x86_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  int count)
{

    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    int i;
    int ret;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        ret = reg_write(env, regid, value, uc->mode);
        if (ret) {
            return ret;
        }
        /*switch (uc->mode) {
        default:
            break;
        case UC_MODE_32:
            switch (regid) {
            default:
                break;
            case UC_X86_REG_EIP:
            case UC_X86_REG_IP:
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            }

#ifdef TARGET_X86_64
        case UC_MODE_64:
            switch (regid) {
            default:
                break;
            case UC_X86_REG_RIP:
            case UC_X86_REG_EIP:
            case UC_X86_REG_IP:
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            }
#endif
        }*/
    }

    return 0;
}

static void x86_set_pc(struct uc_struct *uc, uint64_t address)
{
    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    reg_write(env, UC_X86_REG_RIP, &address, uc->mode);
}

static uint64_t x86_get_pc(struct uc_struct *uc)
{
    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    uint64_t address;
    reg_read(env, UC_X86_REG_RIP, &address, uc->mode);
    return address;
}
static void x86_release(void *ctx) {}
void x86_reg_reset(struct uc_struct *uc) {}
static bool x86_stop_interrupt(struct uc_struct *uc, int intno) {}
static bool x86_insn_hook_validate(uint32_t insn_enum) {}
static bool x86_opcode_hook_invalidate(uint32_t op, uint32_t flags) {}

int whpx_handle_mmio(CPUState *cpu, WHV_MEMORY_ACCESS_CONTEXT *ctx)
{
    HRESULT hr;
    X86CPU *x86_cpu = X86_CPU(cpu);
    whpx_vcpu *vcpu = get_whpx_vcpu(x86_cpu);
    WHV_EMULATOR_STATUS emu_status;

    hr = WHvEmulatorTryMmioEmulation(
        vcpu->emulator, cpu, &vcpu->exit_ctx.VpContext, ctx, &emu_status);
    if (FAILED(hr)) {
        printf("WHPX: Failed to parse MMIO access, hr=%08lx", hr);
        return -1;
    }

    if (!emu_status.EmulationSuccessful) {
        printf("WHPX: Failed to emulate MMIO access with"
               " EmulatorReturnStatus: %u",
               emu_status.AsUINT32);
        return -1;
    }

    return 0;
}

int whpx_handle_portio(CPUState *cpu, WHV_X64_IO_PORT_ACCESS_CONTEXT *ctx)
{
    HRESULT hr;
    X86CPU *x86_cpu = X86_CPU(cpu);
    whpx_vcpu *vcpu = get_whpx_vcpu(x86_cpu);
    WHV_EMULATOR_STATUS emu_status;

    hr = WHvEmulatorTryIoEmulation(vcpu->emulator, cpu,
                                   &vcpu->exit_ctx.VpContext, ctx, &emu_status);
    if (FAILED(hr)) {
        printf("WHPX: Failed to parse PortIO access, hr=%08lx", hr);
        return -1;
    }

    if (!emu_status.EmulationSuccessful) {
        printf("WHPX: Failed to emulate PortIO access with"
               " EmulatorReturnStatus: %u",
               emu_status.AsUINT32);
        return -1;
    }

    return 0;
}

static HRESULT CALLBACK
whpx_emu_ioport_callback(void *ctx, WHV_EMULATOR_IO_ACCESS_INFO *IoAccess)
{
    MemTxAttrs attrs = {0};
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = (CPUState *)ctx;
    address_space_rw(&cpu->uc->address_space_io, IoAccess->Port, attrs,
                     &IoAccess->Data, IoAccess->AccessSize,
                     IoAccess->Direction);
    printf("whpx_emu_ioport_callback \r\n");
    return S_OK;
}

static HRESULT CALLBACK
whpx_emu_mmio_callback(void *ctx, WHV_EMULATOR_MEMORY_ACCESS_INFO *ma)
{
    /*cpu_physical_memory_rw(ma->GpaAddress, ma->Data, ma->AccessSize,
                           ma->Direction);*/

    printf("whpx_emu_mmio_callback MemoryAccessGpa at :=> %016llx\r\n",
           ma->GpaAddress);
    return S_OK;
}

static HRESULT CALLBACK whpx_emu_getreg_callback(
    void *ctx, const WHV_REGISTER_NAME *RegisterNames, UINT32 RegisterCount,
    WHV_REGISTER_VALUE *RegisterValues)
{
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = (CPUState *)ctx;

    hr = WHvGetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         RegisterNames, RegisterCount,
                                         RegisterValues);
    if (FAILED(hr)) {
        printf("WHPX: Failed to get virtual processor registers,"
               " hr=%08lx\r\n ",
               hr);
    }
    printf("whpx_emu_getreg_callback \r\n");
    return hr;
}

static HRESULT CALLBACK whpx_emu_setreg_callback(
    void *ctx, const WHV_REGISTER_NAME *RegisterNames, UINT32 RegisterCount,
    const WHV_REGISTER_VALUE *RegisterValues)
{
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = (CPUState *)ctx;

    hr = WHvSetVirtualProcessorRegisters(whpx->partition, whpx->cpu_index,
                                         RegisterNames, RegisterCount,
                                         RegisterValues);
    if (FAILED(hr)) {
        printf("WHPX: Failed to set virtual processor registers,"
               " hr=%08lx\r\n ",
               hr);
    }
    printf("whpx_emu_setreg_callback \r\n");
    /*
     * The emulator just successfully wrote the register state. We clear
     * the
     * dirty state so we avoid the double write on resume of the VP.

     */
    // cpu->vcpu_dirty = false;

    return hr;
}

static HRESULT CALLBACK
whpx_emu_translate_callback(void *ctx, WHV_GUEST_VIRTUAL_ADDRESS Gva,
                            WHV_TRANSLATE_GVA_FLAGS TranslateFlags,
                            WHV_TRANSLATE_GVA_RESULT_CODE *TranslationResult,
                            WHV_GUEST_PHYSICAL_ADDRESS *Gpa)
{
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = (CPUState *)ctx;
    WHV_TRANSLATE_GVA_RESULT res;

    hr = WHvTranslateGva(whpx->partition, cpu->cpu_index, Gva, TranslateFlags,
                         &res, Gpa);
    if (FAILED(hr)) {
        printf("WHPX: Failed to translate GVA, hr=%08lx\r\n", hr);
    } else {
        *TranslationResult = res.ResultCode;
    }
    printf("whpx_emu_translate_callback  Gpa at :=> %016llx, "
           "Gva at :=> %016llx,ResultCode :=> %08x\r\n",
           Gpa, Gva, res.ResultCode);
    return hr;
}

HRESULT whpx_map_gpa_range(void *ctx, uint64_t HostVa, uint64_t *GuestVa,
                           uint64_t size)
{
    HRESULT hr;
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = (CPUState *)ctx;
    WHV_TRANSLATE_GVA_RESULT res;
    uint64_t oldGuestVa = *GuestVa;
    /*hr = WHvMapGpaRange(whpx->partition, HostVa, oldGuestVa, size,
                        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite |
                            WHvMapGpaRangeFlagExecute);*/

    hr = WhSeMapHostToGuestVirtualMemory(whpx, HostVa, GuestVa, size,
                                         WHvMapGpaRangeFlagRead |
                                             WHvMapGpaRangeFlagWrite |
                                             WHvMapGpaRangeFlagExecute);

    if (FAILED(hr)) {
        printf("WHPX: Failed to WHvMapGpaRange, hr=%08lx\r\n", hr);
    }
    if (oldGuestVa != *GuestVa) {
        printf("WHPX: WHvMapGpaRange, %016llx =>%016llx hr=%08x\r\n",
               oldGuestVa, *GuestVa, hr);
    }

    return hr;
}

static const WHV_EMULATOR_CALLBACKS whpx_emu_callbacks = {
    .Size = sizeof(WHV_EMULATOR_CALLBACKS),
    .WHvEmulatorIoPortCallback = whpx_emu_ioport_callback,
    .WHvEmulatorMemoryCallback = whpx_emu_mmio_callback,
    .WHvEmulatorGetVirtualProcessorRegisters = whpx_emu_getreg_callback,
    .WHvEmulatorSetVirtualProcessorRegisters = whpx_emu_setreg_callback,
    .WHvEmulatorTranslateGvaPage = whpx_emu_translate_callback,
};

static int x86_cpus_init(struct uc_struct *uc, const char *cpu_model)
{

    X86CPU *cpu;
    HRESULT hr = S_OK;
    struct whpx_vcpu *vcpu = (whpx_vcpu *)calloc(1, sizeof(*vcpu));
    WHV_CAPABILITY whpx_cap;
    UINT32 whpx_cap_size;
    WHV_PARTITION_PROPERTY prop;
    UINT32 cpuidExitList[] = {1, 0x80000001};
    WHV_CAPABILITY_FEATURES features = {0};
    WHV_PROCESSOR_FEATURES Caps = {0};
    WHV_PROCESSOR_XSAVE_FEATURES CapsXSave = {0};
    whpx_state *whpx = &whpx_global;

    /*
    setuphv(&whpx->partition);
    goto initx86cpu;*/

    hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &whpx_cap,
                          sizeof(whpx_cap), &whpx_cap_size);
    if (FAILED(hr) || !whpx_cap.HypervisorPresent) {
        printf("WHPX: No accelerator found, hr=%08lx", hr);
        exit(0);
        goto error;
    }

    hr = WHvGetCapability(WHvCapabilityCodeFeatures, &features,
                          sizeof(features), NULL);
    if (FAILED(hr)) {
        printf("WHPX: Failed to query capabilities, hr=%08lx", hr);

        goto error;
    }

    hr = WHvGetCapability(WHvCapabilityCodeProcessorFeatures, &Caps,
                          sizeof(Caps), NULL);
    if (FAILED(hr)) {
        printf("WHPX: Failed to query capabilities, hr=%08lx", hr);

        goto error;
    }
    printf("WHPX:WHvCapabilityCodeProcessorFeatures query capabilities, "
           "hr=%08lx",
           hr);
    NEM_LOG_REL_CPU_FEATURE(Sse3Support);
    NEM_LOG_REL_CPU_FEATURE(LahfSahfSupport);
    NEM_LOG_REL_CPU_FEATURE(Ssse3Support);
    NEM_LOG_REL_CPU_FEATURE(Sse4_1Support);
    NEM_LOG_REL_CPU_FEATURE(Sse4_2Support);
    NEM_LOG_REL_CPU_FEATURE(Sse4aSupport);
    NEM_LOG_REL_CPU_FEATURE(XopSupport);
    NEM_LOG_REL_CPU_FEATURE(PopCntSupport);
    NEM_LOG_REL_CPU_FEATURE(Cmpxchg16bSupport);
    NEM_LOG_REL_CPU_FEATURE(Altmovcr8Support);
    NEM_LOG_REL_CPU_FEATURE(LzcntSupport);
    NEM_LOG_REL_CPU_FEATURE(MisAlignSseSupport);
    NEM_LOG_REL_CPU_FEATURE(MmxExtSupport);
    NEM_LOG_REL_CPU_FEATURE(Amd3DNowSupport);
    NEM_LOG_REL_CPU_FEATURE(ExtendedAmd3DNowSupport);
    NEM_LOG_REL_CPU_FEATURE(Page1GbSupport);
    NEM_LOG_REL_CPU_FEATURE(AesSupport);
    NEM_LOG_REL_CPU_FEATURE(PclmulqdqSupport);
    NEM_LOG_REL_CPU_FEATURE(PcidSupport);
    NEM_LOG_REL_CPU_FEATURE(Fma4Support);
    NEM_LOG_REL_CPU_FEATURE(F16CSupport);
    NEM_LOG_REL_CPU_FEATURE(RdRandSupport);
    NEM_LOG_REL_CPU_FEATURE(RdWrFsGsSupport);
    NEM_LOG_REL_CPU_FEATURE(SmepSupport);
    NEM_LOG_REL_CPU_FEATURE(EnhancedFastStringSupport);
    NEM_LOG_REL_CPU_FEATURE(Bmi1Support);
    NEM_LOG_REL_CPU_FEATURE(Bmi2Support);
    // two reserved bits here, see below #1#
    NEM_LOG_REL_CPU_FEATURE(MovbeSupport);
    NEM_LOG_REL_CPU_FEATURE(Npiep1Support);
    NEM_LOG_REL_CPU_FEATURE(DepX87FPUSaveSupport);
    NEM_LOG_REL_CPU_FEATURE(RdSeedSupport);
    NEM_LOG_REL_CPU_FEATURE(AdxSupport);
    NEM_LOG_REL_CPU_FEATURE(IntelPrefetchSupport);
    NEM_LOG_REL_CPU_FEATURE(SmapSupport);
    NEM_LOG_REL_CPU_FEATURE(HleSupport);
    NEM_LOG_REL_CPU_FEATURE(RtmSupport);
    NEM_LOG_REL_CPU_FEATURE(RdtscpSupport);
    NEM_LOG_REL_CPU_FEATURE(ClflushoptSupport);
    NEM_LOG_REL_CPU_FEATURE(ClwbSupport);
    NEM_LOG_REL_CPU_FEATURE(ShaSupport);
    NEM_LOG_REL_CPU_FEATURE(X87PointersSavedSupport);

    hr = WHvGetCapability(WHvCapabilityCodeProcessorXsaveFeatures, &CapsXSave,
                          sizeof(CapsXSave), NULL);
    if (FAILED(hr)) {
        printf("WHPX: Failed to query capabilities, hr=%08lx\r\n", hr);

        goto error;
    }
    printf("WHPX:WHvCapabilityCodeProcessorXsaveFeatures query capabilities, "
           "hr=%08lx\r\n",
           hr);
    NEM_LOG_REL_XSAVE_FEATURE(XsaveSupport);
    NEM_LOG_REL_XSAVE_FEATURE(XsaveoptSupport);
    NEM_LOG_REL_XSAVE_FEATURE(AvxSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx2Support);
    NEM_LOG_REL_XSAVE_FEATURE(FmaSupport);
    NEM_LOG_REL_XSAVE_FEATURE(MpxSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512Support);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512DQSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512CDSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512BWSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512VLSupport);
    NEM_LOG_REL_XSAVE_FEATURE(XsaveCompSupport);
    NEM_LOG_REL_XSAVE_FEATURE(XsaveSupervisorSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Xcr1Support);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512BitalgSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512IfmaSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512VBmiSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512VBmi2Support);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512VnniSupport);
    NEM_LOG_REL_XSAVE_FEATURE(GfniSupport);
    NEM_LOG_REL_XSAVE_FEATURE(VaesSupport);
    NEM_LOG_REL_XSAVE_FEATURE(Avx512VPopcntdqSupport);
    NEM_LOG_REL_XSAVE_FEATURE(VpclmulqdqSupport);

    hr = WHvCreatePartition(&whpx->partition);
    if (FAILED(hr)) {
        printf("WHPX: Failed to create partition, hr=%08lx", hr);

        goto error;
    }

    /*
     * Query the XSAVE capability of the partition. Any error here is
     * not
     * considered fatal.
     */
    hr = WHvGetPartitionProperty(
        whpx->partition, WHvPartitionPropertyCodeProcessorXsaveFeatures,
        &whpx_xsave_cap, sizeof(whpx_xsave_cap), &whpx_cap_size);

    /*
     * Windows version which don't support this property will return with
     * the
     * specific error code.
     */

    if (FAILED(hr) && hr != WHV_E_UNKNOWN_PROPERTY) {
        printf("WHPX: Failed to query XSAVE capability, hr=%08lx", hr);
    }

    if (!whpx_has_xsave()) {
        printf("WHPX: Partition is not XSAVE capable\n");
    }
    // fix WHvPartitionPropertyCodeProcessorXsaveFeatures
    // whpx_xsave_cap.AsUINT64 = 0;
    /*hr = WHvSetPartitionProperty(whpx->partition,
                                 WHvPartitionPropertyCodeProcessorXsaveFeatures,
        &whpx_xsave_cap, whpx_cap_size);

    if (FAILED(hr)) {
        printf("WHPX: Failed to set partition
    WHvPartitionPropertyCodeProcessorXsaveFeatures  hr=%08lx", hr);

        goto error;
    }*/

    memset(&prop, 0, sizeof(WHV_PARTITION_PROPERTY));
    prop.ProcessorCount = 1;
    hr = WHvSetPartitionProperty(whpx->partition,
                                 WHvPartitionPropertyCodeProcessorCount, &prop,
                                 sizeof(WHV_PARTITION_PROPERTY));

    if (FAILED(hr)) {
        printf("WHPX: Failed to set partition core count  hr=%08lx", hr);

        goto error;
    }

    /*
     * Error out if WHP doesn't support apic emulation and user is
     * requiring
     * it.
     */
    if (whpx->kernel_irqchip_required &&
        (!features.LocalApicEmulation ||
         !WHvSetVirtualProcessorInterruptControllerState2)) {
        printf("WHPX: kernel irqchip requested, but unavailable. "
               "Try without kernel-irqchip or with kernel-irqchip=off");

        goto error;
    }

    if (whpx->kernel_irqchip_allowed && features.LocalApicEmulation &&
        WHvSetVirtualProcessorInterruptControllerState2) {
        WHV_X64_LOCAL_APIC_EMULATION_MODE mode =
            WHvX64LocalApicEmulationModeXApic;
        printf("WHPX: setting APIC emulation mode in the hypervisor\n");
        hr = WHvSetPartitionProperty(
            whpx->partition, WHvPartitionPropertyCodeLocalApicEmulationMode,
            &mode, sizeof(mode));
        if (FAILED(hr)) {
            printf("WHPX: Failed to enable kernel irqchip hr=%08lx", hr);
            if (whpx->kernel_irqchip_required) {
                printf("WHPX: kernel irqchip requested, but unavailable");

                goto error;
            }
        } else {
            whpx->apic_in_platform = true;
        }
    }

    /* Register for MSR and CPUID exits */
    memset(&prop, 0, sizeof(WHV_PARTITION_PROPERTY));
    prop.ExtendedVmExits.X64MsrExit = 1;
    prop.ExtendedVmExits.X64CpuidExit = 1;
    prop.ExtendedVmExits.ExceptionExit = 1;
    // prop.ExtendedVmExits.GpaAccessFaultExit = 1;

    if (whpx_apic_in_platform) {
        prop.ExtendedVmExits.X64ApicInitSipiExitTrap = 1;
    }
#

    hr = WHvSetPartitionProperty(whpx->partition,
                                 WHvPartitionPropertyCodeExtendedVmExits, &prop,
                                 sizeof(WHV_PARTITION_PROPERTY));
    if (FAILED(hr)) {
        printf("WHPX: Failed to enable MSR & CPUIDexit, hr=%08lx", hr);

        goto error;
    }

    hr = WHvSetPartitionProperty(
        whpx->partition, WHvPartitionPropertyCodeCpuidExitList, cpuidExitList,
        RTL_NUMBER_OF(cpuidExitList) * sizeof(UINT32));

    if (FAILED(hr)) {
        printf("WHPX: Failed to set partition CpuidExitList hr=%08lx", hr);

        goto error;
    }

    /*
     * We do not want to intercept any exceptions from the guest,
     *
     * until we actually start debugging with gdb.
     */
    whpx->exception_exit_bitmap = -1;

    hr = WHvSetupPartition(whpx->partition);
    if (FAILED(hr)) {
        printf("WHPX: Failed to setup partition, hr=%08lx", hr);

        goto error;
    }

    hr = WHvEmulatorCreateEmulator(&whpx_emu_callbacks, &vcpu->emulator);
    if (FAILED(hr)) {
        printf("WHPX: Failed to setup instruction completion support,"
               " hr=%08lx",
               hr);

        goto error;
    }

    UINT64 freq = 0;
    hr = WHvCreateVirtualProcessor(whpx->partition, whpx->cpu_index, 0);
    if (FAILED(hr)) {
        printf("WHPX: Failed to create a virtual processor,"
               " hr=%08lx",
               hr);
        WHvEmulatorDestroyEmulator(vcpu->emulator);

        goto error;
    }
    /*WHV_REGISTER_VALUE Reg={0};
    Reg.XmmControlStatus.LastFpRdp = 0;
    Reg.XmmControlStatus.XmmStatusControl = 0x1f80;
    Reg.XmmControlStatus.XmmStatusControlMask = 0x0000ffff;
    hr = whpx_set_reg_value(WHvX64RegisterXmmControlStatus, Reg);*/

initx86cpu:
    hr = WhSeInitializeAllocationTracker(whpx);
    if (FAILED(hr)) {
        printf("WHPX: Failed to WhSeInitializeAllocationTracker, hr=%08lx", hr);

        goto error;
    }

    cpu = cpu_x86_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    CPUX86State *env = &(X86_CPU(cpu)->env);

    /*
    if (!env->tsc_khz) {
        hr = WHvGetCapability(WHvCapabilityCodeProcessorClockFrequency,
    &freq, sizeof(freq), NULL); if (hr != WHV_E_UNKNOWN_CAPABILITY) { if
    (FAILED(hr)) { printf("WHPX: Failed to query tsc frequency,
    hr=0x%08lx\n", hr); goto error; } else { env->tsc_khz = freq / 1000; /*
    Hz to KHz #1#
            }
        }
    }

    /*
     * If the vmware cpuid frequency leaf option is set, and we have
     * a valid
     * tsc value, trap the corresponding cpuid's.
     #1#
    if (env->tsc_khz) {
        UINT32 cpuidExitList[] = {1, 0x80000001, 0x40000000, 0x40000010};

        hr = WHvSetPartitionProperty(
            whpx->partition, WHvPartitionPropertyCodeCpuidExitList,
            cpuidExitList, RTL_NUMBER_OF(cpuidExitList) * sizeof(UINT32));

        if (FAILED(hr)) {
            printf("WHPX: Failed to set partition CpuidExitList hr=%08lx",
    hr);

            goto error;
        }
    }
    */

    hr = WhSeInitializeMemoryLayout(whpx);
    if (FAILED(hr)) {
        printf("WHPX: Failed to WhSeInitializeMemoryLayout, hr=%08lx", hr);

        goto error;
    }

    vcpu->interruptable = true;
    // cpu->vcpu_dirty = true;

    cpu->hax_vcpu = vcpu;

    qemu_init_vcpu((CPUState *)cpu);
    whpx_set_xcrs(cpu);
    DumpRegsGlobal();
    printf("x86_cpus_init done ok init Hypervisor Platform\r\n");
    return 0;

error:
    return -1;
}

void tcg_flush_softmmu_tlb(struct uc_struct *uc) {}

static void page_table_config_init(struct uc_struct *uc)
{
    uint32_t v_l1_bits;

    assert(TARGET_PAGE_BITS);
    /* The bits remaining after N lower levels of page tables.  */
    v_l1_bits = (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % V_L2_BITS;
    if (v_l1_bits < V_L1_MIN_BITS) {
        v_l1_bits += V_L2_BITS;
    }

    uc->v_l1_size = 1 << v_l1_bits;
    uc->v_l1_shift = L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - v_l1_bits;
    uc->v_l2_levels = uc->v_l1_shift / V_L2_BITS - 1;

    assert(v_l1_bits <= V_L1_MAX_BITS);
    assert(uc->v_l1_shift % V_L2_BITS == 0);
    assert(uc->v_l2_levels >= 0);
}

static void page_init(struct uc_struct *uc)
{
    page_size_init(uc);
    page_table_config_init(uc);
}

X86CPU *cpu_x86_init(struct uc_struct *uc)
{

    X86CPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    X86CPUClass *xcc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    if (uc->cpu_model == INT_MAX) {
#ifdef TARGET_X86_64
        uc->cpu_model = UC_CPU_X86_QEMU64; // qemu64
#else
        uc->cpu_model = UC_CPU_X86_QEMU32; // qemu32
#endif
    } /*else if (uc->cpu_model >= ARRAY_SIZE(builtin_x86_defs)) {
        free(cpu);
        return NULL;
    }*/

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;
    cpu->env.cpuid_level_func7 = UINT32_MAX;
    cpu->env.cpuid_level = UINT32_MAX;
    cpu->env.cpuid_xlevel = UINT32_MAX;
    cpu->env.cpuid_xlevel2 = UINT32_MAX;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init X86CPUClass */
    // x86_cpu_common_class_init(uc, cc, NULL);

    /* init X86CPUModel */
    /* Ignore X86CPUVersion, X86CPUVersionDefinition.
       we do not need so many cpu types and their property.
       version: more typename. x86_cpu_versioned_model_name().
       alias: more property. */
    xcc = &cpu->cc;
    xcc->model = calloc(1, sizeof(*(xcc->model)));
    if (xcc->model == NULL) {
        free(cpu);
        return NULL;
    }

    xcc->model->version = CPU_VERSION_AUTO;
    // xcc->model->cpudef = &builtin_x86_defs[uc->cpu_model];

    /*
    if (xcc->model->cpudef == NULL) {
        free(xcc->model);
        free(cpu);
        return NULL;
    }*/

    /*
    /* init CPUState #1#
    cpu_common_initfn(uc, cs);

    /* init X86CPU #1#
    x86_cpu_initfn(uc, cs);

    /* realize X86CPU #1#
    x86_cpu_realizefn(uc, cs);
    */

    // init address space
    // cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    /* realize CPUState */

    return cpu;
}
static void uc_invalidate_tb(struct uc_struct *uc, uint64_t start_addr,
                             size_t len)
{
}
static uc_err uc_gen_tb(struct uc_struct *uc, uint64_t addr, uc_tb *out_tb) {}
static void uc_tb_flush(struct uc_struct *uc)
{
    tb_flush(uc->cpu);
}
void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size)
{
    page_init(uc);

    uc->uc_invalidate_tb = uc_invalidate_tb;
    uc->uc_gen_tb = uc_gen_tb;
    uc->tb_flush = uc_tb_flush;
}
MemoryRegion *memory_map_guest(struct uc_struct *uc, hwaddr *begin, size_t size,
                               uint32_t perms);
MemoryRegion *memory_map_ptr_guest(struct uc_struct *uc, hwaddr *begin,
                                   size_t size, uint32_t perms, void *ptr);

static inline void uc_common_init_whpx(struct uc_struct *uc)
{
    uc->write_mem = cpu_physical_mem_write;
    uc->read_mem = cpu_physical_mem_read;
    uc->tcg_exec_init = tcg_exec_init;
    uc->cpu_exec_init_all = cpu_exec_init_all;
    uc->vm_start = vm_start;
    uc->memory_map = memory_map;
    uc->memory_map_ptr = memory_map_ptr;
    uc->memory_map_guest = memory_map_guest;
    uc->memory_map_ptr_guest = memory_map_ptr_guest;
    uc->memory_unmap = memory_unmap;
    uc->readonly_mem = memory_region_set_readonly;
    uc->target_page = target_page_init;
    uc->softfloat_initialize = softfloat_init;
    uc->tcg_flush_tlb = tcg_flush_softmmu_tlb;
    uc->memory_map_io = memory_map_io;

    /*if (!uc->release)
        uc->release = release_common;*/
}

DEFAULT_VISIBILITY
void x86_whpx_uc_init(struct uc_struct *uc)
{
    uc->reg_read = x86_reg_read;
    uc->reg_write = x86_reg_write;
    uc->reg_reset = x86_reg_reset;
    uc->release = x86_release;
    uc->set_pc = x86_set_pc;
    uc->get_pc = x86_get_pc;
    uc->stop_interrupt = x86_stop_interrupt;
    uc->insn_hook_validate = x86_insn_hook_validate;
    uc->opcode_hook_invalidate = x86_opcode_hook_invalidate;
    uc->cpus_init = x86_cpus_init;
    uc->cpu_context_size = offsetof(CPUX86State, retaddr);
    uc_common_init_whpx(uc);
}
