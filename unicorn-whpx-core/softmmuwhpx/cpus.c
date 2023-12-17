/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysemu/tcg.h"
#include "sysemu/cpus.h"
#include "qemu/bitmap.h"
#include "tcg/tcg.h"
#include "exec/tb-hash.h"
#include "accel/tcg/translate-all.h"

#include "uc_priv.h"
#include "WinHvDefs.hpp"

#define DumpExitReason(name)                                                   \
    printf("ExitReason:=> " #name ",Run from rip=%016llx to %016llx\r\n",      \
           ripvalold, ripval)
#define DumpExceptionType(name)                                                \
    if (vcpu->exit_ctx.VpException.ExceptionType == name) {                    \
        printf("VpException.ExceptionType:=> " #name                           \
               " ,ExceptionTypeCode = %08x ,ExceptionParameter = "             \
               "%016llx,retry\r\n",                                            \
               vcpu->exit_ctx.VpException.ExceptionType,                       \
               vcpu->exit_ctx.VpException.ExceptionParameter);                 \
    }

extern const uint8_t whpx_breakpoint_instruction;
uint64_t whpx_hardware_breakpoint_config_single_step(CPUState *cpu,
                                                     uintptr_t addr);
uint64_t whpx_check_hardware_breakpoint();
int whpx_handle_mmio(CPUState *cpu, WHV_MEMORY_ACCESS_CONTEXT *ctx);
int whpx_handle_portio(CPUState *cpu, WHV_X64_IO_PORT_ACCESS_CONTEXT *ctx);
int whpx_first_vcpu_starting(CPUState *cpu);
int whpx_config_nested_breakpoint_restore(CPUState *cpu, uintptr_t restorerip);
void dump_stack_ret_addr(uint8_t *rspaddr, uintptr_t rspval, ULONG difflen);
int64_t cpu_icount_to_ns(int64_t icount)
{
    // return icount << atomic_read(&timers_state.icount_time_shift);
    // from configure_icount(QemuOpts *opts, Error **errp)
    /* 125MIPS seems a reasonable initial guess at the guest speed.
       It will be corrected fairly quickly anyway.  */
    // timers_state.icount_time_shift = 3;

    return icount << 3;
}

bool cpu_is_stopped(CPUState *cpu)
{
    return cpu->stopped;
}

/* return the time elapsed in VM between vm_start and vm_stop.  Unless
 * icount is active, cpu_get_ticks() uses units of the host CPU cycle
 * counter.
 */
int64_t cpu_get_ticks(void)
{
    return cpu_get_host_ticks();
}

/* Return the monotonic time elapsed in VM, i.e.,
 * the time between vm_start and vm_stop
 */
int64_t cpu_get_clock(void)
{
    return get_clock();
}

static bool cpu_can_run(CPUState *cpu)
{
    if (cpu->stop) {
        return false;
    }
    if (cpu_is_stopped(cpu)) {
        return false;
    }
    return cpu->uc->stop_request == false;
    ;
}

static void cpu_handle_guest_debug(CPUState *cpu)
{
    cpu->stopped = true;
}
void whpx_vcpu_pre_run(CPUState *cpu);
void whpx_vcpu_post_run(CPUState *cpu);

static int whpx_dump_stack(struct uc_struct *uc)
{
    char buf[0x1000];
    size_t len = 0x1000;
    CPUState *cpu = uc->cpu;
    X86CPU *x86_cpu = X86_CPU(cpu);
    uint64_t ripval = 0;
    whpx_get_reg(WHvX64RegisterRsp, &ripval);
    // len = 0x100;
    cpu_memory_rw_whpx(cpu, ripval, buf, len, false);
    dumpbuf(buf, 0x100);
    dump_stack_ret_addr(buf, ripval, len);
}

static int whpx_cpu_exec(struct uc_struct *uc)
{
    uc_tb cur_tb, prev_tb;
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    char buf[0x1000];
    int r;
    size_t len = 0x1000;
    bool finish = false;
    whpx_state *whpx = &whpx_global;
    CPUState *cpu = uc->cpu;
    X86CPU *x86_cpu = X86_CPU(cpu);
    whpx_vcpu *vcpu = get_whpx_vcpu(x86_cpu);
    while (!uc->exit_request) {

        // qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
        //                  (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);
        if (cpu_can_run(cpu)) {

            whpx_vcpu_pre_run(cpu);
            uc->quit_request = false;
            uint64_t ripvalold = 0;
            uint64_t ripval = 0;
            whpx_get_reg(WHvX64RegisterRip, &ripvalold);
            cpu_memory_rw_whpx(cpu, ripvalold, buf, 0x1000, false);
            printf("WHPX:whpx_vcpu_pre_run from rip=%016llx\r\n", ripvalold);
            r = WHvRunVirtualProcessor(whpx->partition, whpx->cpu_index,
                                       &vcpu->exit_ctx, sizeof(vcpu->exit_ctx));
            if (FAILED(r)) {
                printf("WHPX: Failed to WHvRunVirtualProcessor,"
                       " hr=%08lx\r\n",
                       r);
                uc->exit_request = true;
                break;
            }
            whpx_get_reg(WHvX64RegisterRip, &ripval);
            whpx_vcpu_post_run(cpu);
            printf("WHPX:whpx_vcpu_post_run from rip=%016llx\r\n", ripval);
            /*printf(
                "WHPX:WHvRunVirtualProcessor from rip=%016llx to
               rip=%016llx\r\n", ripvalold, ripval);*/

            // quit current TB but continue emulating?
            if (uc->quit_request) {
                // reset stop_request
                uc->stop_request = false;

                // resume cpu
                // cpu->halted = 0;
                cpu->exit_request = 0;
                cpu->exception_index = -1;
                cpu_resume(cpu);
            } else if (uc->stop_request) {
                // printf(">>> got STOP request!!!\n");
                finish = true;
                break;
            }

            // save invalid memory access error & quit
            if (uc->invalid_error) {
                // printf(">>> invalid memory accessed, STOP = %u!!!\n",
                // env->invalid_error);
                finish = true;
                break;
            }
            if (cpu->uc->size_recur_mem > 1) {
                printf("WHPX:whpx_vcpu_post_run size_recur_mem reach max "
                       "count=%016llx fatal error tear down\r\n",
                       cpu->uc->size_recur_mem);
                finish = true;
                break;
            }

            // printf(">>> stop with r = %x, HLT=%x\n", r, EXCP_HLT);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
                break;
            }
            if (r == EXCP_HLT) {
                // printf(">>> got HLT!!!\n");
                finish = true;
                break;
            }

            switch (vcpu->exit_ctx.ExitReason) {
            case WHvRunVpExitReasonMemoryAccess:
                DumpExitReason(WHvRunVpExitReasonMemoryAccess);

                uint64_t MemoryAccessGva = vcpu->exit_ctx.MemoryAccess.Gva;
                if (cpu->uc->size_recur_mem == 0) {
                    whpx_dump_stack(uc);
                }
                WhSeFindAllocationGvaByGpa(
                    whpx, vcpu->exit_ctx.MemoryAccess.Gpa, &ripval);
                printf("try to fetch MemoryAccess times %d, Gpa :=> "
                       "%016llx,Gva :=> %016llx,Solved Gva :=> %016llx\r\n",
                       cpu->uc->size_recur_mem, vcpu->exit_ctx.MemoryAccess.Gpa,
                       vcpu->exit_ctx.MemoryAccess.Gva, ripval);
                cpu->uc->size_recur_mem++;
                if (whpx_handle_mmio(cpu, &vcpu->exit_ctx.MemoryAccess) != 0) {
                    printf("whpx_handle_mmio failed from "
                           "gpa=%016llx,gva=%016llx\r\n",
                           vcpu->exit_ctx.MemoryAccess.Gpa,
                           vcpu->exit_ctx.MemoryAccess.Gva);
                    //这个把他置位如果还有错就终止
                    uc->invalid_error = true;
                } else {
                    printf("whpx_handle_mmio EmulationSuccessful from "
                           "gpa=%016llx,gva=%016llx\r\n",
                           vcpu->exit_ctx.MemoryAccess.Gpa,
                           vcpu->exit_ctx.MemoryAccess.Gva);
                    if (uc_mem_read_hook(cpu->uc, MemoryAccessGva, len) ==
                        UC_ERR_OK) {

                        printf("fix:MemoryAccess from buf=%016llx\r\n",
                               vcpu->exit_ctx.MemoryAccess.Gva);
                        break;

                    } else {

                        printf("ERROR:MemoryAccess from buf=%016llx\r\n",
                               vcpu->exit_ctx.MemoryAccess.Gva);

                        break;
                    }
                }
                finish = false;
                break;

            case WHvRunVpExitReasonX64IoPortAccess:
                DumpExitReason(WHvRunVpExitReasonX64IoPortAccess);

                if (whpx_handle_portio(cpu, &vcpu->exit_ctx.IoPortAccess)) {
                    finish = true;
                }

                break;
                ;
            case WHvRunVpExitReasonException: {
                DumpExitReason(WHvRunVpExitReasonException);
                if ((vcpu->exit_ctx.VpException.ExceptionType ==
                     WHvX64ExceptionTypeDebugTrapOrFault) &&
                    (vcpu->exit_ctx.VpException.InstructionByteCount >= 1) &&
                    (vcpu->exit_ctx.VpException.InstructionBytes[0] ==
                     whpx_breakpoint_instruction)) {
                    /* Stopped at a software breakpoint. */
                    cpu->exception_index = EXCP_DEBUG;
                    printf("whpx_breakpoint_instruction=%016llx\r\n", ripval);
                } else if ((vcpu->exit_ctx.VpException.ExceptionType ==
                            WHvX64ExceptionTypeDebugTrapOrFault) &&
                           cpu->singlestep_enabled) {
                    /*
                     * Just finished stepping over a breakpoint, but the
                     * gdb does not expect us to do single-stepping.
                     * Don't do anything special.
                     */
                    cpu->exception_index = EXCP_INTERRUPT;
                    if (cpu->mem_io_pc) {
                        printf(
                            "whpx_config_nested_breakpoint_restore=%016llx\r\n",
                            cpu->mem_io_pc);
                        whpx_config_nested_breakpoint_restore(cpu,
                                                              cpu->mem_io_pc);

                        //虚拟的恢复断点模式,如果之前是虚拟单步执行模式,如果之前是真实单步执行模式还是走原来逻辑
                        if (!cpu->singlestep_enabled) {

                            printf("whpx_config_nested_breakpoint_restore "
                                   "resume normal debug=%"
                                   "016llx\r\n",
                                   cpu->mem_io_pc);
                            finish == false;
                            break;
                        } else {
                            //如果之前还是trap模式中断
                            printf("WHvX64ExceptionTypeDebugTrapOrFault org "
                                   "step mode=%"
                                   "016llx\r\n",
                                   ripval);
                            finish = true;
                        }
                        //如果之前是单步模式分发到callback
                    } else {
                        printf(
                            "WHvX64ExceptionTypeDebugTrapOrFault=%016llx\r\n",
                            ripval);
                        finish = true;
                    }
                } else if (vcpu->exit_ctx.VpException.ExceptionType ==
                           WHvX64ExceptionTypeDebugTrapOrFault) {

                    uint64_t addrhw = whpx_check_hardware_breakpoint();
                    printf("whpx_check_hardware_breakpoint "
                           "rip=%016llx,addr=%016llx \r\n",
                           ripval, addrhw);
                    if (addrhw) {
                        cpu->mem_io_pc = addrhw;
                        /*whpx_hardware_breakpoint_config_single_step(cpu,
                                                                    addrhw);*/
                        HOOK_FOREACH(uc, hook, UC_HOOK_HARDWARE_EXECUTE)
                        {

                            if (hook->to_delete) {
                                continue;
                            }

                            if (HOOK_BOUND_CHECK(hook, (uint64_t)addrhw)) {
                                ((uc_cb_hookcode_t)hook->callback)(
                                    uc, addrhw, 1, hook->user_data);
                            }
                        }

                        HOOK_FOREACH(uc, hook, UC_HOOK_HARDWARE_READ)
                        {

                            if (hook->to_delete) {
                                continue;
                            }

                            if (HOOK_BOUND_CHECK(hook, (uint64_t)addrhw)) {
                                ((uc_cb_hookcode_t)hook->callback)(
                                    uc, addrhw, 1, hook->user_data);
                            }
                        }

                        HOOK_FOREACH(uc, hook, UC_HOOK_HARDWARE_WRITE)
                        {

                            if (hook->to_delete) {
                                continue;
                            }

                            if (HOOK_BOUND_CHECK(hook, (uint64_t)addrhw)) {
                                ((uc_cb_hookcode_t)hook->callback)(
                                    uc, addrhw, 1, hook->user_data);
                            }
                        }

                        HOOK_FOREACH(uc, hook, UC_HOOK_HARDWARE_READWRITE)
                        {

                            if (hook->to_delete) {
                                continue;
                            }

                            if (HOOK_BOUND_CHECK(hook, (uint64_t)addrhw)) {
                                ((uc_cb_hookcode_t)hook->callback)(
                                    uc, addrhw, 1, hook->user_data);
                            }
                        }

                        if (uc->stop_request == true) {

                            printf("stop_request =%016llx\r\n", ripval);
                            finish = true;
                        }
                        break;
                    }

                } else {
                    /* Another exception or debug event. Report it to GDB.
                     */
                    uintptr_t ripvalsave = ripval;
                    if (cpu->uc->size_recur_mem == 0) {
                        whpx_dump_stack(uc);
                    }
                    cpu->exception_index = EXCP_DEBUG;
                    if (ripvalold == ripvalsave) {
                        printf("WHvX64ExceptionFatalError=%016llx\r\n", ripval);
                        if (cpu->uc->size_recur_mem > 0) {
                            whpx_dump_stack(uc);
                        }
                        cpu->uc->size_recur_mem++;
                    }
                    DumpExceptionType(WHvX64ExceptionTypeDivideErrorFault);
                    DumpExceptionType(WHvX64ExceptionTypeDebugTrapOrFault);
                    DumpExceptionType(WHvX64ExceptionTypeBreakpointTrap);
                    DumpExceptionType(WHvX64ExceptionTypeOverflowTrap);
                    DumpExceptionType(WHvX64ExceptionTypeBoundRangeFault);
                    DumpExceptionType(WHvX64ExceptionTypeInvalidOpcodeFault);
                    DumpExceptionType(
                        WHvX64ExceptionTypeDeviceNotAvailableFault);
                    DumpExceptionType(WHvX64ExceptionTypeDoubleFaultAbort);
                    DumpExceptionType(
                        WHvX64ExceptionTypeInvalidTaskStateSegmentFault);
                    DumpExceptionType(
                        WHvX64ExceptionTypeSegmentNotPresentFault);
                    DumpExceptionType(WHvX64ExceptionTypeStackFault);
                    DumpExceptionType(
                        WHvX64ExceptionTypeGeneralProtectionFault);
                    DumpExceptionType(WHvX64ExceptionTypePageFault);
                    DumpExceptionType(
                        WHvX64ExceptionTypeFloatingPointErrorFault);
                    DumpExceptionType(WHvX64ExceptionTypeAlignmentCheckFault);
                    DumpExceptionType(WHvX64ExceptionTypeMachineCheckAbort);
                    DumpExceptionType(
                        WHvX64ExceptionTypeSimdFloatingPointFault);

                    if (vcpu->exit_ctx.VpException.ExceptionType ==
                            WHvX64ExceptionTypePageFault &&
                        vcpu->exit_ctx.VpException.ExceptionParameter >
                            0x100000) {
                        // len=0x10000
                        if (uc_mem_read_hook(
                                cpu->uc,
                                vcpu->exit_ctx.VpException.ExceptionParameter,
                                0x1000) == UC_ERR_OK) {
                            // cpu->uc->size_recur_mem--;
                            printf(
                                "fix:MemoryAccess from "
                                "buf=%016llx,retry\r\n",
                                vcpu->exit_ctx.VpException.ExceptionParameter);
                            break;
                        } else {
                            printf(
                                "WHvX64ExceptionFatalError "
                                "uc_mem_read_hook unreachable memory "
                                "address=%016llx\r\n",
                                vcpu->exit_ctx.VpException.ExceptionParameter);
                            exit(0);
                        }
                    } else {
                        printf("WHvX64ExceptionFatalError unreachable memory "
                               "address=%016llx\r\n",
                               vcpu->exit_ctx.VpException.ExceptionParameter);
                        exit(0);
                    }
                }

                HOOK_FOREACH(uc, hook, UC_HOOK_CODE)
                {

                    if (hook->to_delete) {
                        continue;
                    }

                    if (HOOK_BOUND_CHECK(hook, (uint64_t)ripval)) {
                        ((uc_cb_hookcode_t)hook->callback)(uc, ripval, 1,
                                                           hook->user_data);
                    }
                }

                if (uc->stop_request == true) {

                    printf("stop_request =%016llx\r\n", ripval);
                    finish = true;
                }
                break;
            }
            case WHvRunVpExitReasonNone:
            case WHvRunVpExitReasonUnrecoverableException:
            case WHvRunVpExitReasonInvalidVpRegisterValue:
            case WHvRunVpExitReasonUnsupportedFeature:
            default: {
                DumpExitReason(WHvRunVpExitReasonUnrecoverableException);
                cpu->uc->size_recur_mem++;
                finish = true;
                break;
            }
            }
            if (finish == true) {
                break;
            }

        } else if (cpu->stop || cpu->stopped) {
            // printf(">>> got stopped!!!\n");
            break;
        }
    }
    uc->exit_request = 0;
    uc->cpu->exit_request = 0;
    // uc->cpu->icount_decr_ptr->u16.high = 0;
    uc->cpu->tcg_exit_req = 0;

    return finish;
}

void cpu_resume(CPUState *cpu)
{
    cpu->stop = false;
    cpu->stopped = false;
}

static void qemu_tcg_init_vcpu(CPUState *cpu)
{
    /*
     * Initialize TCG regions--once. Now is a good time, because:
     * (1) TCG's init context, prologue and target globals have been set up.
     * (2) qemu_tcg_mttcg_enabled() works now (TCG init code runs before the
     *     -accel flag is processed, so the check doesn't work then).
     */
    //  tcg_region_init(cpu->uc->tcg_ctx);

    cpu->created = true;
}

void qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = 1;
    cpu->nr_threads = 1;
    cpu->stopped = true;

    qemu_tcg_init_vcpu(cpu);

    return;
}

void cpu_stop_current(struct uc_struct *uc)
{
    if (uc->cpu) {
        uc->cpu->stop = false;
        uc->cpu->stopped = true;
        cpu_exit(uc->cpu);
    }
}

static inline gboolean uc_exit_invalidate_iter(gpointer key, gpointer val,
                                               gpointer data)
{
    uint64_t exit = *((uint64_t *)key);
    uc_engine *uc = (uc_engine *)data;

    if (exit != 0) {
        // Unicorn: Why addr - 1?
        //
        // 0: INC ecx
        // 1: DEC edx <--- We put exit here, then the range of TB is [0, 1)
        //
        // While tb_invalidate_phys_range invalides [start, end)
        //
        // This function is designed to used with g_tree_foreach
        if (uc->uc_invalidate_tb) {
            uc->uc_invalidate_tb(uc, exit - 1, 1);
        }
    }

    return false;
}

void resume_all_vcpus(struct uc_struct *uc)
{
    CPUState *cpu = uc->cpu;
    cpu->halted = 0;
    cpu->exit_request = 0;
    cpu->exception_index = -1;
    whpx_first_vcpu_starting(cpu);
    cpu_resume(cpu);
    /* static void qemu_tcg_cpu_loop(struct uc_struct *uc) */
    cpu->created = true;
    while (true) {
        if (whpx_cpu_exec(uc)) {
            break;
        }
    }

    // clear the cache of the exits address, since the generated code
    // at that address is to exit emulation, but not for the instruction there.
    // if we dont do this, next time we cannot emulate at that address
    if (uc->use_exits) {
        g_tree_foreach(uc->ctl_exits, uc_exit_invalidate_iter, (void *)uc);
    } else {
        uc_exit_invalidate_iter((gpointer)&uc->exits[uc->nested_level - 1],
                                NULL, (gpointer)uc);
    }

    cpu->created = false;
}

void vm_start(struct uc_struct *uc)
{
    resume_all_vcpus(uc);
}
