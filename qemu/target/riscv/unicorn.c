/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qc_priv.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "cpu_bits.h"
#include <qnicorn/riscv.h>
#include "unicorn.h"

static int csrno_map[] = {
    CSR_USTATUS,       CSR_UIE,           CSR_UTVEC,         CSR_USCRATCH,
    CSR_UEPC,          CSR_UCAUSE,        CSR_UTVAL,         CSR_UIP,
    CSR_FFLAGS,        CSR_FRM,           CSR_FCSR,          CSR_CYCLE,
    CSR_TIME,          CSR_INSTRET,       CSR_HPMCOUNTER3,   CSR_HPMCOUNTER4,
    CSR_HPMCOUNTER5,   CSR_HPMCOUNTER6,   CSR_HPMCOUNTER7,   CSR_HPMCOUNTER8,
    CSR_HPMCOUNTER9,   CSR_HPMCOUNTER10,  CSR_HPMCOUNTER11,  CSR_HPMCOUNTER12,
    CSR_HPMCOUNTER13,  CSR_HPMCOUNTER14,  CSR_HPMCOUNTER15,  CSR_HPMCOUNTER16,
    CSR_HPMCOUNTER17,  CSR_HPMCOUNTER18,  CSR_HPMCOUNTER19,  CSR_HPMCOUNTER20,
    CSR_HPMCOUNTER21,  CSR_HPMCOUNTER22,  CSR_HPMCOUNTER23,  CSR_HPMCOUNTER24,
    CSR_HPMCOUNTER25,  CSR_HPMCOUNTER26,  CSR_HPMCOUNTER27,  CSR_HPMCOUNTER28,
    CSR_HPMCOUNTER29,  CSR_HPMCOUNTER30,  CSR_HPMCOUNTER31,  CSR_CYCLEH,
    CSR_TIMEH,         CSR_INSTRETH,      CSR_HPMCOUNTER3H,  CSR_HPMCOUNTER4H,
    CSR_HPMCOUNTER5H,  CSR_HPMCOUNTER6H,  CSR_HPMCOUNTER7H,  CSR_HPMCOUNTER8H,
    CSR_HPMCOUNTER9H,  CSR_HPMCOUNTER10H, CSR_HPMCOUNTER11H, CSR_HPMCOUNTER12H,
    CSR_HPMCOUNTER13H, CSR_HPMCOUNTER14H, CSR_HPMCOUNTER15H, CSR_HPMCOUNTER16H,
    CSR_HPMCOUNTER17H, CSR_HPMCOUNTER18H, CSR_HPMCOUNTER19H, CSR_HPMCOUNTER20H,
    CSR_HPMCOUNTER21H, CSR_HPMCOUNTER22H, CSR_HPMCOUNTER23H, CSR_HPMCOUNTER24H,
    CSR_HPMCOUNTER25H, CSR_HPMCOUNTER26H, CSR_HPMCOUNTER27H, CSR_HPMCOUNTER28H,
    CSR_HPMCOUNTER29H, CSR_HPMCOUNTER30H, CSR_HPMCOUNTER31H, CSR_MCYCLE,
    CSR_MINSTRET,      CSR_MCYCLEH,       CSR_MINSTRETH,     CSR_MVENDORID,
    CSR_MARCHID,       CSR_MIMPID,        CSR_MHARTID,       CSR_MSTATUS,
    CSR_MISA,          CSR_MEDELEG,       CSR_MIDELEG,       CSR_MIE,
    CSR_MTVEC,         CSR_MCOUNTEREN,    CSR_MSTATUSH,      CSR_MUCOUNTEREN,
    CSR_MSCOUNTEREN,   CSR_MHCOUNTEREN,   CSR_MSCRATCH,      CSR_MEPC,
    CSR_MCAUSE,        CSR_MTVAL,         CSR_MIP,           CSR_MBADADDR,
    CSR_SSTATUS,       CSR_SEDELEG,       CSR_SIDELEG,       CSR_SIE,
    CSR_STVEC,         CSR_SCOUNTEREN,    CSR_SSCRATCH,      CSR_SEPC,
    CSR_SCAUSE,        CSR_STVAL,         CSR_SIP,           CSR_SBADADDR,
    CSR_SPTBR,         CSR_SATP,          CSR_HSTATUS,       CSR_HEDELEG,
    CSR_HIDELEG,       CSR_HIE,           CSR_HCOUNTEREN,    CSR_HTVAL,
    CSR_HIP,           CSR_HTINST,        CSR_HGATP,         CSR_HTIMEDELTA,
    CSR_HTIMEDELTAH,
};

RISCVCPU *cpu_riscv_init(struct qc_struct *uc);

static void riscv_set_pc(struct qc_struct *uc, uint64_t address)
{
    RISCV_CPU(uc->cpu)->env.pc = address;
}

static void riscv_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    RISCVCPU *cpu = (RISCVCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }
}

void riscv_reg_reset(struct qc_struct *uc) {}

static void reg_read(CPURISCVState *env, unsigned int regid, void *value)
{
    switch (regid) {
    case QC_RISCV_REG_X0:
    case QC_RISCV_REG_X1:
    case QC_RISCV_REG_X2:
    case QC_RISCV_REG_X3:
    case QC_RISCV_REG_X4:
    case QC_RISCV_REG_X5:
    case QC_RISCV_REG_X6:
    case QC_RISCV_REG_X7:
    case QC_RISCV_REG_X8:
    case QC_RISCV_REG_X9:
    case QC_RISCV_REG_X10:
    case QC_RISCV_REG_X11:
    case QC_RISCV_REG_X12:
    case QC_RISCV_REG_X13:
    case QC_RISCV_REG_X14:
    case QC_RISCV_REG_X15:
    case QC_RISCV_REG_X16:
    case QC_RISCV_REG_X17:
    case QC_RISCV_REG_X18:
    case QC_RISCV_REG_X19:
    case QC_RISCV_REG_X20:
    case QC_RISCV_REG_X21:
    case QC_RISCV_REG_X22:
    case QC_RISCV_REG_X23:
    case QC_RISCV_REG_X24:
    case QC_RISCV_REG_X25:
    case QC_RISCV_REG_X26:
    case QC_RISCV_REG_X27:
    case QC_RISCV_REG_X28:
    case QC_RISCV_REG_X29:
    case QC_RISCV_REG_X30:
    case QC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->gpr[regid - QC_RISCV_REG_X0];
#else
        *(int32_t *)value = env->gpr[regid - QC_RISCV_REG_X0];
#endif
        break;
    case QC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->pc;
#else
        *(int32_t *)value = env->pc;
#endif
        break;

    case QC_RISCV_REG_F0:  // "ft0"
    case QC_RISCV_REG_F1:  // "ft1"
    case QC_RISCV_REG_F2:  // "ft2"
    case QC_RISCV_REG_F3:  // "ft3"
    case QC_RISCV_REG_F4:  // "ft4"
    case QC_RISCV_REG_F5:  // "ft5"
    case QC_RISCV_REG_F6:  // "ft6"
    case QC_RISCV_REG_F7:  // "ft7"
    case QC_RISCV_REG_F8:  // "fs0"
    case QC_RISCV_REG_F9:  // "fs1"
    case QC_RISCV_REG_F10: // "fa0"
    case QC_RISCV_REG_F11: // "fa1"
    case QC_RISCV_REG_F12: // "fa2"
    case QC_RISCV_REG_F13: // "fa3"
    case QC_RISCV_REG_F14: // "fa4"
    case QC_RISCV_REG_F15: // "fa5"
    case QC_RISCV_REG_F16: // "fa6"
    case QC_RISCV_REG_F17: // "fa7"
    case QC_RISCV_REG_F18: // "fs2"
    case QC_RISCV_REG_F19: // "fs3"
    case QC_RISCV_REG_F20: // "fs4"
    case QC_RISCV_REG_F21: // "fs5"
    case QC_RISCV_REG_F22: // "fs6"
    case QC_RISCV_REG_F23: // "fs7"
    case QC_RISCV_REG_F24: // "fs8"
    case QC_RISCV_REG_F25: // "fs9"
    case QC_RISCV_REG_F26: // "fs10"
    case QC_RISCV_REG_F27: // "fs11"
    case QC_RISCV_REG_F28: // "ft8"
    case QC_RISCV_REG_F29: // "ft9"
    case QC_RISCV_REG_F30: // "ft10"
    case QC_RISCV_REG_F31: // "ft11"
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->fpr[regid - QC_RISCV_REG_F0];
#else
        *(int32_t *)value = env->fpr[regid - QC_RISCV_REG_F0];
#endif
        break;
    case QC_RISCV_REG_USTATUS:
    case QC_RISCV_REG_UIE:
    case QC_RISCV_REG_UTVEC:
    case QC_RISCV_REG_USCRATCH:
    case QC_RISCV_REG_UEPC:
    case QC_RISCV_REG_UCAUSE:
    case QC_RISCV_REG_UTVAL:
    case QC_RISCV_REG_UIP:
    case QC_RISCV_REG_FFLAGS:
    case QC_RISCV_REG_FRM:
    case QC_RISCV_REG_FCSR:
    case QC_RISCV_REG_CYCLE:
    case QC_RISCV_REG_TIME:
    case QC_RISCV_REG_INSTRET:
    case QC_RISCV_REG_HPMCOUNTER3:
    case QC_RISCV_REG_HPMCOUNTER4:
    case QC_RISCV_REG_HPMCOUNTER5:
    case QC_RISCV_REG_HPMCOUNTER6:
    case QC_RISCV_REG_HPMCOUNTER7:
    case QC_RISCV_REG_HPMCOUNTER8:
    case QC_RISCV_REG_HPMCOUNTER9:
    case QC_RISCV_REG_HPMCOUNTER10:
    case QC_RISCV_REG_HPMCOUNTER11:
    case QC_RISCV_REG_HPMCOUNTER12:
    case QC_RISCV_REG_HPMCOUNTER13:
    case QC_RISCV_REG_HPMCOUNTER14:
    case QC_RISCV_REG_HPMCOUNTER15:
    case QC_RISCV_REG_HPMCOUNTER16:
    case QC_RISCV_REG_HPMCOUNTER17:
    case QC_RISCV_REG_HPMCOUNTER18:
    case QC_RISCV_REG_HPMCOUNTER19:
    case QC_RISCV_REG_HPMCOUNTER20:
    case QC_RISCV_REG_HPMCOUNTER21:
    case QC_RISCV_REG_HPMCOUNTER22:
    case QC_RISCV_REG_HPMCOUNTER23:
    case QC_RISCV_REG_HPMCOUNTER24:
    case QC_RISCV_REG_HPMCOUNTER25:
    case QC_RISCV_REG_HPMCOUNTER26:
    case QC_RISCV_REG_HPMCOUNTER27:
    case QC_RISCV_REG_HPMCOUNTER28:
    case QC_RISCV_REG_HPMCOUNTER29:
    case QC_RISCV_REG_HPMCOUNTER30:
    case QC_RISCV_REG_HPMCOUNTER31:
    case QC_RISCV_REG_CYCLEH:
    case QC_RISCV_REG_TIMEH:
    case QC_RISCV_REG_INSTRETH:
    case QC_RISCV_REG_HPMCOUNTER3H:
    case QC_RISCV_REG_HPMCOUNTER4H:
    case QC_RISCV_REG_HPMCOUNTER5H:
    case QC_RISCV_REG_HPMCOUNTER6H:
    case QC_RISCV_REG_HPMCOUNTER7H:
    case QC_RISCV_REG_HPMCOUNTER8H:
    case QC_RISCV_REG_HPMCOUNTER9H:
    case QC_RISCV_REG_HPMCOUNTER10H:
    case QC_RISCV_REG_HPMCOUNTER11H:
    case QC_RISCV_REG_HPMCOUNTER12H:
    case QC_RISCV_REG_HPMCOUNTER13H:
    case QC_RISCV_REG_HPMCOUNTER14H:
    case QC_RISCV_REG_HPMCOUNTER15H:
    case QC_RISCV_REG_HPMCOUNTER16H:
    case QC_RISCV_REG_HPMCOUNTER17H:
    case QC_RISCV_REG_HPMCOUNTER18H:
    case QC_RISCV_REG_HPMCOUNTER19H:
    case QC_RISCV_REG_HPMCOUNTER20H:
    case QC_RISCV_REG_HPMCOUNTER21H:
    case QC_RISCV_REG_HPMCOUNTER22H:
    case QC_RISCV_REG_HPMCOUNTER23H:
    case QC_RISCV_REG_HPMCOUNTER24H:
    case QC_RISCV_REG_HPMCOUNTER25H:
    case QC_RISCV_REG_HPMCOUNTER26H:
    case QC_RISCV_REG_HPMCOUNTER27H:
    case QC_RISCV_REG_HPMCOUNTER28H:
    case QC_RISCV_REG_HPMCOUNTER29H:
    case QC_RISCV_REG_HPMCOUNTER30H:
    case QC_RISCV_REG_HPMCOUNTER31H:
    case QC_RISCV_REG_MCYCLE:
    case QC_RISCV_REG_MINSTRET:
    case QC_RISCV_REG_MCYCLEH:
    case QC_RISCV_REG_MINSTRETH:
    case QC_RISCV_REG_MVENDORID:
    case QC_RISCV_REG_MARCHID:
    case QC_RISCV_REG_MIMPID:
    case QC_RISCV_REG_MHARTID:
    case QC_RISCV_REG_MSTATUS:
    case QC_RISCV_REG_MISA:
    case QC_RISCV_REG_MEDELEG:
    case QC_RISCV_REG_MIDELEG:
    case QC_RISCV_REG_MIE:
    case QC_RISCV_REG_MTVEC:
    case QC_RISCV_REG_MCOUNTEREN:
    case QC_RISCV_REG_MSTATUSH:
    case QC_RISCV_REG_MUCOUNTEREN:
    case QC_RISCV_REG_MSCOUNTEREN:
    case QC_RISCV_REG_MHCOUNTEREN:
    case QC_RISCV_REG_MSCRATCH:
    case QC_RISCV_REG_MEPC:
    case QC_RISCV_REG_MCAUSE:
    case QC_RISCV_REG_MTVAL:
    case QC_RISCV_REG_MIP:
    case QC_RISCV_REG_MBADADDR:
    case QC_RISCV_REG_SSTATUS:
    case QC_RISCV_REG_SEDELEG:
    case QC_RISCV_REG_SIDELEG:
    case QC_RISCV_REG_SIE:
    case QC_RISCV_REG_STVEC:
    case QC_RISCV_REG_SCOUNTEREN:
    case QC_RISCV_REG_SSCRATCH:
    case QC_RISCV_REG_SEPC:
    case QC_RISCV_REG_SCAUSE:
    case QC_RISCV_REG_STVAL:
    case QC_RISCV_REG_SIP:
    case QC_RISCV_REG_SBADADDR:
    case QC_RISCV_REG_SPTBR:
    case QC_RISCV_REG_SATP:
    case QC_RISCV_REG_HSTATUS:
    case QC_RISCV_REG_HEDELEG:
    case QC_RISCV_REG_HIDELEG:
    case QC_RISCV_REG_HIE:
    case QC_RISCV_REG_HCOUNTEREN:
    case QC_RISCV_REG_HTVAL:
    case QC_RISCV_REG_HIP:
    case QC_RISCV_REG_HTINST:
    case QC_RISCV_REG_HGATP:
    case QC_RISCV_REG_HTIMEDELTA:
    case QC_RISCV_REG_HTIMEDELTAH: {
        target_ulong val;
        int csrno = csrno_map[regid - QC_RISCV_REG_USTATUS];
        riscv_csrrw(env, csrno, &val, -1, 0);
#ifdef TARGET_RISCV64
        *(uint64_t *)value = (uint64_t)val;
#else
        *(uint32_t *)value = (uint32_t)val;
#endif
        break;
    }
    default:
        break;
    }

    return;
}

static void reg_write(CPURISCVState *env, unsigned int regid, const void *value)
{
    switch (regid) {
    case QC_RISCV_REG_X0:
    case QC_RISCV_REG_X1:
    case QC_RISCV_REG_X2:
    case QC_RISCV_REG_X3:
    case QC_RISCV_REG_X4:
    case QC_RISCV_REG_X5:
    case QC_RISCV_REG_X6:
    case QC_RISCV_REG_X7:
    case QC_RISCV_REG_X8:
    case QC_RISCV_REG_X9:
    case QC_RISCV_REG_X10:
    case QC_RISCV_REG_X11:
    case QC_RISCV_REG_X12:
    case QC_RISCV_REG_X13:
    case QC_RISCV_REG_X14:
    case QC_RISCV_REG_X15:
    case QC_RISCV_REG_X16:
    case QC_RISCV_REG_X17:
    case QC_RISCV_REG_X18:
    case QC_RISCV_REG_X19:
    case QC_RISCV_REG_X20:
    case QC_RISCV_REG_X21:
    case QC_RISCV_REG_X22:
    case QC_RISCV_REG_X23:
    case QC_RISCV_REG_X24:
    case QC_RISCV_REG_X25:
    case QC_RISCV_REG_X26:
    case QC_RISCV_REG_X27:
    case QC_RISCV_REG_X28:
    case QC_RISCV_REG_X29:
    case QC_RISCV_REG_X30:
    case QC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
        env->gpr[regid - QC_RISCV_REG_X0] = *(uint64_t *)value;
#else
        env->gpr[regid - QC_RISCV_REG_X0] = *(uint32_t *)value;
#endif
        break;
    case QC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
        env->pc = *(uint64_t *)value;
#else
        env->pc = *(uint32_t *)value;
#endif
        break;
    case QC_RISCV_REG_F0:  // "ft0"
    case QC_RISCV_REG_F1:  // "ft1"
    case QC_RISCV_REG_F2:  // "ft2"
    case QC_RISCV_REG_F3:  // "ft3"
    case QC_RISCV_REG_F4:  // "ft4"
    case QC_RISCV_REG_F5:  // "ft5"
    case QC_RISCV_REG_F6:  // "ft6"
    case QC_RISCV_REG_F7:  // "ft7"
    case QC_RISCV_REG_F8:  // "fs0"
    case QC_RISCV_REG_F9:  // "fs1"
    case QC_RISCV_REG_F10: // "fa0"
    case QC_RISCV_REG_F11: // "fa1"
    case QC_RISCV_REG_F12: // "fa2"
    case QC_RISCV_REG_F13: // "fa3"
    case QC_RISCV_REG_F14: // "fa4"
    case QC_RISCV_REG_F15: // "fa5"
    case QC_RISCV_REG_F16: // "fa6"
    case QC_RISCV_REG_F17: // "fa7"
    case QC_RISCV_REG_F18: // "fs2"
    case QC_RISCV_REG_F19: // "fs3"
    case QC_RISCV_REG_F20: // "fs4"
    case QC_RISCV_REG_F21: // "fs5"
    case QC_RISCV_REG_F22: // "fs6"
    case QC_RISCV_REG_F23: // "fs7"
    case QC_RISCV_REG_F24: // "fs8"
    case QC_RISCV_REG_F25: // "fs9"
    case QC_RISCV_REG_F26: // "fs10"
    case QC_RISCV_REG_F27: // "fs11"
    case QC_RISCV_REG_F28: // "ft8"
    case QC_RISCV_REG_F29: // "ft9"
    case QC_RISCV_REG_F30: // "ft10"
    case QC_RISCV_REG_F31: // "ft11"
#ifdef TARGET_RISCV64
        env->fpr[regid - QC_RISCV_REG_F0] = *(uint64_t *)value;
#else
        env->fpr[regid - QC_RISCV_REG_F0] = *(uint32_t *)value;
#endif
        break;
    case QC_RISCV_REG_USTATUS:
    case QC_RISCV_REG_UIE:
    case QC_RISCV_REG_UTVEC:
    case QC_RISCV_REG_USCRATCH:
    case QC_RISCV_REG_UEPC:
    case QC_RISCV_REG_UCAUSE:
    case QC_RISCV_REG_UTVAL:
    case QC_RISCV_REG_UIP:
    case QC_RISCV_REG_FFLAGS:
    case QC_RISCV_REG_FRM:
    case QC_RISCV_REG_FCSR:
    case QC_RISCV_REG_CYCLE:
    case QC_RISCV_REG_TIME:
    case QC_RISCV_REG_INSTRET:
    case QC_RISCV_REG_HPMCOUNTER3:
    case QC_RISCV_REG_HPMCOUNTER4:
    case QC_RISCV_REG_HPMCOUNTER5:
    case QC_RISCV_REG_HPMCOUNTER6:
    case QC_RISCV_REG_HPMCOUNTER7:
    case QC_RISCV_REG_HPMCOUNTER8:
    case QC_RISCV_REG_HPMCOUNTER9:
    case QC_RISCV_REG_HPMCOUNTER10:
    case QC_RISCV_REG_HPMCOUNTER11:
    case QC_RISCV_REG_HPMCOUNTER12:
    case QC_RISCV_REG_HPMCOUNTER13:
    case QC_RISCV_REG_HPMCOUNTER14:
    case QC_RISCV_REG_HPMCOUNTER15:
    case QC_RISCV_REG_HPMCOUNTER16:
    case QC_RISCV_REG_HPMCOUNTER17:
    case QC_RISCV_REG_HPMCOUNTER18:
    case QC_RISCV_REG_HPMCOUNTER19:
    case QC_RISCV_REG_HPMCOUNTER20:
    case QC_RISCV_REG_HPMCOUNTER21:
    case QC_RISCV_REG_HPMCOUNTER22:
    case QC_RISCV_REG_HPMCOUNTER23:
    case QC_RISCV_REG_HPMCOUNTER24:
    case QC_RISCV_REG_HPMCOUNTER25:
    case QC_RISCV_REG_HPMCOUNTER26:
    case QC_RISCV_REG_HPMCOUNTER27:
    case QC_RISCV_REG_HPMCOUNTER28:
    case QC_RISCV_REG_HPMCOUNTER29:
    case QC_RISCV_REG_HPMCOUNTER30:
    case QC_RISCV_REG_HPMCOUNTER31:
    case QC_RISCV_REG_CYCLEH:
    case QC_RISCV_REG_TIMEH:
    case QC_RISCV_REG_INSTRETH:
    case QC_RISCV_REG_HPMCOUNTER3H:
    case QC_RISCV_REG_HPMCOUNTER4H:
    case QC_RISCV_REG_HPMCOUNTER5H:
    case QC_RISCV_REG_HPMCOUNTER6H:
    case QC_RISCV_REG_HPMCOUNTER7H:
    case QC_RISCV_REG_HPMCOUNTER8H:
    case QC_RISCV_REG_HPMCOUNTER9H:
    case QC_RISCV_REG_HPMCOUNTER10H:
    case QC_RISCV_REG_HPMCOUNTER11H:
    case QC_RISCV_REG_HPMCOUNTER12H:
    case QC_RISCV_REG_HPMCOUNTER13H:
    case QC_RISCV_REG_HPMCOUNTER14H:
    case QC_RISCV_REG_HPMCOUNTER15H:
    case QC_RISCV_REG_HPMCOUNTER16H:
    case QC_RISCV_REG_HPMCOUNTER17H:
    case QC_RISCV_REG_HPMCOUNTER18H:
    case QC_RISCV_REG_HPMCOUNTER19H:
    case QC_RISCV_REG_HPMCOUNTER20H:
    case QC_RISCV_REG_HPMCOUNTER21H:
    case QC_RISCV_REG_HPMCOUNTER22H:
    case QC_RISCV_REG_HPMCOUNTER23H:
    case QC_RISCV_REG_HPMCOUNTER24H:
    case QC_RISCV_REG_HPMCOUNTER25H:
    case QC_RISCV_REG_HPMCOUNTER26H:
    case QC_RISCV_REG_HPMCOUNTER27H:
    case QC_RISCV_REG_HPMCOUNTER28H:
    case QC_RISCV_REG_HPMCOUNTER29H:
    case QC_RISCV_REG_HPMCOUNTER30H:
    case QC_RISCV_REG_HPMCOUNTER31H:
    case QC_RISCV_REG_MCYCLE:
    case QC_RISCV_REG_MINSTRET:
    case QC_RISCV_REG_MCYCLEH:
    case QC_RISCV_REG_MINSTRETH:
    case QC_RISCV_REG_MVENDORID:
    case QC_RISCV_REG_MARCHID:
    case QC_RISCV_REG_MIMPID:
    case QC_RISCV_REG_MHARTID:
    case QC_RISCV_REG_MSTATUS:
    case QC_RISCV_REG_MISA:
    case QC_RISCV_REG_MEDELEG:
    case QC_RISCV_REG_MIDELEG:
    case QC_RISCV_REG_MIE:
    case QC_RISCV_REG_MTVEC:
    case QC_RISCV_REG_MCOUNTEREN:
    case QC_RISCV_REG_MSTATUSH:
    case QC_RISCV_REG_MUCOUNTEREN:
    case QC_RISCV_REG_MSCOUNTEREN:
    case QC_RISCV_REG_MHCOUNTEREN:
    case QC_RISCV_REG_MSCRATCH:
    case QC_RISCV_REG_MEPC:
    case QC_RISCV_REG_MCAUSE:
    case QC_RISCV_REG_MTVAL:
    case QC_RISCV_REG_MIP:
    case QC_RISCV_REG_MBADADDR:
    case QC_RISCV_REG_SSTATUS:
    case QC_RISCV_REG_SEDELEG:
    case QC_RISCV_REG_SIDELEG:
    case QC_RISCV_REG_SIE:
    case QC_RISCV_REG_STVEC:
    case QC_RISCV_REG_SCOUNTEREN:
    case QC_RISCV_REG_SSCRATCH:
    case QC_RISCV_REG_SEPC:
    case QC_RISCV_REG_SCAUSE:
    case QC_RISCV_REG_STVAL:
    case QC_RISCV_REG_SIP:
    case QC_RISCV_REG_SBADADDR:
    case QC_RISCV_REG_SPTBR:
    case QC_RISCV_REG_SATP:
    case QC_RISCV_REG_HSTATUS:
    case QC_RISCV_REG_HEDELEG:
    case QC_RISCV_REG_HIDELEG:
    case QC_RISCV_REG_HIE:
    case QC_RISCV_REG_HCOUNTEREN:
    case QC_RISCV_REG_HTVAL:
    case QC_RISCV_REG_HIP:
    case QC_RISCV_REG_HTINST:
    case QC_RISCV_REG_HGATP:
    case QC_RISCV_REG_HTIMEDELTA:
    case QC_RISCV_REG_HTIMEDELTAH: {
        target_ulong val;
        int csrno = csrno_map[regid - QC_RISCV_REG_USTATUS];
#ifdef TARGET_RISCV64
        riscv_csrrw(env, csrno, &val, *(uint64_t *)value, -1);
#else
        riscv_csrrw(env, csrno, &val, *(uint32_t *)value, -1);
#endif
        break;
    } break;
    default:
        break;
    }
}

int riscv_reg_read(struct qc_struct *uc, unsigned int *regs, void **vals,
                   int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int riscv_reg_write(struct qc_struct *uc, unsigned int *regs, void *const *vals,
                    int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == QC_RISCV_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            qc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_read(struct qc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#else
/* TARGET_RISCV64 */
int riscv64_context_reg_read(struct qc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_write(struct qc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#else
/* TARGET_RISCV64 */
int riscv64_context_reg_write(struct qc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static bool riscv_stop_interrupt(struct qc_struct *uc, int intno)
{
    // detect stop exception
    switch (intno) {
    default:
        return false;
    case RISCV_EXCP_UNICORN_END:
        return true;
    case RISCV_EXCP_BREAKPOINT:
        uc->invalid_error = QC_ERR_EXCEPTION;
        return true;
    }
}

static bool riscv_insn_hook_validate(uint32_t insn_enum)
{
    return false;
}

static int riscv_cpus_init(struct qc_struct *uc, const char *cpu_model)
{

    RISCVCPU *cpu;

    cpu = cpu_riscv_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
void riscv32_qc_init(struct qc_struct *uc)
#else
/* TARGET_RISCV64 */
void riscv64_qc_init(struct qc_struct *uc)
#endif
{
    uc->reg_read = riscv_reg_read;
    uc->reg_write = riscv_reg_write;
    uc->reg_reset = riscv_reg_reset;
    uc->release = riscv_release;
    uc->set_pc = riscv_set_pc;
    uc->stop_interrupt = riscv_stop_interrupt;
    uc->insn_hook_validate = riscv_insn_hook_validate;
    uc->cpus_init = riscv_cpus_init;
    uc->cpu_context_size = offsetof(CPURISCVState, rdtime_fn);
    qc_common_init(uc);
}
