/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#if defined(QNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <time.h> // nanosleep
#include <string.h>

#include "qc_priv.h"

// target specific headers
#include "qemu/target/m68k/unicorn.h"
#include "qemu/target/i386/unicorn.h"
#include "qemu/target/arm/unicorn.h"
#include "qemu/target/mips/unicorn.h"
#include "qemu/target/sparc/unicorn.h"
#include "qemu/target/ppc/unicorn.h"
#include "qemu/target/riscv/unicorn.h"

#include "qemu/include/qemu/queue.h"
#include "qemu-common.h"

QNICORN_EXPORT
unsigned int qc_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = QC_API_MAJOR;
        *minor = QC_API_MINOR;
    }

    return (QC_API_MAJOR << 8) + QC_API_MINOR;
}

QNICORN_EXPORT
qc_err qc_errno(qc_engine *qc)
{
    return qc->errnum;
}

QNICORN_EXPORT
const char *qc_strerror(qc_err code)
{
    switch (code) {
    default:
        return "Unknown error code";
    case QC_ERR_OK:
        return "OK (QC_ERR_OK)";
    case QC_ERR_NOMEM:
        return "No memory available or memory not present (QC_ERR_NOMEM)";
    case QC_ERR_ARCH:
        return "Invalid/unsupported architecture (QC_ERR_ARCH)";
    case QC_ERR_HANDLE:
        return "Invalid handle (QC_ERR_HANDLE)";
    case QC_ERR_MODE:
        return "Invalid mode (QC_ERR_MODE)";
    case QC_ERR_VERSION:
        return "Different API version between core & binding (QC_ERR_VERSION)";
    case QC_ERR_READ_UNMAPPED:
        return "Invalid memory read (QC_ERR_READ_UNMAPPED)";
    case QC_ERR_WRITE_UNMAPPED:
        return "Invalid memory write (QC_ERR_WRITE_UNMAPPED)";
    case QC_ERR_FETCH_UNMAPPED:
        return "Invalid memory fetch (QC_ERR_FETCH_UNMAPPED)";
    case QC_ERR_HOOK:
        return "Invalid hook type (QC_ERR_HOOK)";
    case QC_ERR_INSN_INVALID:
        return "Invalid instruction (QC_ERR_INSN_INVALID)";
    case QC_ERR_MAP:
        return "Invalid memory mapping (QC_ERR_MAP)";
    case QC_ERR_WRITE_PROT:
        return "Write to write-protected memory (QC_ERR_WRITE_PROT)";
    case QC_ERR_READ_PROT:
        return "Read from non-readable memory (QC_ERR_READ_PROT)";
    case QC_ERR_FETCH_PROT:
        return "Fetch from non-executable memory (QC_ERR_FETCH_PROT)";
    case QC_ERR_ARG:
        return "Invalid argument (QC_ERR_ARG)";
    case QC_ERR_READ_UNALIGNED:
        return "Read from unaligned memory (QC_ERR_READ_UNALIGNED)";
    case QC_ERR_WRITE_UNALIGNED:
        return "Write to unaligned memory (QC_ERR_WRITE_UNALIGNED)";
    case QC_ERR_FETCH_UNALIGNED:
        return "Fetch from unaligned memory (QC_ERR_FETCH_UNALIGNED)";
    case QC_ERR_RESOURCE:
        return "Insufficient resource (QC_ERR_RESOURCE)";
    case QC_ERR_EXCEPTION:
        return "Unhandled CPU exception (QC_ERR_EXCEPTION)";
    }
}

QNICORN_EXPORT
bool qc_arch_supported(qc_arch arch)
{
    switch (arch) {
#ifdef QNICORN_HAS_ARM
    case QC_ARCH_ARM:
        return true;
#endif
#ifdef QNICORN_HAS_ARM64
    case QC_ARCH_ARM64:
        return true;
#endif
#ifdef QNICORN_HAS_M68K
    case QC_ARCH_M68K:
        return true;
#endif
#ifdef QNICORN_HAS_MIPS
    case QC_ARCH_MIPS:
        return true;
#endif
#ifdef QNICORN_HAS_PPC
    case QC_ARCH_PPC:
        return true;
#endif
#ifdef QNICORN_HAS_SPARC
    case QC_ARCH_SPARC:
        return true;
#endif
#ifdef QNICORN_HAS_X86
    case QC_ARCH_X86:
        return true;
#endif
#ifdef QNICORN_HAS_RISCV
    case QC_ARCH_RISCV:
        return true;
#endif
    /* Invalid or disabled arch */
    default:
        return false;
    }
}

#define QC_INIT(qc)                                                            \
    if (unlikely(!(qc)->init_done)) {                                          \
        int __init_ret = qc_init(qc);                                          \
        if (unlikely(__init_ret != QC_ERR_OK)) {                               \
            return __init_ret;                                                 \
        }                                                                      \
    }

static gint qc_exits_cmp(gconstpointer a, gconstpointer b, gpointer user_data)
{
    uint64_t lhs = *((uint64_t *)a);
    uint64_t rhs = *((uint64_t *)b);

    if (lhs < rhs) {
        return -1;
    } else if (lhs == rhs) {
        return 0;
    } else {
        return 1;
    }
}

static qc_err qc_init(qc_engine *qc)
{

    if (qc->init_done) {
        return QC_ERR_HANDLE;
    }

    qc->exits = g_tree_new_full(qc_exits_cmp, NULL, g_free, NULL);

    if (machine_initialize(qc)) {
        return QC_ERR_RESOURCE;
    }

    // init fpu softfloat
    qc->softfloat_initialize();

    if (qc->reg_reset) {
        qc->reg_reset(qc);
    }

    qc->init_done = true;

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_open(qc_arch arch, qc_mode mode, qc_engine **result)
{
    struct qc_struct *qc;

    if (arch < QC_ARCH_MAX) {
        qc = calloc(1, sizeof(*qc));
        if (!qc) {
            // memory insufficient
            return QC_ERR_NOMEM;
        }

        /* qemu/exec.c: phys_map_node_reserve() */
        qc->alloc_hint = 16;
        qc->errnum = QC_ERR_OK;
        qc->arch = arch;
        qc->mode = mode;

        // qc->ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };
        QLIST_INIT(&qc->ram_list.blocks);

        QTAILQ_INIT(&qc->memory_listeners);

        QTAILQ_INIT(&qc->address_spaces);

        switch (arch) {
        default:
            break;
#ifdef QNICORN_HAS_M68K
        case QC_ARCH_M68K:
            if ((mode & ~QC_MODE_M68K_MASK) || !(mode & QC_MODE_BIG_ENDIAN)) {
                free(qc);
                return QC_ERR_MODE;
            }
            qc->init_arch = m68k_qc_init;
            break;
#endif
#ifdef QNICORN_HAS_X86
        case QC_ARCH_X86:
            if ((mode & ~QC_MODE_X86_MASK) || (mode & QC_MODE_BIG_ENDIAN) ||
                !(mode & (QC_MODE_16 | QC_MODE_32 | QC_MODE_64))) {
                free(qc);
                return QC_ERR_MODE;
            }
            qc->init_arch = x86_qc_init;
            break;
#endif
#ifdef QNICORN_HAS_ARM
        case QC_ARCH_ARM:
            if ((mode & ~QC_MODE_ARM_MASK)) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_BIG_ENDIAN) {
                qc->init_arch = armeb_qc_init;
            } else {
                qc->init_arch = arm_qc_init;
            }

            if (mode & QC_MODE_THUMB) {
                qc->thumb = 1;
            }
            break;
#endif
#ifdef QNICORN_HAS_ARM64
        case QC_ARCH_ARM64:
            if (mode & ~QC_MODE_ARM_MASK) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_BIG_ENDIAN) {
                qc->init_arch = arm64eb_qc_init;
            } else {
                qc->init_arch = arm64_qc_init;
            }
            break;
#endif

#if defined(QNICORN_HAS_MIPS) || defined(QNICORN_HAS_MIPSEL) ||                \
    defined(QNICORN_HAS_MIPS64) || defined(QNICORN_HAS_MIPS64EL)
        case QC_ARCH_MIPS:
            if ((mode & ~QC_MODE_MIPS_MASK) ||
                !(mode & (QC_MODE_MIPS32 | QC_MODE_MIPS64))) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_BIG_ENDIAN) {
#ifdef QNICORN_HAS_MIPS
                if (mode & QC_MODE_MIPS32) {
                    qc->init_arch = mips_qc_init;
                }
#endif
#ifdef QNICORN_HAS_MIPS64
                if (mode & QC_MODE_MIPS64) {
                    qc->init_arch = mips64_qc_init;
                }
#endif
            } else { // little endian
#ifdef QNICORN_HAS_MIPSEL
                if (mode & QC_MODE_MIPS32) {
                    qc->init_arch = mipsel_qc_init;
                }
#endif
#ifdef QNICORN_HAS_MIPS64EL
                if (mode & QC_MODE_MIPS64) {
                    qc->init_arch = mips64el_qc_init;
                }
#endif
            }
            break;
#endif

#ifdef QNICORN_HAS_SPARC
        case QC_ARCH_SPARC:
            if ((mode & ~QC_MODE_SPARC_MASK) || !(mode & QC_MODE_BIG_ENDIAN) ||
                !(mode & (QC_MODE_SPARC32 | QC_MODE_SPARC64))) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_SPARC64) {
                qc->init_arch = sparc64_qc_init;
            } else {
                qc->init_arch = sparc_qc_init;
            }
            break;
#endif
#ifdef QNICORN_HAS_PPC
        case QC_ARCH_PPC:
            if ((mode & ~QC_MODE_PPC_MASK) || !(mode & QC_MODE_BIG_ENDIAN) ||
                !(mode & (QC_MODE_PPC32 | QC_MODE_PPC64))) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_PPC64) {
                qc->init_arch = ppc64_qc_init;
            } else {
                qc->init_arch = ppc_qc_init;
            }
            break;
#endif
#ifdef QNICORN_HAS_RISCV
        case QC_ARCH_RISCV:
            if ((mode & ~QC_MODE_RISCV_MASK) ||
                !(mode & (QC_MODE_RISCV32 | QC_MODE_RISCV64))) {
                free(qc);
                return QC_ERR_MODE;
            }
            if (mode & QC_MODE_RISCV32) {
                qc->init_arch = riscv32_qc_init;
            } else if (mode & QC_MODE_RISCV64) {
                qc->init_arch = riscv64_qc_init;
            } else {
                free(qc);
                return QC_ERR_MODE;
            }
            break;
#endif
        }

        if (qc->init_arch == NULL) {
            return QC_ERR_ARCH;
        }

        qc->init_done = false;
        qc->cpu_model = INT_MAX; // INT_MAX means the default cpu model.

        *result = qc;

        return QC_ERR_OK;
    } else {
        return QC_ERR_ARCH;
    }
}

QNICORN_EXPORT
qc_err qc_close(qc_engine *qc)
{
    int i;
    struct list_item *cur;
    struct hook *hook;
    MemoryRegion *mr;

    if (!qc->init_done) {
        free(qc);
        return QC_ERR_OK;
    }

    // Cleanup internally.
    if (qc->release) {
        qc->release(qc->tcg_ctx);
    }
    g_free(qc->tcg_ctx);

    // Cleanup CPU.
    g_free(qc->cpu->cpu_ases);
    g_free(qc->cpu->thread);

    /* cpu */
    free(qc->cpu);

    /* flatviews */
    g_hash_table_destroy(qc->flat_views);

    // During flatviews destruction, we may still access memory regions.
    // So we free them afterwards.
    /* memory */
    mr = &qc->io_mem_unassigned;
    mr->destructor(mr);
    mr = qc->system_io;
    mr->destructor(mr);
    mr = qc->system_memory;
    mr->destructor(mr);
    g_free(qc->system_memory);
    g_free(qc->system_io);

    // Thread relateds.
    if (qc->qemu_thread_data) {
        g_free(qc->qemu_thread_data);
    }

    /* free */
    g_free(qc->init_target_page);

    // Other auxilaries.
    g_free(qc->l1_map);

    if (qc->bounce.buffer) {
        free(qc->bounce.buffer);
    }

    // free hooks and hook lists
    for (i = 0; i < QC_HOOK_MAX; i++) {
        cur = qc->hook[i].head;
        // hook can be in more than one list
        // so we refcount to know when to free
        while (cur) {
            hook = (struct hook *)cur->data;
            if (--hook->refs == 0) {
                free(hook);
            }
            cur = cur->next;
        }
        list_clear(&qc->hook[i]);
    }

    free(qc->mapped_blocks);

    // free the saved contexts list and notify them that uc has been closed.
    cur = qc->saved_contexts.head;
    while (cur != NULL) {
        struct list_item *next = cur->next;
        struct qc_context *context = (struct qc_context *)cur->data;
        context->qc = NULL;
        cur = next;
    }
    list_clear(&qc->saved_contexts);

    g_tree_destroy(qc->exits);

    // finally, free uc itself.
    memset(qc, 0, sizeof(*qc));
    free(qc);

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_reg_read_batch(qc_engine *qc, int *ids, void **vals, int count)
{
    int ret = QC_ERR_OK;

    QC_INIT(qc);

    if (qc->reg_read) {
        ret = qc->reg_read(qc, (unsigned int *)ids, vals, count);
    } else {
        return QC_ERR_HANDLE;
    }

    return ret;
}

QNICORN_EXPORT
qc_err qc_reg_write_batch(qc_engine *qc, int *ids, void *const *vals, int count)
{
    int ret = QC_ERR_OK;

    QC_INIT(qc);

    if (qc->reg_write) {
        ret = qc->reg_write(qc, (unsigned int *)ids, vals, count);
    } else {
        return QC_ERR_HANDLE;
    }

    return ret;
}

QNICORN_EXPORT
qc_err qc_reg_read(qc_engine *qc, int regid, void *value)
{
    QC_INIT(qc);
    return qc_reg_read_batch(qc, &regid, &value, 1);
}

QNICORN_EXPORT
qc_err qc_reg_write(qc_engine *qc, int regid, const void *value)
{
    QC_INIT(qc);
    return qc_reg_write_batch(qc, &regid, (void *const *)&value, 1);
}

// check if a memory area is mapped
// this is complicated because an area can overlap adjacent blocks
static bool check_mem_area(qc_engine *qc, uint64_t address, size_t size)
{
    size_t count = 0, len;

    while (count < size) {
        MemoryRegion *mr = memory_mapping(qc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            count += len;
            address += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    return (count == size);
}

QNICORN_EXPORT
qc_err qc_mem_read(qc_engine *qc, uint64_t address, void *_bytes, size_t size)
{
    size_t count = 0, len;
    uint8_t *bytes = _bytes;

    QC_INIT(qc);

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX)
        return QC_ERR_ARG;

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    if (!check_mem_area(qc, address, size)) {
        return QC_ERR_READ_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while (count < size) {
        MemoryRegion *mr = memory_mapping(qc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            if (qc->read_mem(&qc->address_space_memory, address, bytes, len) ==
                false) {
                break;
            }
            count += len;
            address += len;
            bytes += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    if (count == size) {
        return QC_ERR_OK;
    } else {
        return QC_ERR_READ_UNMAPPED;
    }
}

QNICORN_EXPORT
qc_err qc_mem_write(qc_engine *qc, uint64_t address, const void *_bytes,
                    size_t size)
{
    size_t count = 0, len;
    const uint8_t *bytes = _bytes;

    QC_INIT(qc);

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX)
        return QC_ERR_ARG;

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    if (!check_mem_area(qc, address, size)) {
        return QC_ERR_WRITE_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while (count < size) {
        MemoryRegion *mr = memory_mapping(qc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            if (!(operms & QC_PROT_WRITE)) { // write protected
                // but this is not the program accessing memory, so temporarily
                // mark writable
                qc->readonly_mem(mr, false);
            }

            len = (size_t)MIN(size - count, mr->end - address);
            if (qc->write_mem(&qc->address_space_memory, address, bytes, len) ==
                false) {
                break;
            }

            if (!(operms & QC_PROT_WRITE)) { // write protected
                // now write protect it again
                qc->readonly_mem(mr, true);
            }

            count += len;
            address += len;
            bytes += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    if (count == size) {
        return QC_ERR_OK;
    } else {
        return QC_ERR_WRITE_UNMAPPED;
    }
}

#define TIMEOUT_STEP 2 // microseconds
static void *_timeout_fn(void *arg)
{
    struct qc_struct *qc = arg;
    int64_t current_time = get_clock();

    do {
        usleep(TIMEOUT_STEP);
        // perhaps emulation is even done before timeout?
        if (qc->emulation_done) {
            break;
        }
    } while ((uint64_t)(get_clock() - current_time) < qc->timeout);

    // timeout before emulation is done?
    if (!qc->emulation_done) {
        qc->timed_out = true;
        // force emulation to stop
        qc_emu_stop(qc);
    }

    return NULL;
}

static void enable_emu_timer(qc_engine *qc, uint64_t timeout)
{
    qc->timeout = timeout;
    qemu_thread_create(qc, &qc->timer, "timeout", _timeout_fn, qc,
                       QEMU_THREAD_JOINABLE);
}

static void hook_count_cb(struct qc_struct *qc, uint64_t address, uint32_t size,
                          void *user_data)
{
    // count this instruction. ah ah ah.
    qc->emu_counter++;
    // printf(":: emu counter = %u, at %lx\n", qc->emu_counter, address);

    if (qc->emu_counter > qc->emu_count) {
        // printf(":: emu counter = %u, stop emulation\n", qc->emu_counter);
        qc_emu_stop(qc);
    }
}

static void clear_deleted_hooks(qc_engine *qc)
{
    struct list_item *cur;
    struct hook *hook;
    int i;

    for (cur = qc->hooks_to_del.head;
         cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        assert(hook->to_delete);
        for (i = 0; i < QC_HOOK_MAX; i++) {
            if (list_remove(&qc->hook[i], (void *)hook)) {
                if (--hook->refs == 0) {
                    free(hook);
                }

                // a hook cannot be twice in the same list
                break;
            }
        }
    }

    list_clear(&qc->hooks_to_del);
}

QNICORN_EXPORT
qc_err qc_emu_start(qc_engine *qc, uint64_t begin, uint64_t until,
                    uint64_t timeout, size_t count)
{
    // reset the counter
    qc->emu_counter = 0;
    qc->invalid_error = QC_ERR_OK;
    qc->emulation_done = false;
    qc->size_recur_mem = 0;
    qc->timed_out = false;
    qc->first_tb = true;

    QC_INIT(qc);

    switch (qc->arch) {
    default:
        break;
#ifdef QNICORN_HAS_M68K
    case QC_ARCH_M68K:
        qc_reg_write(qc, QC_M68K_REG_PC, &begin);
        break;
#endif
#ifdef QNICORN_HAS_X86
    case QC_ARCH_X86:
        switch (qc->mode) {
        default:
            break;
        case QC_MODE_16: {
            uint64_t ip;
            uint16_t cs;

            qc_reg_read(qc, QC_X86_REG_CS, &cs);
            // compensate for later adding up IP & CS
            ip = begin - cs * 16;
            qc_reg_write(qc, QC_X86_REG_IP, &ip);
            break;
        }
        case QC_MODE_32:
            qc_reg_write(qc, QC_X86_REG_EIP, &begin);
            break;
        case QC_MODE_64:
            qc_reg_write(qc, QC_X86_REG_RIP, &begin);
            break;
        }
        break;
#endif
#ifdef QNICORN_HAS_ARM
    case QC_ARCH_ARM:
        qc_reg_write(qc, QC_ARM_REG_R15, &begin);
        break;
#endif
#ifdef QNICORN_HAS_ARM64
    case QC_ARCH_ARM64:
        qc_reg_write(qc, QC_ARM64_REG_PC, &begin);
        break;
#endif
#ifdef QNICORN_HAS_MIPS
    case QC_ARCH_MIPS:
        // TODO: MIPS32/MIPS64/BIGENDIAN etc
        qc_reg_write(qc, QC_MIPS_REG_PC, &begin);
        break;
#endif
#ifdef QNICORN_HAS_SPARC
    case QC_ARCH_SPARC:
        // TODO: Sparc/Sparc64
        qc_reg_write(qc, QC_SPARC_REG_PC, &begin);
        break;
#endif
#ifdef QNICORN_HAS_PPC
    case QC_ARCH_PPC:
        qc_reg_write(qc, QC_PPC_REG_PC, &begin);
        break;
#endif
#ifdef QNICORN_HAS_RISCV
    case QC_ARCH_RISCV:
        qc_reg_write(qc, QC_RISCV_REG_PC, &begin);
        break;
#endif
    }

    qc->stop_request = false;

    qc->emu_count = count;
    // remove count hook if counting isn't necessary
    if (count <= 0 && qc->count_hook != 0) {
        qc_hook_del(qc, qc->count_hook);
        qc->count_hook = 0;
    }
    // set up count hook to count instructions.
    if (count > 0 && qc->count_hook == 0) {
        qc_err err;
        // callback to count instructions must be run before everything else,
        // so instead of appending, we must insert the hook at the begin
        // of the hook list
        qc->hook_insert = 1;
        err = qc_hook_add(qc, &qc->count_hook, QC_HOOK_CODE, hook_count_cb,
                          NULL, 1, 0);
        // restore to append mode for qc_hook_add()
        qc->hook_insert = 0;
        if (err != QC_ERR_OK) {
            return err;
        }
    }

    // If QC_CTL_QC_USE_EXITS is set, then the @until param won't have any
    // effect. This is designed for the backward compatibility.
    if (!qc->use_exits) {
        g_tree_remove_all(qc->exits);
        qc_add_exit(qc, until);
    }

    if (timeout) {
        enable_emu_timer(qc, timeout * 1000); // microseconds -> nanoseconds
    }

    qc->vm_start(qc);

    // emulation is done
    qc->emulation_done = true;

    // remove hooks to delete
    clear_deleted_hooks(qc);

    if (timeout) {
        // wait for the timer to finish
        qemu_thread_join(&qc->timer);
    }

    return qc->invalid_error;
}

QNICORN_EXPORT
qc_err qc_emu_stop(qc_engine *qc)
{
    QC_INIT(qc);

    if (qc->emulation_done) {
        return QC_ERR_OK;
    }

    qc->stop_request = true;
    // TODO: make this atomic somehow?
    if (qc->cpu) {
        // exit the current TB
        cpu_exit(qc->cpu);
    }

    return QC_ERR_OK;
}

// return target index where a memory region at the address exists, or could be
// inserted
//
// address either is inside the mapping at the returned index, or is in free
// space before the next mapping.
//
// if there is overlap, between regions, ending address will be higher than the
// starting address of the mapping at returned index
static int bsearch_mapped_blocks(const qc_engine *qc, uint64_t address)
{
    int left, right, mid;
    MemoryRegion *mapping;

    left = 0;
    right = qc->mapped_block_count;

    while (left < right) {
        mid = left + (right - left) / 2;

        mapping = qc->mapped_blocks[mid];

        if (mapping->end - 1 < address) {
            left = mid + 1;
        } else if (mapping->addr > address) {
            right = mid;
        } else {
            return mid;
        }
    }

    return left;
}

// find if a memory range overlaps with existing mapped regions
static bool memory_overlap(struct qc_struct *qc, uint64_t begin, size_t size)
{
    unsigned int i;
    uint64_t end = begin + size - 1;

    i = bsearch_mapped_blocks(qc, begin);

    // is this the highest region with no possible overlap?
    if (i >= qc->mapped_block_count)
        return false;

    // end address overlaps this region?
    if (end >= qc->mapped_blocks[i]->addr)
        return true;

    // not found
    return false;
}

// common setup/error checking shared between qc_mem_map and qc_mem_map_ptr
static qc_err mem_map(qc_engine *qc, uint64_t address, size_t size,
                      uint32_t perms, MemoryRegion *block)
{
    MemoryRegion **regions;
    int pos;

    if (block == NULL) {
        return QC_ERR_NOMEM;
    }

    if ((qc->mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) { // time to grow
        regions = (MemoryRegion **)g_realloc(
            qc->mapped_blocks,
            sizeof(MemoryRegion *) * (qc->mapped_block_count + MEM_BLOCK_INCR));
        if (regions == NULL) {
            return QC_ERR_NOMEM;
        }
        qc->mapped_blocks = regions;
    }

    pos = bsearch_mapped_blocks(qc, block->addr);

    // shift the array right to give space for the new pointer
    memmove(&qc->mapped_blocks[pos + 1], &qc->mapped_blocks[pos],
            sizeof(MemoryRegion *) * (qc->mapped_block_count - pos));

    qc->mapped_blocks[pos] = block;
    qc->mapped_block_count++;

    return QC_ERR_OK;
}

static qc_err mem_map_check(qc_engine *qc, uint64_t address, size_t size,
                            uint32_t perms)
{
    if (size == 0) {
        // invalid memory mapping
        return QC_ERR_ARG;
    }

    // address cannot wrapp around
    if (address + size - 1 < address) {
        return QC_ERR_ARG;
    }

    // address must be aligned to qc->target_page_size
    if ((address & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    // size must be multiple of qc->target_page_size
    if ((size & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    // check for only valid permissions
    if ((perms & ~QC_PROT_ALL) != 0) {
        return QC_ERR_ARG;
    }

    // this area overlaps existing mapped regions?
    if (memory_overlap(qc, address, size)) {
        return QC_ERR_MAP;
    }

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_mem_map(qc_engine *qc, uint64_t address, size_t size, uint32_t perms)
{
    qc_err res;

    QC_INIT(qc);

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    res = mem_map_check(qc, address, size, perms);
    if (res) {
        return res;
    }

    return mem_map(qc, address, size, perms,
                   qc->memory_map(qc, address, size, perms));
}

QNICORN_EXPORT
qc_err qc_mem_map_ptr(qc_engine *qc, uint64_t address, size_t size,
                      uint32_t perms, void *ptr)
{
    qc_err res;

    QC_INIT(qc);

    if (ptr == NULL) {
        return QC_ERR_ARG;
    }

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    res = mem_map_check(qc, address, size, perms);
    if (res) {
        return res;
    }

    return mem_map(qc, address, size, QC_PROT_ALL,
                   qc->memory_map_ptr(qc, address, size, perms, ptr));
}

QNICORN_EXPORT
qc_err qc_mmio_map(qc_engine *qc, uint64_t address, size_t size,
                   qc_cb_mmio_read_t read_cb, void *user_data_read,
                   qc_cb_mmio_write_t write_cb, void *user_data_write)
{
    qc_err res;

    QC_INIT(qc);

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    res = mem_map_check(qc, address, size, QC_PROT_ALL);
    if (res)
        return res;

    // The callbacks do not need to be checked for NULL here, as their presence
    // (or lack thereof) will determine the permissions used.
    return mem_map(qc, address, size, QC_PROT_NONE,
                   qc->memory_map_io(qc, address, size, read_cb, write_cb,
                                     user_data_read, user_data_write));
}

// Create a backup copy of the indicated MemoryRegion.
// Generally used in prepartion for splitting a MemoryRegion.
static uint8_t *copy_region(struct qc_struct *qc, MemoryRegion *mr)
{
    uint8_t *block = (uint8_t *)g_malloc0((size_t)int128_get64(mr->size));
    if (block != NULL) {
        qc_err err =
            qc_mem_read(qc, mr->addr, block, (size_t)int128_get64(mr->size));
        if (err != QC_ERR_OK) {
            free(block);
            block = NULL;
        }
    }

    return block;
}

/*
   Split the given MemoryRegion at the indicated address for the indicated size
   this may result in the create of up to 3 spanning sections. If the delete
   parameter is true, the no new section will be created to replace the indicate
   range. This functions exists to support qc_mem_protect and qc_mem_unmap.

   This is a static function and callers have already done some preliminary
   parameter validation.

   The do_delete argument indicates that we are being called to support
   qc_mem_unmap. In this case we save some time by choosing NOT to remap
   the areas that are intended to get unmapped
 */
// TODO: investigate whether qemu region manipulation functions already offered
// this capability
static bool split_region(struct qc_struct *qc, MemoryRegion *mr,
                         uint64_t address, size_t size, bool do_delete)
{
    uint8_t *backup;
    uint32_t perms;
    uint64_t begin, end, chunk_end;
    size_t l_size, m_size, r_size;
    RAMBlock *block = NULL;
    bool prealloc = false;

    chunk_end = address + size;

    // if this region belongs to area [address, address+size],
    // then there is no work to do.
    if (address <= mr->addr && chunk_end >= mr->end) {
        return true;
    }

    if (size == 0) {
        // trivial case
        return true;
    }

    if (address >= mr->end || chunk_end <= mr->addr) {
        // impossible case
        return false;
    }

    QLIST_FOREACH(block, &qc->ram_list.blocks, next)
    {
        if (block->offset <= mr->addr &&
            block->used_length >= (mr->end - mr->addr)) {
            break;
        }
    }

    if (block == NULL) {
        return false;
    }

    // RAM_PREALLOC is not defined outside exec.c and I didn't feel like
    // moving it
    prealloc = !!(block->flags & 1);

    if (block->flags & 1) {
        backup = block->host;
    } else {
        backup = copy_region(qc, mr);
        if (backup == NULL) {
            return false;
        }
    }

    // save the essential information required for the split before mr gets
    // deleted
    perms = mr->perms;
    begin = mr->addr;
    end = mr->end;

    // unmap this region first, then do split it later
    if (qc_mem_unmap(qc, mr->addr, (size_t)int128_get64(mr->size)) !=
        QC_ERR_OK) {
        goto error;
    }

    /* overlapping cases
     *               |------mr------|
     * case 1    |---size--|
     * case 2           |--size--|
     * case 3                  |---size--|
     */

    // adjust some things
    if (address < begin) {
        address = begin;
    }
    if (chunk_end > end) {
        chunk_end = end;
    }

    // compute sub region sizes
    l_size = (size_t)(address - begin);
    r_size = (size_t)(end - chunk_end);
    m_size = (size_t)(chunk_end - address);

    // If there are error in any of the below operations, things are too far
    // gone at that point to recover. Could try to remap orignal region, but
    // these smaller allocation just failed so no guarantee that we can recover
    // the original allocation at this point
    if (l_size > 0) {
        if (!prealloc) {
            if (qc_mem_map(qc, begin, l_size, perms) != QC_ERR_OK) {
                goto error;
            }
            if (qc_mem_write(qc, begin, backup, l_size) != QC_ERR_OK) {
                goto error;
            }
        } else {
            if (qc_mem_map_ptr(qc, begin, l_size, perms, backup) != QC_ERR_OK) {
                goto error;
            }
        }
    }

    if (m_size > 0 && !do_delete) {
        if (!prealloc) {
            if (qc_mem_map(qc, address, m_size, perms) != QC_ERR_OK) {
                goto error;
            }
            if (qc_mem_write(qc, address, backup + l_size, m_size) !=
                QC_ERR_OK) {
                goto error;
            }
        } else {
            if (qc_mem_map_ptr(qc, address, m_size, perms, backup + l_size) !=
                QC_ERR_OK) {
                goto error;
            }
        }
    }

    if (r_size > 0) {
        if (!prealloc) {
            if (qc_mem_map(qc, chunk_end, r_size, perms) != QC_ERR_OK) {
                goto error;
            }
            if (qc_mem_write(qc, chunk_end, backup + l_size + m_size, r_size) !=
                QC_ERR_OK) {
                goto error;
            }
        } else {
            if (qc_mem_map_ptr(qc, chunk_end, r_size, perms,
                               backup + l_size + m_size) != QC_ERR_OK) {
                goto error;
            }
        }
    }

    if (!prealloc) {
        free(backup);
    }
    return true;

error:
    if (!prealloc) {
        free(backup);
    }
    return false;
}

QNICORN_EXPORT
qc_err qc_mem_protect(struct qc_struct *qc, uint64_t address, size_t size,
                      uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    size_t count, len;
    bool remove_exec = false;

    QC_INIT(qc);

    if (size == 0) {
        // trivial case, no change
        return QC_ERR_OK;
    }

    // address must be aligned to qc->target_page_size
    if ((address & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    // size must be multiple of qc->target_page_size
    if ((size & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    // check for only valid permissions
    if ((perms & ~QC_PROT_ALL) != 0) {
        return QC_ERR_ARG;
    }

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(qc, address, size)) {
        return QC_ERR_NOMEM;
    }

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while (count < size) {
        mr = memory_mapping(qc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(qc, mr, addr, len, false)) {
            return QC_ERR_NOMEM;
        }

        mr = memory_mapping(qc, addr);
        // will this remove EXEC permission?
        if (((mr->perms & QC_PROT_EXEC) != 0) &&
            ((perms & QC_PROT_EXEC) == 0)) {
            remove_exec = true;
        }
        mr->perms = perms;
        qc->readonly_mem(mr, (perms & QC_PROT_WRITE) == 0);

        count += len;
        addr += len;
    }

    // if EXEC permission is removed, then quit TB and continue at the same
    // place
    if (remove_exec) {
        qc->quit_request = true;
        qc_emu_stop(qc);
    }

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_mem_unmap(struct qc_struct *qc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    QC_INIT(qc);

    if (size == 0) {
        // nothing to unmap
        return QC_ERR_OK;
    }

    // address must be aligned to qc->target_page_size
    if ((address & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    // size must be multiple of qc->target_page_size
    if ((size & qc->target_page_align) != 0) {
        return QC_ERR_ARG;
    }

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(qc, address, size)) {
        return QC_ERR_NOMEM;
    }

    // Now we know entire region is mapped, so do the unmap
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while (count < size) {
        mr = memory_mapping(qc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(qc, mr, addr, len, true)) {
            return QC_ERR_NOMEM;
        }

        // if we can retrieve the mapping, then no splitting took place
        // so unmap here
        mr = memory_mapping(qc, addr);
        if (mr != NULL) {
            qc->memory_unmap(qc, mr);
        }
        count += len;
        addr += len;
    }

    return QC_ERR_OK;
}

// find the memory region of this address
MemoryRegion *memory_mapping(struct qc_struct *qc, uint64_t address)
{
    unsigned int i;

    if (qc->mapped_block_count == 0) {
        return NULL;
    }

    if (qc->mem_redirect) {
        address = qc->mem_redirect(address);
    }

    // try with the cache index first
    i = qc->mapped_block_cache_index;

    if (i < qc->mapped_block_count && address >= qc->mapped_blocks[i]->addr &&
        address < qc->mapped_blocks[i]->end) {
        return qc->mapped_blocks[i];
    }

    i = bsearch_mapped_blocks(qc, address);

    if (i < qc->mapped_block_count && address >= qc->mapped_blocks[i]->addr &&
        address <= qc->mapped_blocks[i]->end - 1)
        return qc->mapped_blocks[i];

    // not found
    return NULL;
}

QNICORN_EXPORT
qc_err qc_hook_add(qc_engine *qc, qc_hook *hh, int type, void *callback,
                   void *user_data, uint64_t begin, uint64_t end, ...)
{
    int ret = QC_ERR_OK;
    int i = 0;

    QC_INIT(qc);

    struct hook *hook = calloc(1, sizeof(struct hook));
    if (hook == NULL) {
        return QC_ERR_NOMEM;
    }

    hook->begin = begin;
    hook->end = end;
    hook->type = type;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->refs = 0;
    hook->to_delete = false;
    *hh = (qc_hook)hook;

    // QC_HOOK_INSN has an extra argument for instruction ID
    if (type & QC_HOOK_INSN) {
        va_list valist;

        va_start(valist, end);
        hook->insn = va_arg(valist, int);
        va_end(valist);

        if (qc->insn_hook_validate) {
            if (!qc->insn_hook_validate(hook->insn)) {
                free(hook);
                return QC_ERR_HOOK;
            }
        }

        if (qc->hook_insert) {
            if (list_insert(&qc->hook[QC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return QC_ERR_NOMEM;
            }
        } else {
            if (list_append(&qc->hook[QC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return QC_ERR_NOMEM;
            }
        }

        hook->refs++;
        return QC_ERR_OK;
    }

    if (type & QC_HOOK_TCG_OPCODE) {
        va_list valist;

        va_start(valist, end);
        hook->op = va_arg(valist, int);
        hook->op_flags = va_arg(valist, int);
        va_end(valist);

        if (qc->opcode_hook_invalidate) {
            if (!qc->opcode_hook_invalidate(hook->op, hook->op_flags)) {
                free(hook);
                return QC_ERR_HOOK;
            }
        }

        if (qc->hook_insert) {
            if (list_insert(&qc->hook[QC_HOOK_TCG_OPCODE_IDX], hook) == NULL) {
                free(hook);
                return QC_ERR_NOMEM;
            }
        } else {
            if (list_append(&qc->hook[QC_HOOK_TCG_OPCODE_IDX], hook) == NULL) {
                free(hook);
                return QC_ERR_NOMEM;
            }
        }

        hook->refs++;
        return QC_ERR_OK;
    }

    while ((type >> i) > 0) {
        if ((type >> i) & 1) {
            // TODO: invalid hook error?
            if (i < QC_HOOK_MAX) {
                if (qc->hook_insert) {
                    if (list_insert(&qc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return QC_ERR_NOMEM;
                    }
                } else {
                    if (list_append(&qc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return QC_ERR_NOMEM;
                    }
                }
                hook->refs++;
            }
        }
        i++;
    }

    // we didn't use the hook
    // TODO: return an error?
    if (hook->refs == 0) {
        free(hook);
    }

    return ret;
}

QNICORN_EXPORT
qc_err qc_hook_del(qc_engine *qc, qc_hook hh)
{
    int i;
    struct hook *hook = (struct hook *)hh;

    QC_INIT(qc);

    // we can't dereference hook->type if hook is invalid
    // so for now we need to iterate over all possible types to remove the hook
    // which is less efficient
    // an optimization would be to align the hook pointer
    // and store the type mask in the hook pointer.
    for (i = 0; i < QC_HOOK_MAX; i++) {
        if (list_exists(&qc->hook[i], (void *)hook)) {
            hook->to_delete = true;
            list_append(&qc->hooks_to_del, hook);
        }
    }

    return QC_ERR_OK;
}

// TCG helper
// 2 arguments are enough for most opcodes. Load/Store needs 3 arguments but we
// have memory hooks already. We may exceed the maximum arguments of a tcg
// helper but that's easy to extend.
void helper_qc_traceopcode(struct hook *hook, uint64_t arg1, uint64_t arg2,
                           void *handle, uint64_t address);
void helper_qc_traceopcode(struct hook *hook, uint64_t arg1, uint64_t arg2,
                           void *handle, uint64_t address)
{
    struct qc_struct *qc = handle;

    if (unlikely(qc->stop_request)) {
        return;
    }

    if (unlikely(hook->to_delete)) {
        return;
    }

    // We did all checks in translation time.
    //
    // This could optimize the case that we have multiple hooks with different
    // opcodes and have one callback per opcode. Note that the assumption don't
    // hold in most cases for qc_tracecode.
    //
    // TODO: Shall we have a flag to allow users to control whether updating PC?
    ((qc_hook_tcg_op_2)hook->callback)(qc, address, arg1, arg2,
                                       hook->user_data);

    if (unlikely(qc->stop_request)) {
        return;
    }
}

void helper_qc_tracecode(int32_t size, qc_hook_idx index, void *handle,
                         int64_t address);
void helper_qc_tracecode(int32_t size, qc_hook_idx index, void *handle,
                         int64_t address)
{
    struct qc_struct *qc = handle;
    struct list_item *cur;
    struct hook *hook;
    int hook_flags =
        index &
        QC_HOOK_FLAG_MASK; // The index here may contain additional flags. See
                           // the comments of qc_hook_idx for details.

    index = index & QC_HOOK_IDX_MASK;

    // sync PC in CPUArchState with address
    if (qc->set_pc) {
        qc->set_pc(qc, address);
    }

    // the last callback may already asked to stop emulation
    if (qc->stop_request && !(hook_flags & QC_HOOK_FLAG_NO_STOP)) {
        return;
    }

    for (cur = qc->hook[index].head;
         cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        if (hook->to_delete) {
            continue;
        }

        // on invalid block/instruction, call instruction counter (if enable),
        // then quit
        if (size == 0) {
            if (index == QC_HOOK_CODE_IDX && qc->count_hook) {
                // this is the instruction counter (first hook in the list)
                ((qc_cb_hookcode_t)hook->callback)(qc, address, size,
                                                   hook->user_data);
            }

            return;
        }

        if (HOOK_BOUND_CHECK(hook, (uint64_t)address)) {
            ((qc_cb_hookcode_t)hook->callback)(qc, address, size,
                                               hook->user_data);
        }

        // the last callback may already asked to stop emulation
        // Unicorn:
        //   In an ARM IT block, we behave like the emulation continues
        //   normally. No check_exit_request is generated and the hooks are
        //   triggered normally. In other words, the whole IT block is treated
        //   as a single instruction.
        if (qc->stop_request && !(hook_flags & QC_HOOK_FLAG_NO_STOP)) {
            break;
        }
    }
}

QNICORN_EXPORT
qc_err qc_mem_regions(qc_engine *qc, qc_mem_region **regions, uint32_t *count)
{
    uint32_t i;
    qc_mem_region *r = NULL;

    QC_INIT(qc);

    *count = qc->mapped_block_count;

    if (*count) {
        r = g_malloc0(*count * sizeof(qc_mem_region));
        if (r == NULL) {
            // out of memory
            return QC_ERR_NOMEM;
        }
    }

    for (i = 0; i < *count; i++) {
        r[i].begin = qc->mapped_blocks[i]->addr;
        r[i].end = qc->mapped_blocks[i]->end - 1;
        r[i].perms = qc->mapped_blocks[i]->perms;
    }

    *regions = r;

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_query(qc_engine *qc, qc_query_type type, size_t *result)
{
    QC_INIT(qc);

    switch (type) {
    default:
        return QC_ERR_ARG;

    case QC_QUERY_PAGE_SIZE:
        *result = qc->target_page_size;
        break;

    case QC_QUERY_ARCH:
        *result = qc->arch;
        break;

    case QC_QUERY_MODE:
#ifdef QNICORN_HAS_ARM
        if (qc->arch == QC_ARCH_ARM) {
            return qc->query(qc, type, result);
        }
#endif
        *result = qc->mode;
        break;

    case QC_QUERY_TIMEOUT:
        *result = qc->timed_out;
        break;
    }

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_context_alloc(qc_engine *qc, qc_context **context)
{
    struct qc_context **_context = context;
    size_t size = qc_context_size(qc);

    QC_INIT(qc);

    *_context = g_malloc(size);
    if (*_context) {
        (*_context)->jmp_env_size = sizeof(*qc->cpu->jmp_env);
        (*_context)->context_size = qc->cpu_context_size;
        (*_context)->arch = qc->arch;
        (*_context)->mode = qc->mode;
        (*_context)->qc = qc;
        if (list_insert(&qc->saved_contexts, *_context)) {
            return QC_ERR_OK;
        } else {
            return QC_ERR_NOMEM;
        }
    } else {
        return QC_ERR_NOMEM;
    }
}

QNICORN_EXPORT
qc_err qc_free(void *mem)
{
    g_free(mem);
    return QC_ERR_OK;
}

QNICORN_EXPORT
size_t qc_context_size(qc_engine *qc)
{
    QC_INIT(qc);
    // return the total size of struct qc_context
    return sizeof(qc_context) + qc->cpu_context_size +
           sizeof(*qc->cpu->jmp_env);
}

QNICORN_EXPORT
qc_err qc_context_save(qc_engine *qc, qc_context *context)
{
    QC_INIT(qc);

    memcpy(context->data, qc->cpu->env_ptr, context->context_size);
    memcpy(context->data + context->context_size, qc->cpu->jmp_env,
           context->jmp_env_size);

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_context_reg_write(qc_context *ctx, int regid, const void *value)
{
    return qc_context_reg_write_batch(ctx, &regid, (void *const *)&value, 1);
}

QNICORN_EXPORT
qc_err qc_context_reg_read(qc_context *ctx, int regid, void *value)
{
    return qc_context_reg_read_batch(ctx, &regid, &value, 1);
}

// Keep in mind that we don't a qc_engine when r/w the registers of a context.
static void find_context_reg_rw_function(qc_arch arch, qc_mode mode,
                                         context_reg_rw_t *rw)
{
    // We believe that the arch/mode pair is correct.
    switch (arch) {
    default:
        rw->context_reg_read = NULL;
        rw->context_reg_write = NULL;
        break;
#ifdef QNICORN_HAS_M68K
    case QC_ARCH_M68K:
        rw->context_reg_read = m68k_context_reg_read;
        rw->context_reg_write = m68k_context_reg_write;
        break;
#endif
#ifdef QNICORN_HAS_X86
    case QC_ARCH_X86:
        rw->context_reg_read = x86_context_reg_read;
        rw->context_reg_write = x86_context_reg_write;
        break;
#endif
#ifdef QNICORN_HAS_ARM
    case QC_ARCH_ARM:
        if (mode & QC_MODE_BIG_ENDIAN) {
            rw->context_reg_read = armeb_context_reg_read;
            rw->context_reg_write = armeb_context_reg_write;
        } else {
            rw->context_reg_read = arm_context_reg_read;
            rw->context_reg_write = arm_context_reg_write;
        }
#endif
#ifdef QNICORN_HAS_ARM64
    case QC_ARCH_ARM64:
        if (mode & QC_MODE_BIG_ENDIAN) {
            rw->context_reg_read = arm64eb_context_reg_read;
            rw->context_reg_write = arm64eb_context_reg_write;
        } else {
            rw->context_reg_read = arm64_context_reg_read;
            rw->context_reg_write = arm64_context_reg_write;
        }
        break;
#endif

#if defined(QNICORN_HAS_MIPS) || defined(QNICORN_HAS_MIPSEL) ||                \
    defined(QNICORN_HAS_MIPS64) || defined(QNICORN_HAS_MIPS64EL)
    case QC_ARCH_MIPS:
        if (mode & QC_MODE_BIG_ENDIAN) {
#ifdef QNICORN_HAS_MIPS
            if (mode & QC_MODE_MIPS32) {
                rw->context_reg_read = mips_context_reg_read;
                rw->context_reg_write = mips_context_reg_write;
            }
#endif
#ifdef QNICORN_HAS_MIPS64
            if (mode & QC_MODE_MIPS64) {
                rw->context_reg_read = mips64_context_reg_read;
                rw->context_reg_write = mips64_context_reg_write;
            }
#endif
        } else { // little endian
#ifdef QNICORN_HAS_MIPSEL
            if (mode & QC_MODE_MIPS32) {
                rw->context_reg_read = mipsel_context_reg_read;
                rw->context_reg_write = mipsel_context_reg_write;
            }
#endif
#ifdef QNICORN_HAS_MIPS64EL
            if (mode & QC_MODE_MIPS64) {
                rw->context_reg_read = mips64el_context_reg_read;
                rw->context_reg_write = mips64el_context_reg_write;
            }
#endif
        }
        break;
#endif

#ifdef QNICORN_HAS_SPARC
    case QC_ARCH_SPARC:
        if (mode & QC_MODE_SPARC64) {
            rw->context_reg_read = sparc64_context_reg_read;
            rw->context_reg_write = sparc64_context_reg_write;
        } else {
            rw->context_reg_read = sparc_context_reg_read;
            rw->context_reg_write = sparc_context_reg_write;
        }
        break;
#endif
#ifdef QNICORN_HAS_PPC
    case QC_ARCH_PPC:
        if (mode & QC_MODE_PPC64) {
            rw->context_reg_read = ppc64_context_reg_read;
            rw->context_reg_write = ppc64_context_reg_write;
        } else {
            rw->context_reg_read = ppc_context_reg_read;
            rw->context_reg_write = ppc_context_reg_write;
        }
        break;
#endif
#ifdef QNICORN_HAS_RISCV
    case QC_ARCH_RISCV:
        if (mode & QC_MODE_RISCV32) {
            rw->context_reg_read = riscv32_context_reg_read;
            rw->context_reg_write = riscv32_context_reg_write;
        } else if (mode & QC_MODE_RISCV64) {
            rw->context_reg_read = riscv64_context_reg_read;
            rw->context_reg_write = riscv64_context_reg_write;
        }
        break;
#endif
    }

    return;
}

QNICORN_EXPORT
qc_err qc_context_reg_write_batch(qc_context *ctx, int *ids, void *const *vals,
                                  int count)
{
    int ret = QC_ERR_OK;
    context_reg_rw_t rw;

    find_context_reg_rw_function(ctx->arch, ctx->mode, &rw);
    if (rw.context_reg_write) {
        ret = rw.context_reg_write(ctx, (unsigned int *)ids, vals, count);
    } else {
        return QC_ERR_HANDLE;
    }

    return ret;
}

QNICORN_EXPORT
qc_err qc_context_reg_read_batch(qc_context *ctx, int *ids, void **vals,
                                 int count)
{
    int ret = QC_ERR_OK;
    context_reg_rw_t rw;

    find_context_reg_rw_function(ctx->arch, ctx->mode, &rw);
    if (rw.context_reg_read) {
        ret = rw.context_reg_read(ctx, (unsigned int *)ids, vals, count);
    } else {
        return QC_ERR_HANDLE;
    }

    return ret;
}

QNICORN_EXPORT
qc_err qc_context_restore(qc_engine *qc, qc_context *context)
{
    QC_INIT(qc);

    memcpy(qc->cpu->env_ptr, context->data, context->context_size);
    if (list_exists(&qc->saved_contexts, context)) {
        memcpy(qc->cpu->jmp_env, context->data + context->context_size,
               context->jmp_env_size);
    }

    return QC_ERR_OK;
}

QNICORN_EXPORT
qc_err qc_context_free(qc_context *context)
{
    qc_engine *qc = context->qc;
    // if qc is NULL, it means that qc_engine has been free-ed.
    if (qc) {
        list_remove(&qc->saved_contexts, context);
    }
    return qc_free(context);
}

typedef struct _qc_ctl_exit_request {
    uint64_t *array;
    size_t len;
} qc_ctl_exit_request;

static inline gboolean qc_read_exit_iter(gpointer key, gpointer val,
                                         gpointer data)
{
    qc_ctl_exit_request *req = (qc_ctl_exit_request *)data;

    req->array[req->len++] = *(uint64_t *)key;

    return false;
}

QNICORN_EXPORT
qc_err qc_ctl(qc_engine *qc, qc_control_type control, ...)
{
    int rw, type;
    qc_err err = QC_ERR_OK;
    va_list args;

    // MSVC Would do signed shift on signed integers.
    rw = (uint32_t)control >> 30;
    type = (control & ((1 << 16) - 1));
    va_start(args, control);

    switch (type) {
    case QC_CTL_QC_MODE: {
        if (rw == QC_CTL_IO_READ) {
            int *pmode = va_arg(args, int *);
            *pmode = qc->mode;
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_QC_ARCH: {
        if (rw == QC_CTL_IO_READ) {
            int *arch = va_arg(args, int *);
            *arch = qc->arch;
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_QC_TIMEOUT: {
        if (rw == QC_CTL_IO_READ) {
            uint64_t *arch = va_arg(args, uint64_t *);
            *arch = qc->timeout;
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_QC_PAGE_SIZE: {
        if (rw == QC_CTL_IO_READ) {

            QC_INIT(qc);

            uint32_t *page_size = va_arg(args, uint32_t *);
            *page_size = qc->target_page_size;
        } else {
            uint32_t page_size = va_arg(args, uint32_t);
            int bits = 0;

            if (qc->init_done) {
                err = QC_ERR_ARG;
                break;
            }

            if (qc->arch != QC_ARCH_ARM) {
                err = QC_ERR_ARG;
                break;
            }

            if ((page_size & (page_size - 1))) {
                err = QC_ERR_ARG;
                break;
            }

            while (page_size) {
                bits++;
                page_size >>= 1;
            }

            qc->target_bits = bits;

            err = QC_ERR_OK;
        }
        break;
    }

    case QC_CTL_QC_USE_EXITS: {
        if (rw == QC_CTL_IO_WRITE) {
            int use_exits = va_arg(args, int);
            qc->use_exits = use_exits;
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_QC_EXITS_CNT: {

        QC_INIT(qc);

        if (!qc->use_exits) {
            err = QC_ERR_ARG;
        } else if (rw == QC_CTL_IO_READ) {
            size_t *exits_cnt = va_arg(args, size_t *);
            *exits_cnt = g_tree_nnodes(qc->exits);
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_QC_EXITS: {

        QC_INIT(qc);

        if (!qc->use_exits) {
            err = QC_ERR_ARG;
        } else if (rw == QC_CTL_IO_READ) {
            uint64_t *exits = va_arg(args, uint64_t *);
            size_t cnt = va_arg(args, size_t);
            if (cnt < g_tree_nnodes(qc->exits)) {
                err = QC_ERR_ARG;
            } else {
                qc_ctl_exit_request req;
                req.array = exits;
                req.len = 0;

                g_tree_foreach(qc->exits, qc_read_exit_iter, (void *)&req);
            }
        } else if (rw == QC_CTL_IO_WRITE) {
            uint64_t *exits = va_arg(args, uint64_t *);
            size_t cnt = va_arg(args, size_t);

            g_tree_remove_all(qc->exits);

            for (size_t i = 0; i < cnt; i++) {
                qc_add_exit(qc, exits[i]);
            }
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_CPU_MODEL: {
        if (rw == QC_CTL_IO_READ) {

            QC_INIT(qc);

            int *model = va_arg(args, int *);
            *model = qc->cpu_model;
        } else {
            int model = va_arg(args, int);

            if (qc->init_done) {
                err = QC_ERR_ARG;
                break;
            }

            qc->cpu_model = model;

            err = QC_ERR_OK;
        }
        break;
    }

    case QC_CTL_TB_REQUEST_CACHE: {

        QC_INIT(qc);

        if (rw == QC_CTL_IO_READ_WRITE) {
            uint64_t addr = va_arg(args, uint64_t);
            qc_tb *tb = va_arg(args, qc_tb *);
            err = qc->qc_gen_tb(qc, addr, tb);
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    case QC_CTL_TB_REMOVE_CACHE: {

        QC_INIT(qc);

        if (rw == QC_CTL_IO_WRITE) {
            uint64_t addr = va_arg(args, uint64_t);
            qc->qc_invalidate_tb(qc, addr, 1);
        } else {
            err = QC_ERR_ARG;
        }
        break;
    }

    default:
        err = QC_ERR_ARG;
        break;
    }

    va_end(args);

    return err;
}
