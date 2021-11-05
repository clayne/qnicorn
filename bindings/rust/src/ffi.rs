#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::qnicorn_const::*;
use libc::{c_char, c_int};
use std::ffi::c_void;
use std::pin::Pin;

pub type qc_handle = *mut c_void;
pub type qc_hook = *mut c_void;
pub type qc_context = libc::size_t;

extern "C" {
    pub fn qc_version(major: *mut u32, minor: *mut u32) -> u32;
    pub fn qc_arch_supported(arch: Arch) -> bool;
    pub fn qc_open(arch: Arch, mode: Mode, engine: *mut qc_handle) -> qc_error;
    pub fn qc_close(engine: qc_handle) -> qc_error;
    pub fn qc_context_free(mem: qc_context) -> qc_error;
    pub fn qc_errno(engine: qc_handle) -> qc_error;
    pub fn qc_strerror(error_code: qc_error) -> *const c_char;
    pub fn qc_reg_write(engine: qc_handle, regid: c_int, value: *const c_void) -> qc_error;
    pub fn qc_reg_read(engine: qc_handle, regid: c_int, value: *mut c_void) -> qc_error;
    pub fn qc_mem_write(
        engine: qc_handle,
        address: u64,
        bytes: *const u8,
        size: libc::size_t,
    ) -> qc_error;
    pub fn qc_mem_read(
        engine: qc_handle,
        address: u64,
        bytes: *mut u8,
        size: libc::size_t,
    ) -> qc_error;
    pub fn qc_mem_map(engine: qc_handle, address: u64, size: libc::size_t, perms: u32) -> qc_error;
    pub fn qc_mem_map_ptr(
        engine: qc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
        ptr: *mut c_void,
    ) -> qc_error;
    pub fn qc_mem_unmap(engine: qc_handle, address: u64, size: libc::size_t) -> qc_error;
    pub fn qc_mem_protect(
        engine: qc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
    ) -> qc_error;
    pub fn qc_mem_regions(
        engine: qc_handle,
        regions: *const *const MemRegion,
        count: *mut u32,
    ) -> qc_error;
    pub fn qc_emu_start(
        engine: qc_handle,
        begin: u64,
        until: u64,
        timeout: u64,
        count: libc::size_t,
    ) -> qc_error;
    pub fn qc_emu_stop(engine: qc_handle) -> qc_error;
    pub fn qc_hook_add(
        engine: qc_handle,
        hook: *mut qc_hook,
        hook_type: HookType,
        callback: *mut c_void,
        user_data: *mut c_void,
        begin: u64,
        end: u64,
        ...
    ) -> qc_error;
    pub fn qc_hook_del(engine: qc_handle, hook: qc_hook) -> qc_error;
    pub fn qc_query(engine: qc_handle, query_type: Query, result: *mut libc::size_t) -> qc_error;
    pub fn qc_context_alloc(engine: qc_handle, context: *mut qc_context) -> qc_error;
    pub fn qc_context_save(engine: qc_handle, context: qc_context) -> qc_error;
    pub fn qc_context_restore(engine: qc_handle, context: qc_context) -> qc_error;
}

pub struct CodeHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, u64, u32)>,
}

pub struct BlockHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, u64, u32)>,
}

pub struct MemHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, MemType, u64, usize, i64)>,
}

pub struct InterruptHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, u32)>,
}

pub struct InstructionInHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, u32, usize)>,
}

pub struct InstructionOutHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle, u32, usize, u32)>,
}

pub struct InstructionSysHook {
    pub qnicorn: *mut crate::QnicornInner,
    pub callback: Box<dyn FnMut(crate::QnicornHandle)>,
}

pub extern "C" fn code_hook_proxy(
    qc: qc_handle,
    address: u64,
    size: u32,
    user_data: *mut CodeHook,
) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        address,
        size,
    );
}

pub extern "C" fn block_hook_proxy(
    qc: qc_handle,
    address: u64,
    size: u32,
    user_data: *mut BlockHook,
) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        address,
        size,
    );
}

pub extern "C" fn mem_hook_proxy(
    qc: qc_handle,
    mem_type: MemType,
    address: u64,
    size: u32,
    value: i64,
    user_data: *mut MemHook,
) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        mem_type,
        address,
        size as usize,
        value,
    );
}

pub extern "C" fn intr_hook_proxy(qc: qc_handle, value: u32, user_data: *mut InterruptHook) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        value,
    );
}

pub extern "C" fn insn_in_hook_proxy(
    qc: qc_handle,
    port: u32,
    size: usize,
    user_data: *mut InstructionInHook,
) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        port,
        size,
    );
}

pub extern "C" fn insn_out_hook_proxy(
    qc: qc_handle,
    port: u32,
    size: usize,
    value: u32,
    user_data: *mut InstructionOutHook,
) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(
        crate::QnicornHandle {
            inner: unsafe { Pin::new_unchecked(qnicorn) },
        },
        port,
        size,
        value,
    );
}

pub extern "C" fn insn_sys_hook_proxy(qc: qc_handle, user_data: *mut InstructionSysHook) {
    let qnicorn = unsafe { &mut *(*user_data).qnicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(qc, qnicorn.qc);
    callback(crate::QnicornHandle {
        inner: unsafe { Pin::new_unchecked(qnicorn) },
    });
}
