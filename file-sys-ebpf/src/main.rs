#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(unused_imports)]
mod vmlinux;
use aya_bpf::{
    bindings::path,
    cty::{c_char, c_long},
    helpers::bpf_d_path,
    macros::{lsm, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::LsmContext,
};
use vmlinux::file;
use aya_log_ebpf::info;

pub const PATH_LEN: usize = 512;

use file_sys_common::SuidEvent;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Path {
    pub path: [u8; PATH_LEN],
}

#[map]
static mut SCRATCH: PerCpuArray<SuidEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "NET_EVENTS")]
static NET_EVENTS: PerfEventArray<SuidEvent> =
    PerfEventArray::<SuidEvent>::with_max_entries(1024, 0);

#[inline(always)]
pub fn my_bpf_d_path(path: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
    let ret = unsafe { bpf_d_path(path, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if ret < 0 {
        return Err(ret);
    }

    Ok(ret as usize)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let buf = unsafe { SCRATCH.get_ptr_mut(0).ok_or(0) }?;

    let _p: &str = unsafe {
        let f: *const file = ctx.arg(0);
        let p = &(*f).f_path as *const _ as *mut path;
        let len = my_bpf_d_path(p, &mut (*buf).path).map_err(|e| e as i32)?;
        if len >= PATH_LEN {
            return Err(0);
        }
        core::str::from_utf8_unchecked(&(*buf).path[..len])
    };
    NET_EVENTS.output(&ctx, unsafe { &*buf }, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
