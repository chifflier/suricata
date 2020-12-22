/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use crate::wasm::CallEnv;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;
use wasmtime::{Caller, Extern, Func, Global, Memory, Store, Trap, WasmTy};

// wrap a function with 0 arguments to add call environment
pub(crate) fn wrap_env0<F, R>(store: &Store, call_env: Rc<RefCell<CallEnv>>, f: F) -> Func
where
    F: Fn(Caller<'_>, &CallEnv) -> Result<R, Trap> + 'static,
    R: WasmTy,
{
    let f = move |caller: Caller<'_>| -> Result<R, Trap> {
        let env = call_env
            // safety: must not be called recursively
            .borrow();
        f(caller, &env)
    };
    Func::wrap(store, f).into()
}

// wrap a function with 1 arguments to add call environment
pub(crate) fn wrap_env1<F, A1, R>(store: &Store, call_env: Rc<RefCell<CallEnv>>, f: F) -> Func
where
    F: Fn(Caller<'_>, &CallEnv, A1) -> Result<R, Trap> + 'static,
    A1: WasmTy,
    R: WasmTy,
{
    let f = move |caller: Caller<'_>, a1: A1| -> Result<R, Trap> {
        let env = call_env
            // safety: must not be called recursively
            .borrow();
        f(caller, &env, a1)
    };
    Func::wrap(store, f).into()
}

// wrap a function with 2 arguments to add call environment
pub(crate) fn wrap_env2<F, A1, A2, R>(store: &Store, call_env: Rc<RefCell<CallEnv>>, f: F) -> Func
where
    F: Fn(Caller<'_>, &CallEnv, A1, A2) -> Result<R, Trap> + 'static,
    A1: WasmTy,
    A2: WasmTy,
    R: WasmTy,
{
    let f = move |caller: Caller<'_>, a1: A1, a2: A2| -> Result<R, Trap> {
        let env = call_env
            // safety: must not be called recursively
            .borrow();
        f(caller, &env, a1, a2)
    };
    Func::wrap(store, f).into()
}

#[inline]
pub(crate) fn wasm_get_caller_memory(caller: &Caller) -> Result<Memory, Trap> {
    match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => Ok(mem),
        _ => return Err(Trap::new("failed to find host memory")),
    }
}

#[inline]
pub(crate) fn wasm_get_caller_function(caller: &Caller, name: &str) -> Result<Func, Trap> {
    match caller.get_export(name) {
        Some(Extern::Func(f)) => Ok(f),
        _ => return Err(Trap::new("failed to find guest function")),
    }
}

pub(crate) fn get_global_str<'a>(mem: &'a Memory, global: &Global) -> Result<&'a str, Trap> {
    let offset = global.get().i32().ok_or(Trap::new(
        "Global has wrong type (expected pointer to string)",
    ))?;
    let s = memory_read_serialized_slice(&mem, offset as u32)?;
    let s = std::str::from_utf8(s).map_err(|_| Trap::new("Invalid UTF-8 encoding"))?;
    Ok(s)
}

// helper function to get a string from memory area, knowing start and length
pub(crate) fn get_memory_str<'a>(mem: &'a Memory, ptr: u32, len: u32) -> Result<&'a str, Trap> {
    let s = get_memory_slice(mem, ptr, len)?;
    std::str::from_utf8(s).map_err(|_| Trap::new("Invalid UTF-8 encoding"))
}

// helper function to get a slice from memory area, knowing start and length
pub(crate) fn get_memory_slice<'a>(mem: &'a Memory, ptr: u32, len: u32) -> Result<&'a [u8], Trap> {
    debug_assert!(mem.data_size() >= (ptr + len) as usize);
    // We're reading raw wasm memory here so we need `unsafe`. Note
    // though that this should be safe because we don't reenter wasm
    // while we're reading wasm memory, nor should we clash with
    // any other memory accessors (assuming they're well-behaved
    // too).
    unsafe {
        let data = mem
            .data_unchecked()
            .get(ptr as usize..)
            .and_then(|arr| arr.get(..len as usize));
        match data {
            Some(data) => Ok(data),
            None => return Err(Trap::new("pointer/length out of bounds")),
        }
    }
}

// helper function to get memory area
pub(crate) fn get_memory_slice_mut<'a>(
    mem: &'a Memory, ptr: u32, len: u32,
) -> Result<&'a mut [u8], Trap> {
    debug_assert!(mem.data_size() >= (ptr + len) as usize);
    // We're reading raw wasm memory here so we need `unsafe`. Note
    // though that this should be safe because we don't reenter wasm
    // while we're reading wasm memory, nor should we clash with
    // any other memory accessors (assuming they're well-behaved
    // too).
    unsafe {
        let data = mem
            .data_unchecked_mut()
            .get_mut(ptr as usize..)
            .and_then(|arr| arr.get_mut(..len as usize));
        match data {
            Some(data) => Ok(data),
            None => return Err(Trap::new("pointer/length out of bounds")),
        }
    }
}

// helper function to read a serialized slice from memory
// a slice is written as [ ptr, len ] (both fields as u32)
pub(crate) fn memory_read_serialized_slice<'a>(
    mem: &'a Memory, ptr: u32,
) -> Result<&'a [u8], Trap> {
    let s_ptr = get_memory_as::<u32>(&mem, ptr as u32)?;
    let s_len = get_memory_as::<u32>(&mem, ptr as u32 + 4)?;
    get_memory_slice(&mem, *s_ptr, *s_len)
}

// Allocate space in guest memory, copy data and return index in guest memory
pub(crate) fn copy_data_to_memory(
    caller: &Caller, ptr: *const u8, len: usize,
) -> Result<u32, Trap> {
    //
    let mem = wasm_get_caller_memory(&caller)?;
    let alloc = wasm_get_caller_function(&caller, "sc_allocate")?;
    let alloc = alloc.get1::<u32, u32>()?;
    //
    let buffer = alloc(len as u32)?;
    let dst = get_memory_slice_mut(&mem, buffer, len as u32)?;
    // safety:, pointers and length are valid (from slices), no alignment requirement (pointer to u8)
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr() as *mut _, len);
    }
    // dst.copy_from_slice(src);
    Ok(buffer)
}

// helper function to get memory area
pub(crate) fn get_memory_as<'a, T: Sized>(mem: &'a Memory, ptr: u32) -> Result<&'a T, Trap> {
    let len = mem::size_of::<T>();
    if mem.data_size() < ptr as usize + len {
        println!("Request for data outside memory");
        return Err(Trap::new("Request for data outside memory"));
    }
    // pointer must be aligned
    if ptr as usize % len != 0 {
        println!("Unaligned pointer cast 0x{:x}", ptr as usize);
        return Err(Trap::new("Unaligned pointer cast"));
    }
    // We're reading raw wasm memory here so we need `unsafe`. Note
    // though that this should be safe because we don't reenter wasm
    // while we're reading wasm memory, nor should we clash with
    // any other memory accessors (assuming they're well-behaved
    // too).
    unsafe {
        let data = mem
            .data_unchecked_mut()
            .get(ptr as usize..)
            .and_then(|arr| arr.get(..len));
        match data {
            Some(data) => {
                // safety: size tested at function start
                // ptr should be aligned, too XXX
                let data = data.as_ptr() as *const T;
                Ok(&*data)
            }
            None => return Err(Trap::new("pointer/length out of bounds")),
        }
    }
}

// helper function to get memory area
pub(crate) fn get_memory_as_mut<'a, T: Sized>(
    mem: &'a Memory, ptr: u32,
) -> Result<&'a mut T, Trap> {
    let len = mem::size_of::<T>();
    if mem.data_size() < ptr as usize + len {
        return Err(Trap::new("Request for data outside memory"));
    }
    // pointer must be aligned
    if ptr as usize % len != 0 {
        return Err(Trap::new("Unaligned pointer cast"));
    }
    // We're reading raw wasm memory here so we need `unsafe`. Note
    // though that this should be safe because we don't reenter wasm
    // while we're reading wasm memory, nor should we clash with
    // any other memory accessors (assuming they're well-behaved
    // too).
    unsafe {
        let data = mem
            .data_unchecked_mut()
            .get_mut(ptr as usize..)
            .and_then(|arr| arr.get_mut(..len));
        match data {
            Some(data) => {
                // safety: size tested at function start
                // ptr should be aligned, too XXX
                let data = data.as_ptr() as *mut T;
                Ok(&mut *data)
            }
            None => return Err(Trap::new("pointer/length out of bounds")),
        }
    }
}
