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

// Developers:
// Allowed types for signatures only allow types `i32`, `u32`, `i64`, `u64`,
// `f32` and `f64`.
//
// Make sure to check this carefully!
use crate::core::{AppProto, Flow};
use crate::wasm::runtime_tls::*;
use crate::wasm::runtime_util::*;
use crate::wasm::CallEnv;
use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Rc;
use std::str;
use wasmtime::{Caller, Extern, Func, Module, Store, Trap};

extern "C" {
    fn wasm_app_proto_to_string(app_proto: AppProto) -> *const libc::c_char;
    fn wasm_get_flow_app_proto(f: *const Flow) -> AppProto;
    fn wasm_packet_timestamp(p: *const libc::c_void, sec: &mut u64, usec: &mut u64);
}

// resolve imports, wasmtime expects them in order!
pub(crate) fn wasm_create_import(
    store: &Store, module: &Module, call_env: Rc<RefCell<CallEnv>>,
) -> Vec<Extern> {
    let mut imports = Vec::new();
    for import in module.imports() {
        match import.name() {
            "abort" => imports.push(Func::wrap(&store, abort).into()),
            "hc_log" => imports.push(Func::wrap(&store, hc_log).into()),
            "hc_print_str" => imports.push(Func::wrap(&store, hc_print_str).into()),
            "hc_tls_get_cert_serial" => {
                imports.push(wrap_env0(store, call_env.clone(), hc_tls_get_cert_serial).into())
            }
            "hc_tls_get_sni" => {
                imports.push(wrap_env0(store, call_env.clone(), hc_tls_get_sni).into())
            }
            "SCFlowAppLayerProto" => {
                imports.push(wrap_env0(store, call_env.clone(), sc_flow_app_layer_proto).into())
            }
            "SCLogInfo" => imports.push(Func::wrap(&store, sc_log_info).into()),
            "SCPacketTimestamp" => {
                imports.push(wrap_env2(store, call_env.clone(), sc_packet_timestamp).into())
            }
            s => {
                SCLogError!("WASM: unknown import '{}' requested", s);
            }
        }
    }
    imports
}

fn sc_packet_timestamp(caller: Caller<'_>, env: &CallEnv, sec: u32, usec: u32) -> Result<(), Trap> {
    let mut val_sec: u64 = 0;
    let mut val_usec: u64 = 0;
    let mem = wasm_get_caller_memory(&caller)?;
    if env.packet.is_null() {
        return Err(Trap::new("Internal error: no packet"));
    }
    unsafe { wasm_packet_timestamp(env.packet, &mut val_sec, &mut val_usec) };
    let data_sec = get_memory_slice_mut(&mem, sec, 8)?;
    let data_usec = get_memory_slice_mut(&mem, usec, 8)?;
    // safety: get_memory_slice_mut tests pointer and length
    // safety: copy byte per byte, we don't know if `val_sec` is aligned for u64
    unsafe {
        std::ptr::copy_nonoverlapping(&val_sec as *const _ as *const u8, data_sec.as_mut_ptr(), 8);
        std::ptr::copy_nonoverlapping(
            &val_usec as *const _ as *const u8,
            data_usec.as_mut_ptr(),
            8,
        );
    }
    Ok(())
}

fn hc_print_str(caller: Caller<'_>, ptr: u32, len: u32) -> Result<(), Trap> {
    let mem = wasm_get_caller_memory(&caller)?;
    let data = get_memory_slice(&mem, ptr, len)?;
    let s = match str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return Err(Trap::new("invalid utf-8")),
    };
    println!("{}", s);
    Ok(())
}

// abort is usually required by assemblyscript modules
fn abort(
    _caller: Caller<'_>, _message: u32, _file_name: u32, _line: u32, _column: u32,
) -> Result<(), Trap> {
    SCLogInfo!("XXX abort function called");
    Err(Trap::new("XXX abort function called"))
}

fn hc_log(
    caller: Caller<'_>, level: i32, file: u32, file_len: u32, line: u32, function: u32,
    function_len: u32, code: i32, msg: u32, msg_len: u32,
) -> Result<(), Trap> {
    if crate::log::get_log_level() >= level {
        let level = unsafe { std::mem::transmute::<i32, crate::log::Level>(level) };
        let mem = wasm_get_caller_memory(&caller)?;
        let file = get_memory_str(&mem, file, file_len)?;
        let function = get_memory_str(&mem, function, function_len)?;
        let msg = get_memory_str(&mem, msg, msg_len)?;
        crate::log::sclog(level, file, line, function, code, msg);
    }
    Ok(())
}

fn sc_log_info(caller: Caller<'_>, ptr: u32, len: u32) -> Result<(), Trap> {
    let mem = wasm_get_caller_memory(&caller)?;
    let s = get_memory_str(&mem, ptr, len)?;
    SCLogInfo!("{}", s);
    Ok(())
}

fn sc_flow_app_layer_proto(caller: Caller<'_>, env: &CallEnv) -> Result<u32, Trap> {
    // println!("XXX sc_flow_app_layer_proto");
    // get flow
    let f = env.flow;
    // eprintln!("    flow: {:x}", f as u64);
    // allocate string for response
    let mem = wasm_get_caller_memory(&caller)?;
    let alloc = wasm_get_caller_function(&caller, "sc_allocate")?;
    let alloc = alloc.get1::<u32, u32>()?;
    // get app_proto
    let app_proto = unsafe { wasm_get_flow_app_proto(f) };
    // eprintln!("    AppProto: {}", app_proto);
    let proto_str = unsafe { CStr::from_ptr(wasm_app_proto_to_string(app_proto)) };
    // eprintln!("    Proto: {:?}", proto_str);

    let bytes = proto_str.to_bytes_with_nul();
    let len = bytes.len() as u32;
    let buffer = alloc(len)?;
    // std::dbg!(&buffer);
    let dst = get_memory_slice_mut(&mem, buffer, len)?;
    // unsafe {
    //     std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.as_mut_ptr(), len as usize);
    // }
    dst.copy_from_slice(bytes);
    Ok(buffer)
}
