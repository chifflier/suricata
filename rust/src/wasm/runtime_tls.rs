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

use crate::core::Flow;
use crate::wasm::runtime_util::*;
use crate::wasm::CallEnv;
use libc::strlen;
use std::os::raw::c_char;
use wasmtime::{Caller, Trap};

extern "C" {
    fn _wasm_tls_get_serial(f: *const Flow, res: *mut *const c_char) -> i32;
    fn _wasm_tls_get_sni(f: *const Flow, res: *mut *const c_char) -> i32;
}

pub(crate) fn hc_tls_get_cert_serial(caller: Caller<'_>, env: &CallEnv) -> Result<u32, Trap> {
    if env.packet.is_null() {
        return Err(Trap::new("Internal error: no packet"));
    }
    // get result
    let mut result: *const c_char = std::ptr::null();
    let rc = unsafe { _wasm_tls_get_serial(env.flow, &mut result) };
    if rc != 0 {
        return Err(Trap::new("Could not get TLS cert serial"));
    }
    if result.is_null() {
        return Ok(0);
    }
    let len = unsafe { strlen(result) + 1 }; // +1 to copy the ending \0
    //
    copy_data_to_memory(&caller, result as *const u8, len)
}

pub(crate) fn hc_tls_get_sni(caller: Caller<'_>, env: &CallEnv) -> Result<u32, Trap> {
    if env.packet.is_null() {
        return Err(Trap::new("Internal error: no packet"));
    }
    // get result
    let mut result: *const c_char = std::ptr::null();
    let rc = unsafe { _wasm_tls_get_sni(env.flow, &mut result) };
    if rc != 0 {
        return Err(Trap::new("Could not get TLS SNI"));
    }
    if result.is_null() {
        return Ok(0);
    }
    let len = unsafe { strlen(result) + 1 }; // +1 to copy the ending \0
    //
    copy_data_to_memory(&caller, result as *const u8, len)
}
