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

mod compile;
mod modules;
mod output;
mod runtime;
mod runtime_tls;
mod runtime_util;
pub use modules::*;
pub use output::*;

use std::io;
use wasmtime::Trap;

pub const WASM_API_MAJOR: u32 = 1;
pub const WASM_API_MINOR: u32 = 0;

#[derive(Debug)]
pub enum WasmError {
    IOError(io::Error),
    InvalidID,
    FileNameError,
    ReadError,
    LoadError,
    CompileError,
    CacheLoadError,
    CacheStoreError,
    InstantiateError(&'static str),
    RuntimeError(&'static str),
    FunctionNotFound(&'static str),
    Trap(Trap),
}

impl From<io::Error> for WasmError {
    fn from(e: io::Error) -> Self {
        WasmError::IOError(e)
    }
}

impl From<Trap> for WasmError {
    fn from(e: Trap) -> Self {
        WasmError::Trap(e)
    }
}
