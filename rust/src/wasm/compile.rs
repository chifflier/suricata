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

use crate::wasm::WasmError;
use fxhash::hash64;
use std::fs;
use std::path::Path;
use wasmtime::{Engine, Module};

pub(crate) fn wasm_compile_nocache<P: AsRef<Path>>(
    engine: &Engine, s: P,
) -> Result<Module, WasmError> {
    let s = s.as_ref();
    SCLogDebug!("WASM: compiling module {}", s.display());
    let bytes = fs::read(s).map_err(|_| WasmError::ReadError)?;
    Module::new(&engine, &bytes).map_err(|_| WasmError::CompileError)
}

pub(crate) fn wasm_compile_cache<P1, P2>(
    engine: &Engine, s: P1, cache_dir: P2,
) -> Result<Module, WasmError>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    let s = s.as_ref();
    SCLogDebug!("WASM: compiling module {}", s.display());

    let bytes = fs::read(s).map_err(|_| WasmError::ReadError)?;

    // Compute a key for a given WebAssembly binary
    let hash = hash64(&bytes);

    // Try to load from cache
    let hash_str = format!("{:016x}", hash);
    let out_file_name = cache_dir.as_ref().join(&hash_str);
    if let Ok(v) = fs::read(&out_file_name) {
        SCLogDebug!("WASM: loading module {} from cache", s.display());
        return Module::deserialize(&engine, &v).map_err(|_| WasmError::CompileError);
    }

    // Compile module
    let m = Module::new(&engine, bytes).map_err(|_| WasmError::CompileError)?;

    // Save precompiled module
    SCLogDebug!(
        "WASM: saving pre-compiled data to cache for module {}",
        s.display()
    );
    let data = m.serialize().map_err(|_| WasmError::CacheStoreError)?;
    fs::write(out_file_name, &data).map_err(|_| WasmError::CacheStoreError)?;

    Ok(m)
}
