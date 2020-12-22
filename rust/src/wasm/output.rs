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

use crate::core::{AppProto, Flow, StringToAppProto};
use crate::wasm::compile::*;
use crate::wasm::modules::*;
use crate::wasm::runtime_util::*;
use crate::wasm::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use wasmtime::{Func, Instance, Module, Trap};

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct WasmModuleOpts {
    pub alproto: AppProto,
    pub packet: u8,
    pub alerts: u8,
    pub file: u8,
    pub streaming: u8,
    pub tcp_data: u8,
    pub http_body: u8,
    pub flow: u8,
    pub stats: u8,
}

// Environment for WASM closures
pub struct CallEnv {
    // pub map: HashMap<&'static str, *const libc::c_void>,
    pub flow: *const Flow,
    pub packet: *const c_void,
}

unsafe impl Send for CallEnv {}
unsafe impl Sync for CallEnv {}

impl Default for CallEnv {
    fn default() -> Self {
        CallEnv {
            // map: HashMap::default(),
            flow: std::ptr::null(),
            packet: std::ptr::null(),
        }
    }
}

impl CallEnv {
    pub fn clear(&mut self) {
        // self.map.clear();
        self.flow = std::ptr::null();
        self.packet = std::ptr::null();
    }
}

// Developers:
// Allowed types for signatures only allow types `i32`, `u32`, `i64`, `u64`,
// `f32` and `f64`.
// type InitFn<'a> = Func<'a, (), i32>;
type AllocateFn = dyn Fn(u32) -> Result<u32, Trap>;
type FreeFn = dyn Fn(u32) -> Result<(), Trap>;
type StreamLogFn = dyn Fn(u32, u32, u64) -> Result<i32, Trap>;
type TxLogFn = dyn Fn(u64) -> Result<i32, Trap>;

#[derive(Default)]
pub struct WasmMasterCtx {
    pub registry: ModulesRegistry,
    modules_dir: Option<String>,
    cache_dir: Option<String>,
    instances: HashMap<String, WasmCtx>,
}

pub struct WasmCtx {
    pub instance: Instance,
    pub marker: String,

    pub allocate: Box<AllocateFn>,
    pub free: Box<FreeFn>,

    stream_log: Option<Box<StreamLogFn>>,
    tx_log: Option<Box<TxLogFn>>,
    call_env: Rc<RefCell<CallEnv>>,
}

impl WasmMasterCtx {
    pub fn enable_cache(&mut self, cache_dir: &str) -> Result<(), WasmError> {
        // XXX check if dir exists
        self.cache_dir = Some(cache_dir.to_owned());
        Ok(())
    }

    pub fn set_modules_dir(&mut self, modules_dir: &str) -> Result<(), WasmError> {
        // XXX check if dir exists
        self.modules_dir = Some(modules_dir.to_owned());
        Ok(())
    }

    pub fn compile_module(&mut self, s: &str) -> Result<Module, WasmError> {
        let mut path = PathBuf::new();
        if let Some(modules_dir) = &self.modules_dir {
            path.push(modules_dir);
        }
        path.push(s);
        if let Some(cache_dir) = &self.cache_dir {
            wasm_compile_cache(self.registry.engine(), &path, &cache_dir)
        } else {
            wasm_compile_nocache(self.registry.engine(), &path)
        }
    }

    pub fn create_instance_ctx(&mut self, name: &str) -> Result<(), WasmError> {
        let id = self
            .registry
            .get_id_by_name(name)
            .ok_or(WasmError::InstantiateError(
                "WASM: no module with this name",
            ))?;
        let call_env = Rc::new(RefCell::new(CallEnv::default()));
        let instance = self.registry.instantiate(id, call_env.clone())?;
        let marker = format!("Instance {}", id.0);
        let allocate = get_func("sc_allocate", &instance)?
            .get1::<u32, u32>()
            .map_err(|_| WasmError::FunctionNotFound("sc_allocate"))?;
        let free = get_func("sc_free", &instance)?
            .get1::<u32, ()>()
            .map_err(|_| WasmError::FunctionNotFound("sc_free"))?;
        let log_ctx = WasmCtx {
            instance,
            marker,
            allocate: Box::new(allocate),
            free: Box::new(free),
            stream_log: None,
            tx_log: None,
            call_env,
        };
        self.instances.insert(name.to_owned(), log_ctx);
        Ok(())
    }

    /// Get a raw pointer to a module instance
    ///
    /// # Safety
    ///
    /// Caller must ensure that:
    /// - the pointer is not used before the `WasmMasterCtx` object
    /// - no concurrent access can be performed on the instance (thread safety)
    pub unsafe fn get_instance_ptr(&mut self, name: &str) -> Option<*mut WasmCtx> {
        self.instances
            .get_mut(&name.to_owned())
            .map(|ctx| ctx as *mut WasmCtx)
    }
}

impl WasmCtx {
    // update function pointers, resolve module exports
    fn update_functions(&mut self) -> Result<(), WasmError> {
        for export in self.instance.exports() {
            match export.name() {
                "stream_log" => {
                    let f = get_func("stream_log", &self.instance)?
                        .get3::<u32, u32, u64, i32>()
                        .map_err(|_| WasmError::FunctionNotFound("stream_log"))?;
                    self.stream_log = Some(Box::new(f));
                }
                "tx_log" => {
                    let f = get_func("tx_log", &self.instance)?
                        .get1::<u64, i32>()
                        .map_err(|_| WasmError::FunctionNotFound("tx_log"))?;
                    self.tx_log = Some(Box::new(f));
                }
                _ => (),
            }
        }
        Ok(())
    }

    fn update_call_env<F>(&self, f: F)
    where
        F: Fn(&mut CallEnv),
    {
        let mut env = self
            .call_env
            // safety: must not be called recursively
            .borrow_mut();
        env.clear();
        f(&mut env)
    }

    pub fn init(&mut self) -> Result<i32, WasmError> {
        let init = get_func("init", &self.instance)?
            .get2::<u32, u32, i32>()
            .map_err(|_| WasmError::InstantiateError("'init' has wrong prototype"))?;
        let ret = init(WASM_API_MAJOR, WASM_API_MINOR);
        match ret {
            Ok(r) => Ok(r),
            Err(e) => {
                SCLogError!("WASM: error while calling 'init': {}", e);
                return Err(WasmError::InstantiateError("'init' function failed"));
            }
        }
    }

    pub fn get_info(&self, opts: &mut WasmModuleOpts) -> Result<(), WasmError> {
        let mem = self
            .instance
            .get_memory("memory")
            .ok_or(WasmError::InstantiateError("Could not get memory"))?;
        // check PROTOCOL global
        if let Some(global) = self.instance.get_global("PROTOCOL") {
            let s_protocol = get_global_str(&mem, &global)
                .map_err(|_| WasmError::InstantiateError("Could not get PROTOCOL value"))?;
            match s_protocol {
                "tls" => {
                    opts.alproto = unsafe { StringToAppProto("tls\0".as_ptr()) };
                }
                _ => SCLogInfo!(
                    "WASM: unknown/unsupported protocol {} requested",
                    s_protocol
                ),
            }
        }
        // check TYPE global
        if let Some(global) = self.instance.get_global("TYPE") {
            let s_type = get_global_str(&mem, &global)
                .map_err(|_| WasmError::InstantiateError("Could not get TYPE value"))?;
            match s_type {
                "file" => opts.file = 1,
                "flow" => opts.flow = 1,
                "packet" => opts.packet = 1,
                "streaming" => opts.streaming = 1,
                _ => SCLogInfo!("WASM: unknown/unsupported type {}", s_type),
            }
        }
        // check FILTER global
        if let Some(global) = self.instance.get_global("FILTER") {
            let s_filter = get_global_str(&mem, &global)
                .map_err(|_| WasmError::InstantiateError("Could not get FILTER value"))?;
            match s_filter {
                "alerts" => opts.alerts = 1,
                "tcp" => opts.tcp_data = 1,
                _ => SCLogInfo!("WASM: unknown/unsupported filter {}", s_filter),
            }
        }
        Ok(())
    }

    fn stream_log(&self, src: &[u8], tx_id: u64) -> Result<i32, WasmError> {
        let stream_log_fn = self
            .stream_log
            .as_ref()
            .ok_or(WasmError::FunctionNotFound("stream_log"))?;
        let len = src.len() as u32;
        // copy to buffer
        let memory_buffer = (self.allocate)(len)?;
        let mem = self
            .instance
            .get_memory("memory")
            .ok_or(WasmError::RuntimeError("Could not get guest memory"))?;
        let dst = get_memory_slice_mut(&mem, memory_buffer, len)?;
        // // safety:, pointers and length are valid (from slices), no alignment requirement (pointer to u8)
        // unsafe {
        //     std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), len as usize);
        // }
        dst.copy_from_slice(src);
        // call stream_log_fn
        let res = stream_log_fn(memory_buffer, len, tx_id);
        // free memory, and return
        let _ = (self.free)(memory_buffer);
        res.map_err(|e| e.into())
    }

    fn tx_log(&self, tx_id: u64) -> Result<i32, WasmError> {
        let tx_log_fn = self
            .tx_log
            .as_ref()
            .ok_or(WasmError::FunctionNotFound("tx_log"))?;
        // call tx_log_fn
        tx_log_fn(tx_id).map_err(|e| e.into())
    }
}

fn get_func(name: &'static str, instance: &Instance) -> Result<Func, WasmError> {
    match instance.get_func(name) {
        Some(f) => Ok(f),
        None => {
            SCLogError!("wasm: function '{}' not found", name);
            return Err(WasmError::FunctionNotFound(name));
        }
    }
}

#[no_mangle]
pub extern "C" fn wasm_master_ctx_new() -> *mut WasmMasterCtx {
    let ctx = Box::new(WasmMasterCtx::default());
    Box::into_raw(ctx)
}

#[no_mangle]
pub unsafe extern "C" fn wasm_master_ctx_free(ptr: *mut WasmMasterCtx) {
    if ptr != std::ptr::null_mut() {
        let _drop = Box::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_register_module(
    s: *const c_char, ctx: *mut WasmMasterCtx,
) -> WasmModuleID {
    SCLogDebug!("WASM register module");
    if s.is_null() || ctx.is_null() {
        SCLogError!("wasm_ctx_register_module: empty input");
        return WasmModuleID::FAILURE;
    }
    let c_str = match CStr::from_ptr(s).to_str() {
        Ok(s) => s,
        _ => {
            SCLogError!("wasm_ctx_register_module: input UTF-8 encoding for module name");
            return WasmModuleID::FAILURE;
        }
    };

    let ctx = &mut *ctx;

    let m = match ctx.compile_module(c_str) {
        Ok(m) => m,
        Err(e) => {
            SCLogError!("Could not compile WASM file: {:?}", e);
            return WasmModuleID::FAILURE;
        }
    };
    let id = ctx.registry.add_module(c_str, m);
    id
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_new_by_name(
    s: *const c_char, ctx: *mut WasmMasterCtx,
) -> *mut WasmCtx {
    if s.is_null() || ctx.is_null() {
        SCLogError!("wasm_ctx_new_by_name: empty input");
        return std::ptr::null_mut();
    }
    let c_str = match CStr::from_ptr(s).to_str() {
        Ok(s) => s,
        _ => {
            SCLogError!("wasm_ctx_new_by_name: invalid UTF-8 encoding for module name");
            return std::ptr::null_mut();
        }
    };
    let ctx = &mut *ctx;
    if ctx.create_instance_ctx(c_str).is_err() {
        SCLogError!("wasm_ctx_new_by_name: instance initialization failed");
        return std::ptr::null_mut();
    }
    ctx.get_instance_ptr(c_str).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_free(ptr: *mut WasmCtx) {
    if ptr != std::ptr::null_mut() {
        let _drop = &*ptr;
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_get_by_name(
    s: *const c_char, ctx: *mut WasmMasterCtx,
) -> *mut WasmCtx {
    if s.is_null() || ctx.is_null() {
        SCLogError!("wasm_ctx_get_by_name: empty input");
        return std::ptr::null_mut();
    }
    let c_str = match CStr::from_ptr(s).to_str() {
        Ok(s) => s,
        _ => {
            SCLogError!("wasm_ctx_get_by_name: invalid UTF-8 encoding for module name");
            return std::ptr::null_mut();
        }
    };
    let ctx = &mut *ctx;
    ctx.get_instance_ptr(c_str).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_enable_cache(s: *const c_char, ctx: *mut WasmMasterCtx) {
    if s.is_null() || ctx.is_null() {
        SCLogError!("wasm_ctx_enable_cache: empty input");
        return;
    }
    let c_str = match CStr::from_ptr(s).to_str() {
        Ok(s) => s,
        _ => {
            SCLogError!("wasm_ctx_enable_cache: input UTF-8 encoding for module name");
            return;
        }
    };
    let ctx = &mut *ctx;
    match ctx.enable_cache(c_str) {
        Ok(()) => (),
        Err(e) => {
            SCLogError!("Could not enable WASM cache: {:?}", e);
            return;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasm_ctx_set_modules_dir(
    s: *const c_char, ctx: *mut WasmMasterCtx,
) -> i32 {
    if s.is_null() || ctx.is_null() {
        SCLogError!("wasm_ctx_set_modules_dir: empty input");
        return -1;
    }
    let c_str = match CStr::from_ptr(s).to_str() {
        Ok(s) => s,
        _ => {
            SCLogError!("wasm_ctx_set_modules_dir: input UTF-8 encoding for module name");
            return -1;
        }
    };
    if c_str.len() == 0 {
        return 0;
    }
    let ctx = &mut *ctx;
    match ctx.set_modules_dir(c_str) {
        Ok(()) => 0,
        Err(e) => {
            SCLogError!("Could not set modules dir: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wasm_module_get_info(ctx: *mut WasmCtx, opts: &mut WasmModuleOpts) -> i32 {
    let ctx = unsafe { &*ctx };
    match ctx.get_info(opts) {
        Ok(_) => 0,
        Err(e) => {
            SCLogError!("WASM: could not get module info: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wasm_logger_instance_init(ctx: *mut WasmCtx) -> i32 {
    let ctx = unsafe { &mut *ctx };
    match ctx.update_functions() {
        Ok(_) => (),
        Err(e) => {
            SCLogError!(
                "wasm_logger_instance_init: function resolving failed: {:?}",
                e
            );
            return -1;
        }
    }
    match ctx.init() {
        Ok(r) => r,
        Err(e) => {
            SCLogError!("WASM: could not initialize module: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wasm_streaming_log(
    f: *const Flow, data: *const u8, len: u32, tx_id: u64, ctx: *mut WasmCtx,
) -> i32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = build_slice!(data, len as usize);
    let ctx = unsafe { &*ctx };
    // update env
    ctx.update_call_env(|env| {
        env.flow = f;
    });
    match ctx.stream_log(slice, tx_id) {
        Ok(r) => r,
        Err(e) => {
            SCLogError!("WASM: stream_log function failed: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn wasm_tx_log(
    p: *const c_void, f: *const Flow, tx_id: u64, ctx: *mut WasmCtx,
) -> i32 {
    let ctx = unsafe { &*ctx };
    // update env
    ctx.update_call_env(|env| {
        env.packet = p;
        env.flow = f;
    });
    match ctx.tx_log(tx_id) {
        Ok(r) => r,
        Err(e) => {
            SCLogError!("WASM: tx_log function failed: {:?}", e);
            -1
        }
    }
}
