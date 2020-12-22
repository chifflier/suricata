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

use crate::wasm::runtime::wasm_create_import;
use crate::wasm::{CallEnv, WasmError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasmtime::{Engine, Instance, Module, Store};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(C)]
pub struct WasmModuleID(pub(crate) i32);

impl WasmModuleID {
    pub const FAILURE: WasmModuleID = WasmModuleID(-1);
}

pub struct ModulesRegistry {
    engine: Engine,
    store: Store,
    map: HashMap<WasmModuleID, Module>,
    id_map: HashMap<String, WasmModuleID>,
    id_count: i32,
}

impl Default for ModulesRegistry {
    fn default() -> Self {
        // create engine with default configuration
        let engine = Engine::default();
        // let engine = Engine::new(Config::new().debug_info(true)); // XXX debug
        let store = Store::new(&engine);
        ModulesRegistry {
            engine,
            store,
            map: HashMap::new(),
            id_map: HashMap::new(),
            id_count: 0,
        }
    }
}

impl ModulesRegistry {
    #[inline]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn add_module(&mut self, s: &str, m: Module) -> WasmModuleID {
        let id = WasmModuleID(self.id_count);
        self.id_map.insert(s.to_owned(), id);
        self.map.insert(id, m);
        self.id_count += 1;
        id
    }

    pub fn get_by_id(&self, id: WasmModuleID) -> Option<&Module> {
        self.map.get(&id)
    }

    pub fn get_mut_by_id(&mut self, id: WasmModuleID) -> Option<&mut Module> {
        self.map.get_mut(&id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Module> {
        let id = self.id_map.get(name)?;
        self.map.get(&id)
    }

    pub fn get_mut_by_name(&mut self, name: &str) -> Option<&mut Module> {
        let id = self.id_map.get(name)?;
        self.map.get_mut(&id)
    }

    pub fn get_id_by_name(&self, name: &str) -> Option<WasmModuleID> {
        self.id_map.get(name).map(|&id| id)
    }

    pub fn instantiate(
        &self, id: WasmModuleID, call_env: Rc<RefCell<CallEnv>>,
    ) -> Result<Instance, WasmError> {
        let module = self.map.get(&id).ok_or(WasmError::InvalidID)?;
        SCLogDebug!("WASM: creating instance for module id {}", id.0);
        let imports = wasm_create_import(&self.store, &module, call_env);
        let instance = Instance::new(&self.store, &module, &imports).map_err(|e| {
            SCLogError!("WASM module instantiation error: {:?}", e);
            WasmError::InstantiateError("Could not create WASM module instance")
        })?;
        Ok(instance)
    }
}
