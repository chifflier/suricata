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

use super::ldap::{LDAPState, LDAPTransaction};
use crate::conf::ConfNode;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use ldap_parser::ldap::ProtocolOpTag;
use std::os::raw::c_void;
use std::string::String;

pub struct LDAPLogger {
    /// Bitfield representing one operation per bit.
    /// There are only 26 operations in LDAP RFC
    operations: u32,
}

impl LDAPLogger {
    pub fn new(conf: ConfNode) -> Self {
        // default value: everything is logged
        let mut operations = 0;
        if let Some(op_list) = conf.get_child_value("operations") {
            for op_str in op_list.split(',') {
                match ldap_str_to_operation(op_str.trim()) {
                    Some(op) => {
                        operations |= 1 << op.0;
                    }
                    None => {
                        SCLogError!("LDAP/Logger: invalid operation {}", op_str);
                    }
                }
            }
        } else {
            operations = 0xffff_ffff;
        }
        Self { operations }
    }

    pub fn do_log(&self, tx: &LDAPTransaction) -> bool {
        if self.operations & (1 << tx.request_protocol_op.0) != 0 {
            return true;
        }
        // other conditions?
        return false;
    }
}

fn ldap_str_to_operation(s: &str) -> Option<ProtocolOpTag> {
    match s {
        "BindRequest" => Some(ProtocolOpTag::BindRequest),
        "BindResponse" => Some(ProtocolOpTag::BindResponse),
        "UnbindRequest" => Some(ProtocolOpTag::UnbindRequest),
        "SearchRequest" => Some(ProtocolOpTag::SearchRequest),
        "SearchResultEntry" => Some(ProtocolOpTag::SearchResultEntry),
        "SearchResultDone" => Some(ProtocolOpTag::SearchResultDone),
        "ModifyRequest" => Some(ProtocolOpTag::ModifyRequest),
        "ModifyResponse" => Some(ProtocolOpTag::ModifyResponse),
        "AddRequest" => Some(ProtocolOpTag::AddRequest),
        "AddResponse" => Some(ProtocolOpTag::AddResponse),
        "DelRequest" => Some(ProtocolOpTag::DelRequest),
        "DelResponse" => Some(ProtocolOpTag::DelResponse),
        "ModDnRequest" => Some(ProtocolOpTag::ModDnRequest),
        "ModDnResponse" => Some(ProtocolOpTag::ModDnResponse),
        "CompareRequest" => Some(ProtocolOpTag::CompareRequest),
        "CompareResponse" => Some(ProtocolOpTag::CompareResponse),
        "AbandonRequest" => Some(ProtocolOpTag::AbandonRequest),
        "SearchResultReference" => Some(ProtocolOpTag::SearchResultReference),
        "ExtendedRequest" => Some(ProtocolOpTag::ExtendedRequest),
        "ExtendedResponse" => Some(ProtocolOpTag::ExtendedResponse),
        "IntermediateResponse" => Some(ProtocolOpTag::IntermediateResponse),
        _ => None,
    }
}

fn ldap_log_response(jsb: &mut JsonBuilder, tx: &LDAPTransaction) -> Result<(), JsonError> {
    jsb.set_string("request_protocol_op", &tx.request_protocol_op.to_string())?;
    if let Some(dn) = &tx.bind_dn {
        if dn.is_empty() {
            // special display for empty bind DN
            jsb.set_string("bind_dn", "<ROOT>")?;
        } else {
            jsb.set_string("bind_dn", dn)?;
        }
    }
    if let Some(pwd) = &tx.bind_pwd {
        let s = String::from_utf8_lossy(pwd);
        jsb.set_string("bind_pwd", &s)?;
    }
    if let Some(s) = &tx.sasl_mech {
        jsb.set_string("sasl_mech", s)?;
    }
    if let Some(id) = &tx.message_id {
        jsb.set_string("message_id", &id.0.to_string())?;
    }
    if let Some(n) = &tx.result_code {
        jsb.set_string("result_code", &n.0.to_string())?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_ldap_log_json_response(
    jsb: &mut JsonBuilder, _state: &mut LDAPState, tx: &mut LDAPTransaction,
) -> bool {
    ldap_log_response(jsb, tx).is_ok()
}

#[no_mangle]
pub extern "C" fn rs_ldap_logger_new(conf: *const c_void) -> *mut std::os::raw::c_void {
    let conf = ConfNode::wrap(conf);
    let boxed = Box::new(LDAPLogger::new(conf));
    return Box::into_raw(boxed) as *mut _;
}
#[no_mangle]
pub unsafe extern "C" fn rs_ldap_logger_free(logger: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(logger as *mut LDAPLogger));
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_logger_do_log(
    logger: *mut std::os::raw::c_void, tx: *mut std::os::raw::c_void,
) -> bool {
    let logger = cast_pointer!(logger, LDAPLogger);
    let tx = cast_pointer!(tx, LDAPTransaction);
    logger.do_log(tx)
}
