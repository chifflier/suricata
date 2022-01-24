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
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std::string::String;

fn ldap_log_response(jsb: &mut JsonBuilder, tx: &LDAPTransaction) -> Result<(), JsonError> {
    jsb.set_string("request_protocol_op", &tx.request_protocol_op.to_string())?;
    if let Some(dn) = &tx.bind_dn {
        if dn.is_empty() {
            // special display for empty bind DN
            jsb.set_string("bind_dn", "<ROOT>")?;
        } else {
            jsb.set_string("bind_dn", &dn)?;
        }
    }
    if let Some(pwd) = &tx.bind_pwd {
        let s = String::from_utf8_lossy(pwd);
        jsb.set_string("bind_pwd", &s)?;
    }
    if let Some(s) = &tx.sasl_mech {
        jsb.set_string("sasl_mech", &s)?;
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
