/* Copyright (C) 2018-2020 Open Information Security Foundation
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

use super::gssapi::{parse_gssapi, GssApiBuffer};
use super::sasl::parse_sasl_buffer;
use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use ldap_parser::{der_parser::ber::ber_read_element_header, ldap::*, parse_ldap_message};
use std;
use std::ffi::CString;

static mut ALPROTO_LDAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum LDAPEvent {}

pub struct LDAPTransaction {
    tx_id: u64,

    pub request_protocol_op: ProtocolOpTag,
    pub message_id: Option<MessageID>,
    pub result_code: Option<ResultCode>,
    pub bind_dn: Option<String>,
    pub bind_pwd: Option<Vec<u8>>,
    pub sasl_mech: Option<String>,

    tx_data: AppLayerTxData,
}

impl LDAPTransaction {
    pub fn new() -> LDAPTransaction {
        LDAPTransaction {
            tx_id: 0,
            request_protocol_op: ProtocolOpTag(0),
            message_id: None,
            result_code: None,
            bind_dn: None,
            bind_pwd: None,
            sasl_mech: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for LDAPTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct LDAPState {
    state_data: AppLayerStateData,

    request_gap: bool,
    response_gap: bool,

    // Current bind DN of the session
    bind_dn: Option<String>,
    // message ID of TLS request, if present
    tls_request: Option<MessageID>,
    has_starttls: bool,
    has_sasl_layers: bool,
    sasl_mech: Option<String>,

    /// List of transactions for this session
    transactions: Vec<LDAPTransaction>,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

impl State<LDAPTransaction> for LDAPState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&LDAPTransaction> {
        self.transactions.get(index)
    }
}

impl LDAPState {
    pub fn new() -> Self {
        Self::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&LDAPTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> LDAPTransaction {
        let mut tx = LDAPTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn parse_request(
        &mut self, input: &[u8], flow: *const Flow, pstate: *mut std::os::raw::c_void,
    ) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.has_starttls {
            unsafe {
                AppLayerRequestProtocolTLSUpgrade(flow);
            }
            return AppLayerResult::ok();
        }
        // debug: check if we missed TLS
        if input.len() >= 2 && &input[..2] == b"\x16\x03" {
            SCLogDebug!("LDAP: missed STARTTLS ?!");
        }

        if self.has_sasl_layers {
            self.parse_ldap_sasl(input, false, pstate)
        } else {
            self.parse_ldap_buffer(input, false)
        }
    }

    fn parse_response(
        &mut self, input: &[u8], flow: *const Flow, pstate: *mut std::os::raw::c_void,
    ) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.has_starttls {
            unsafe {
                AppLayerRequestProtocolTLSUpgrade(flow);
            }
            return AppLayerResult::ok();
        }
        // debug: check if we missed TLS
        if input.len() >= 2 && &input[..2] == b"\x16\x03" {
            SCLogDebug!("LDAP: missed STARTTLS ?!");
        }

        if self.has_sasl_layers {
            self.parse_ldap_sasl(input, true, pstate)
        } else {
            self.parse_ldap_buffer(input, true)
        }
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }

    fn parse_ldap_buffer(&mut self, input: &[u8], is_response: bool) -> AppLayerResult {
        let mut cur_i = input;
        loop {
            if cur_i.is_empty() {
                break;
            }
            // read header and see if we have a complete message
            cur_i = match check_ldap_message_complete(cur_i) {
                Ok(n) => {
                    // Assume we have only one message per frame (in RFC 4511, it is said
                    // " a client transmits a protocol request".
                    // However, some frames (mostly SASL buffers) sometimes contains trailing
                    // bytes.
                    // Truncate the frame to the message length
                    // Note: wireshark does the same
                    if cur_i.len() > n {
                        &cur_i[..n]
                    } else {
                        cur_i
                    }
                }
                Err(n) => {
                    // not complete, request more bytes
                    let consumed = input.len() - cur_i.len();
                    return AppLayerResult::incomplete(
                        consumed as u32,
                        n as u32, /* needed_estimation */
                    );
                }
            };
            match parse_ldap_message(cur_i) {
                Ok((rem, msg)) => {
                    if is_response {
                        self.handle_response_message(&msg);
                    } else {
                        self.handle_request_message(&msg);
                    }
                    cur_i = rem;
                }
                _e => {
                    SCLogDebug!("parse_ldap_message failed: {:?}", _e);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn parse_ldap_sasl(
        &mut self, input: &[u8], is_response: bool, pstate: *mut std::os::raw::c_void,
    ) -> AppLayerResult {
        // Are we *really* using SASL?
        // Sometimes, SASL is negotiated but the next packets are sent in clear
        //
        // Check if the first byte is 0: sasl layer length is 4 bytes, so this is OK
        // if the fragment does not exceed 16 MB)
        // If plain LDAP, first byte should be 0x30 (BER sequence)
        if !input.is_empty() && input[0] != 0 {
            return self.parse_ldap_buffer(input, is_response);
        }
        let mech = match &self.sasl_mech {
            Some(s) => s,
            None => {
                SCLogDebug!("SASL mechanism could not be determined");
                return AppLayerResult::err();
            }
        };
        match mech.as_ref() {
            "GSSAPI" | "GSS-SPNEGO" => {
                let (_rem, sasl) = match parse_sasl_buffer(input) {
                    Ok(x) => x,
                    Err(_e) => {
                        SCLogDebug!("LDAP: parsing SASL buffer failed: {:?}", _e);
                        return AppLayerResult::err();
                    }
                };
                let (_rem, gss) = match parse_gssapi(sasl.0) {
                    Ok(x) => x,
                    Err(_e) => {
                        SCLogDebug!("LDAP: parsing GSS-API buffer failed: {:?}", _e);
                        return AppLayerResult::err();
                    }
                };
                match &gss {
                    GssApiBuffer::Wrapped(buffer) => {
                        if buffer.token.seal_alg == 0xffff {
                            // no encryption, integrity only
                            return self.parse_ldap_buffer(buffer.payload, is_response);
                        }
                        // Encrypted GSSAPI encapsulation
                        // fallthrough to bypass
                    }
                    GssApiBuffer::Spnego | GssApiBuffer::GssCfxWrap { .. } => {
                        // Encrypted encapsulation
                        // fallthrough to bypass
                    }
                    GssApiBuffer::Unknown => {
                        // Unknown or unsupported GSS-API encapsulation
                        SCLogInfo!(
                            "LDAP: unknown or unsupported OID in GSSAPI encapsulation {:?}",
                            mech
                        );
                        // fallthrough to bypass
                    }
                }
            }
            _ => {
                // Unkwnown SASL mechanism
                // fallthrough to bypass
            }
        }
        // activate bypass
        unsafe {
            AppLayerParserStateSetFlag(
                pstate,
                APP_LAYER_PARSER_NO_INSPECTION
                    | APP_LAYER_PARSER_NO_REASSEMBLY
                    | APP_LAYER_PARSER_BYPASS_READY,
            );
        }
        AppLayerResult::ok()
    }

    fn handle_request_message(&mut self, msg: &LdapMessage) {
        let mut tx = self.new_tx();
        tx.message_id = Some(msg.message_id);
        tx.request_protocol_op = msg.protocol_op.tag();
        match &msg.protocol_op {
            ProtocolOp::BindRequest(r) => {
                self.bind_dn = Some(r.name.0.to_string());
                match &r.authentication {
                    AuthenticationChoice::Simple(creds) => {
                        tx.bind_pwd = Some(creds.to_vec());
                    }
                    AuthenticationChoice::Sasl(creds) => {
                        self.sasl_mech = Some(creds.mechanism.0.to_string());
                    }
                }
            }
            ProtocolOp::UnbindRequest => {
                self.bind_dn = None;
            }
            ProtocolOp::ExtendedRequest(req) => {
                // check for STARTTLS
                if req.request_name.0 == "1.3.6.1.4.1.1466.20037" {
                    self.tls_request = Some(msg.message_id);
                }
            }
            _ => (),
        }
        // if we are not in a bind request, add authentication parameters to tx
        if !matches!(msg.protocol_op, ProtocolOp::BindRequest(_)) {
            tx.bind_dn = self.bind_dn.clone();
            tx.sasl_mech = self.sasl_mech.clone();
        }
        self.transactions.push(tx);
    }

    fn handle_response_message(&mut self, msg: &LdapMessage) {
        // LDAP transactions are not ordered, so we have to look
        // for a transaction for this message ID
        let find_tx = self
            .transactions
            .iter_mut()
            .find(|tx| tx.message_id == Some(msg.message_id));
        let tx = match find_tx {
            Some(tx) => tx,
            None => {
                SCLogDebug!("No transaction for response {}", msg.message_id.0);
                return;
            }
        };
        match &msg.protocol_op {
            ProtocolOp::BindResponse(r) => {
                tx.result_code = Some(r.result.result_code);
                match r.result.result_code {
                    ResultCode::Success => {
                        tx.bind_dn = self.bind_dn.clone();
                        tx.sasl_mech = self.sasl_mech.clone();
                        if self.sasl_mech.is_some() {
                            self.has_sasl_layers = true;
                        }
                    }
                    _ => {
                        self.bind_dn = None;
                        self.sasl_mech = None;
                    }
                }
            }
            ProtocolOp::ModifyResponse(r) => {
                tx.result_code = Some(r.result.result_code);
            }
            ProtocolOp::ExtendedResponse(r) => {
                tx.result_code = Some(r.result.result_code);
                if self.tls_request.is_some() {
                    match r.result.result_code {
                        ResultCode::Success => {
                            self.has_starttls = true;
                        }
                        _ => {
                            self.tls_request = None;
                            self.has_starttls = false;
                        }
                    }
                }
            }
            ProtocolOp::SearchResultDone(r)
            | ProtocolOp::AddResponse(r)
            | ProtocolOp::DelResponse(r)
            | ProtocolOp::ModDnResponse(r)
            | ProtocolOp::CompareResponse(r) => {
                tx.result_code = Some(r.result_code);
            }
            _ => (),
        }
    }
}

/// Return Ok(length) if message is complete, Err(n) if some bytes are missing.
fn check_ldap_message_complete(i: &[u8]) -> Result<usize, usize> {
    let (rem, header) = ber_read_element_header(i).or(Err(1_usize))?;
    let len = header.len.primitive().or(Err(1_usize))?;
    if rem.len() >= len {
        Ok(len + (i.len() - rem.len()))
    } else {
        Err(len + (i.len() - rem.len()))
    }
}

/// Probe for a valid LDAP message.
fn probe(input: &[u8]) -> ldap_parser::error::Result<LdapMessage> {
    parse_ldap_message(input)
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_ldap_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len > 2 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_LDAP;
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_ldap_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = LDAPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut LDAPState));
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, LDAPState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_parse_request(
    flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, LDAPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf, flow, pstate)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_parse_response(
    flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, LDAPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf, flow, pstate)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, LDAPState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, LDAPState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, LDAPTransaction);

    // Transaction is done if we have a response.
    if tx.result_code.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_ldap_get_tx_data, LDAPTransaction);
export_state_data_get!(rs_ldap_get_state_data, LDAPState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"ldap\0";

#[no_mangle]
pub unsafe extern "C" fn rs_ldap_register_parser() {
    let default_port = CString::new("[389, 3268]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_ldap_probing_parser),
        probe_tc: Some(rs_ldap_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_ldap_state_new,
        state_free: rs_ldap_state_free,
        tx_free: rs_ldap_state_tx_free,
        parse_ts: rs_ldap_parse_request,
        parse_tc: rs_ldap_parse_response,
        get_tx_count: rs_ldap_state_get_tx_count,
        get_tx: rs_ldap_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_ldap_tx_get_alstate_progress,
        get_eventinfo: Some(LDAPEvent::get_event_info),
        get_eventinfo_byid: Some(LDAPEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<LDAPState, LDAPTransaction>),
        get_tx_data: rs_ldap_get_tx_data,
        get_state_data: rs_ldap_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_LDAP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust ldap parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for LDAP.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const BIND_REQ_ANON: &[u8] = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00";
    const BIND_RESP_ANON: &[u8] = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00";

    #[test]
    fn test_probe() {
        assert!(probe(b"1").is_err());
        assert!(probe(BIND_REQ_ANON).is_ok());
        assert!(probe(&BIND_REQ_ANON[1..]).is_err());
    }

    #[test]
    fn test_bind_req() {
        let mut state = LDAPState::new();
        let flow = std::ptr::null();
        let pstate = std::ptr::null_mut();

        let _r = state.parse_request(BIND_REQ_ANON, flow, pstate);
        assert_eq!(state.tx_id, 1);
        assert!(state.bind_dn.is_some());
        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert!(tx.result_code.is_none());

        let _r = state.parse_response(BIND_RESP_ANON, flow, pstate);
        assert_eq!(state.tx_id, 1);
        assert!(state.bind_dn.is_some());
        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert_eq!(tx.result_code, Some(ResultCode::Success));
    }

    #[test]
    fn test_incomplete() {
        let mut state = LDAPState::new();
        let flow = std::ptr::null();
        let pstate = std::ptr::null_mut();
        let mut v = Vec::new();
        v.extend_from_slice(BIND_REQ_ANON);
        v.extend_from_slice(&[0x00, 0x00]);
        let buf = &v;

        let r = state.parse_request(&buf[0..0], flow, pstate);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        let r = state.parse_request(&buf[0..1], flow, pstate);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 1
            }
        );

        let r = state.parse_request(&buf[0..2], flow, pstate);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 14
            }
        );

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[..BIND_REQ_ANON.len()], flow, pstate);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        // The first message with trailing bytes
        let r = state.parse_request(&buf[..BIND_REQ_ANON.len() + 2], flow, pstate);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );
    }
}
