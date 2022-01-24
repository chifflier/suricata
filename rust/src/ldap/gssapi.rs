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

// GSS-API (RFC 2743) messages
//
// See also:
//   - The Kerberos Version 5 GSS-API Mechanism (RFC1964)
//   - The Kerberos Version 5 Generic Security Service Application Program Interface (GSS-API)
//     Mechanism: Version 2 (RFC4121)
//
// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use ldap_parser::{
    der_parser::ber::*,
    der_parser::der::*,
    der_parser::error::*,
    der_parser::{oid, oid::Oid},
    nom::combinator::{cond, rest},
    nom::number::streaming::{le_u16, le_u64, le_u8},
};

const OID_SPNEGO: Oid<'static> = oid!{1.3.6.1.5.5.2};
const OID_KERBEROS: Oid<'static> = oid!{1.2.840.113554.1.2.2};

pub const KRB_SGN_ALG_DES_MAC_MD5: u16 = 0x0000;
// pub const KRB_SGN_ALG_MD2_5: u16 = 0x0001;
// pub const KRB_SGN_ALG_DES_MAC: u16 = 0x0002;
pub const KRB_SGN_ALG_HMAC: u16 = 0x0011;

// pub const KRB_CFX_FLAG_SENT_BY_ACCEPTOR: u8 = 0b001;
// pub const KRB_CFX_FLAG_SEALED: u8 = 0b010;
// pub const KRB_CFX_FLAG_ACCEPTOR_SUBKEY: u8 = 0b100;

// const KRB_TOKEN_WRAP: u16 = 0x0102;
const KRB_TOKEN_CFX_WRAP: u16 = 0x0405;

#[derive(Debug, PartialEq)]
pub enum GssApiBuffer<'a> {
    Wrapped(GssWrappedToken<'a>),
    GssCfxWrap {
        token: GssCfxWrap,
        payload: &'a [u8],
    },
    Spnego,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct GssWrappedToken<'a> {
    pub mech_type: Oid<'a>,
    pub token: GssWrap,
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct GssWrap {
    /// Identification field.
    /// Tokens emitted by GSS_GetMIC() contain
    /// the hex value 01 01 in this field.
    pub tok_id: u16,
    /// Integrity algorithm indicator.
    ///     00 00 - DES MAC MD5
    ///     01 00 - MD2.5
    ///     02 00 - DES MAC
    pub sgn_alg: u16,
    /// Encryption algorithm
    ///     ff ff - none
    ///     00 00 - DES
    pub seal_alg: u16,
    /// Contains ff ff ff ff
    pub filler: u16,
    /// Sequence number field
    pub snd_seq: u64,
    /// Checksum of "to-be-signed data",
    /// calculated according to algorithm
    /// specified in SGN_ALG field.
    pub sgn_cksum: u64,
    /// Optional random confounder
    /// See draft-brezak-win2k-krb-rc4-hmac-04
    pub random_confounder: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct GssCfxWrap {
    pub tok_id: u16,
    pub flags: u8,
    pub filler: u8,
    pub ec: u16,
    pub rrc: u16,
    pub snd_seq: u64,
}

pub(crate) fn parse_gssapi(i: &[u8]) -> BerResult<GssApiBuffer> {
    let (_, hdr) = der_read_element_header(i)?;
    if hdr.is_constructed() && hdr.is_application() && hdr.tag.0 == 0 {
        // probably a wrapped token
        //
        // InitialContextToken ::=
        // -- option indication (delegation, etc.) indicated within
        // -- mechanism-specific token
        // [APPLICATION 0] IMPLICIT SEQUENCE {
        //         thisMech MechType,
        //         innerContextToken ANY DEFINED BY thisMech
        //            -- contents mechanism-specific
        //            -- ASN.1 structure not required
        //         }
        parse_ber_tagged_implicit_g(0, |i, _hdr, _depth| {
            // MechType ::= OBJECT IDENTIFIER
            let (i, obj) = parse_der_oid(i)?;
            let mech_type = obj.as_oid().unwrap().clone(); // safety: only an OID object is parsed (line above)
            if mech_type == OID_KERBEROS {
                let (i, token) = parse_krb5_gss_wrap_token(i)?;
                let (_rem, payload) = rest(i)?;
                let inner = GssWrappedToken {
                    mech_type,
                    token,
                    payload,
                };
                let context = GssApiBuffer::Wrapped(inner);
                Ok((i, context))
            } else if mech_type == OID_SPNEGO {
                // SPNEGO requested (Usually in *request* token)
                Ok((i, GssApiBuffer::Spnego))
            } else {
                Ok((i, GssApiBuffer::Unknown))
            }
        })(i)
    } else {
        // could be GSS-SPNEGO, NTLMSSP, or anything microsoft calls 'Negotiate'
        // check GSSKRB5_CFX wrapping (RFC4121)
        let (_, magic) = le_u16(i)?;
        if magic == KRB_TOKEN_CFX_WRAP {
            // let (i, token) = parse_spnego_gss_wrap(i)?;
            let (i, token) = parse_krb5_gss_cfx_wrap_token(i)?;
            let (i, payload) = rest(i)?;
            let context = GssApiBuffer::GssCfxWrap { token, payload };
            Ok((i, context))
        } else {
            Ok((i, GssApiBuffer::Unknown))
        }
    }
}

fn parse_krb5_gss_wrap_token(i: &[u8]) -> BerResult<GssWrap> {
    let (i, tok_id) = le_u16(i)?;
    let (i, sgn_alg) = le_u16(i)?;
    let (i, seal_alg) = le_u16(i)?;
    let (i, filler) = le_u16(i)?;
    let (i, snd_seq) = le_u64(i)?;
    let (i, sgn_cksum) = le_u64(i)?;
    //
    // according to draft-brezak-win2k-krb-rc4-hmac-04,
    // if the signing alg is KRB_SGN_ALG_HMAC, there's an extra 8 bytes of "random confounder" after
    // the checksum
    let (i, random_confounder) = cond(
        sgn_alg == KRB_SGN_ALG_HMAC || sgn_alg == KRB_SGN_ALG_DES_MAC_MD5,
        le_u64,
    )(i)?;
    let token = GssWrap {
        tok_id,
        sgn_alg,
        seal_alg,
        filler,
        snd_seq,
        sgn_cksum,
        random_confounder,
    };
    Ok((i, token))
}

fn parse_krb5_gss_cfx_wrap_token(i: &[u8]) -> BerResult<GssCfxWrap> {
    let (i, tok_id) = le_u16(i)?;
    let (i, flags) = le_u8(i)?;
    let (i, filler) = le_u8(i)?;
    let (i, ec) = le_u16(i)?;
    let (i, rrc) = le_u16(i)?;
    let (i, snd_seq) = le_u64(i)?;
    let token = GssCfxWrap {
        tok_id,
        flags,
        filler,
        ec,
        rrc,
        snd_seq,
    };
    Ok((i, token))
}
