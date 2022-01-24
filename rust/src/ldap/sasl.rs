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

use ldap_parser::nom::{combinator::map, multi::length_data, number::streaming::be_u32, IResult};

#[derive(Debug, PartialEq)]
pub struct SaslBuffer<'a>(pub &'a [u8]);

pub(crate) fn parse_sasl_buffer(i: &[u8]) -> IResult<&[u8], SaslBuffer> {
    map(length_data(be_u32), SaslBuffer)(i)
}
