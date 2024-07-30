/*
   Unix SMB/CIFS implementation.
   Samba Version functions

   Copyright (C) David Mulder 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use std::str;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn samba_version_string() -> Option<String> {
    let null_trimmed_vers =
        &SAMBA_VERSION_STRING[..SAMBA_VERSION_STRING.len() - 1];
    match str::from_utf8(null_trimmed_vers) {
        Ok(vers) => Some(vers.to_string()),
        Err(_) => None,
    }
}

pub fn samba_copyright_string() -> Option<String> {
    let null_trimmed_copy =
        &SAMBA_COPYRIGHT_STRING[..SAMBA_COPYRIGHT_STRING.len() - 1];
    match str::from_utf8(null_trimmed_copy) {
        Ok(copy) => Some(copy.to_string()),
        Err(_) => None,
    }
}
