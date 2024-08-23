/*
   Unix SMB/CIFS implementation.

   Talloc stackframe functions

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

pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(clippy::upper_case_acronyms)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[macro_export]
macro_rules! talloc_stackframe {
    () => {{
        let function = chelps::function!();
        let function_cstr = chelps::wrap_string(&function);
        unsafe {
            let ret = $crate::ffi::_talloc_stackframe(function_cstr);
            chelps::string_free(function_cstr);
            ret
        }
    }};
}

#[macro_export]
macro_rules! TALLOC_FREE {
    ($ctx:ident) => {{
        if !$ctx.is_null() {
            let function = chelps::function!();
            let function_cstr = chelps::wrap_string(&function);
            unsafe {
                $crate::ffi::_talloc_free($ctx, function_cstr);
                chelps::string_free(function_cstr);
            }
        }
    }};
}
