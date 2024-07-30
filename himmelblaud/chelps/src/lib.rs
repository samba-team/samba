/*
   Unix SMB/CIFS implementation.

   C conversion helper functions and macros

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

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

pub unsafe fn wrap_c_char(input: *const c_char) -> Option<String> {
    if input.is_null() {
        return None;
    }

    let c_str = unsafe { CStr::from_ptr(input) };
    match c_str.to_str() {
        Ok(output) => Some(output.to_string()),
        Err(_) => None,
    }
}

pub fn wrap_string(input: &str) -> *mut c_char {
    match CString::new(input.to_string()) {
        Ok(msg) => msg.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

pub unsafe fn string_free(input: *mut c_char) {
    if !input.is_null() {
        unsafe {
            let _ = CString::from_raw(input);
        }
    }
}
