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

#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);

        let base_name = match name.rfind("::") {
            Some(pos) => &name[..pos],
            None => name,
        };
        let parts: Vec<&str> = base_name
            .split("::")
            .filter(|&p| p != "{{closure}}")
            .collect();
        parts.join("::")
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_wrap_c_char_non_null() {
        let original = "Hello, world!";
        let c_string = CString::new(original).expect("CString::new failed");
        let c_ptr = c_string.as_ptr();

        let result = unsafe { wrap_c_char(c_ptr) };
        assert_eq!(result, Some(original.to_string()));
    }

    #[test]
    fn test_wrap_c_char_null() {
        let result = unsafe { wrap_c_char(ptr::null()) };
        assert!(result.is_none());
    }

    #[test]
    fn test_wrap_c_char_invalid_utf8() {
        let invalid_utf8 = vec![0xff, 0xff, 0xff, 0xff];
        let c_string = CString::new(invalid_utf8).expect("CString::new failed");
        let c_ptr = c_string.as_ptr();

        let result = unsafe { wrap_c_char(c_ptr) };
        assert!(result.is_none());
    }

    #[test]
    fn test_wrap_string() {
        let original = "Hello, world!";
        let c_ptr = wrap_string(original);

        let c_str = unsafe { CStr::from_ptr(c_ptr) };
        let result = c_str.to_str().expect("CStr::to_str failed");

        assert_eq!(result, original);

        // Clean up the allocated memory
        unsafe { string_free(c_ptr) };
    }

    #[test]
    fn test_wrap_string_empty() {
        let original = "";
        let c_ptr = wrap_string(original);

        let c_str = unsafe { CStr::from_ptr(c_ptr) };
        let result = c_str.to_str().expect("CStr::to_str failed");

        assert_eq!(result, original);

        // Clean up the allocated memory
        unsafe { string_free(c_ptr) };
    }

    #[test]
    fn test_wrap_string_null_pointer() {
        let c_ptr = wrap_string("\0");
        assert!(c_ptr.is_null());
    }

    #[test]
    fn test_string_free_null() {
        unsafe { string_free(ptr::null_mut()) };
        // No assertion needed, just ensuring no crash occurs
    }

    #[test]
    fn test_string_free_non_null() {
        let original = "Hello, world!";
        let c_ptr = wrap_string(original);

        unsafe { string_free(c_ptr) };
        // No assertion needed, just ensuring the memory was freed without a crash
    }
}
