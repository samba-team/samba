/*
   Unix SMB/CIFS implementation.

   Parameter loading functions

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

pub const MAX_DEBUG_LEVEL: u32 = ffi::MAX_DEBUG_LEVEL;
pub const DBGLVL_ERR: u32 = ffi::DBGLVL_ERR;
pub const DBGLVL_WARNING: u32 = ffi::DBGLVL_WARNING;
pub const DBGLVL_NOTICE: u32 = ffi::DBGLVL_NOTICE;
pub const DBGLVL_INFO: u32 = ffi::DBGLVL_INFO;
pub const DBGLVL_DEBUG: u32 = ffi::DBGLVL_DEBUG;

pub const DEBUG_DEFAULT_STDERR: ffi::debug_logtype =
    ffi::debug_logtype_DEBUG_DEFAULT_STDERR;
pub const DEBUG_DEFAULT_STDOUT: ffi::debug_logtype =
    ffi::debug_logtype_DEBUG_DEFAULT_STDOUT;
pub const DEBUG_FILE: ffi::debug_logtype = ffi::debug_logtype_DEBUG_FILE;
pub const DEBUG_STDOUT: ffi::debug_logtype = ffi::debug_logtype_DEBUG_STDOUT;
pub const DEBUG_STDERR: ffi::debug_logtype = ffi::debug_logtype_DEBUG_STDERR;
pub const DEBUG_CALLBACK: ffi::debug_logtype =
    ffi::debug_logtype_DEBUG_CALLBACK;

pub fn debug_set_logfile(name: &str) {
    let name_cstr = chelps::wrap_string(name);
    unsafe {
        ffi::debug_set_logfile(name_cstr);
        chelps::string_free(name_cstr);
    }
}

pub fn setup_logging(prog_name: &str, new_logtype: ffi::debug_logtype) {
    let prog_name_cstr = chelps::wrap_string(prog_name);
    unsafe {
        ffi::setup_logging(prog_name_cstr, new_logtype);
        chelps::string_free(prog_name_cstr);
    }
}

#[macro_export]
macro_rules! debuglevel_set {
    ($level:expr) => {{
        unsafe {
            dbg::ffi::debuglevel_set_class(
                dbg::ffi::DBGC_ALL as usize,
                $level as i32,
            )
        }
    }};
}

#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);

        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

#[macro_export]
macro_rules! DBG_PREFIX {
    ($level:expr $(, $arg:expr)* $(,)?) => {{
        if $level <= dbg::ffi::MAX_DEBUG_LEVEL {
            let location = format!("{}:{}", file!(), line!());
            let location_cstr = chelps::wrap_string(&location);
            let function = dbg::function!();
            let function_msg = format!("{}: ", function);
            let function_cstr = chelps::wrap_string(function);
            let function_msg_cstr = chelps::wrap_string(&function_msg);
            let msg = format!($($arg),*);
            let msg_cstr = chelps::wrap_string(&msg);
            unsafe {
                let _ = dbg::ffi::debuglevel_get_class(dbg::ffi::DBGC_CLASS as usize) >= ($level as i32)
                    && dbg::ffi::dbghdrclass($level as i32,
			    dbg::ffi::DBGC_CLASS as i32,
			    location_cstr,
			    function_cstr)
                    && dbg::ffi::dbgtext(function_msg_cstr)
                    && dbg::ffi::dbgtext(msg_cstr);
                chelps::string_free(location_cstr);
                chelps::string_free(function_cstr);
                chelps::string_free(function_msg_cstr);
                chelps::string_free(msg_cstr);
            }
        }
    }}
}

#[macro_export]
macro_rules! DBG_ERR {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        dbg::DBG_PREFIX!(dbg::ffi::DBGLVL_ERR, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_WARNING {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        dbg::DBG_PREFIX!(dbg::ffi::DBGLVL_WARNING, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_NOTICE {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        dbg::DBG_PREFIX!(dbg::ffi::DBGLVL_NOTICE, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_INFO {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        dbg::DBG_PREFIX!(dbg::ffi::DBGLVL_INFO, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_DEBUG {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        dbg::DBG_PREFIX!(dbg::ffi::DBGLVL_DEBUG, $msg, $($arg),*)
    }}
}
