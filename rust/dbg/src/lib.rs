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

pub fn dbgflush() {
    unsafe {
        ffi::dbgflush();
    }
}

#[macro_export]
macro_rules! debuglevel_set {
    ($level:expr) => {{
        unsafe {
            $crate::ffi::debuglevel_set_class(
                $crate::ffi::DBGC_ALL as usize,
                $level as i32,
            )
        }
    }};
}

#[macro_export]
macro_rules! DBG_PREFIX {
    ($level:expr $(, $arg:expr)* $(,)?) => {{
        if $level <= $crate::ffi::MAX_DEBUG_LEVEL {
            let location = format!("{}:{}", file!(), line!());
            let location_cstr = chelps::wrap_string(&location);
            let function = chelps::function!();
            let function_msg = format!("{}: ", function);
            let function_cstr = chelps::wrap_string(&function);
            let function_msg_cstr = chelps::wrap_string(&function_msg);
            let msg = format!($($arg),*);
            let msg_cstr = chelps::wrap_string(&msg);
            unsafe {
                let _ = $crate::ffi::debuglevel_get_class($crate::ffi::DBGC_CLASS as usize) >= ($level as i32)
                    && $crate::ffi::dbghdrclass($level as i32,
			    $crate::ffi::DBGC_CLASS as i32,
			    location_cstr,
			    function_cstr)
                    && $crate::ffi::dbgtext(function_msg_cstr)
                    && $crate::ffi::dbgtext(msg_cstr);
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
        $crate::DBG_PREFIX!($crate::ffi::DBGLVL_ERR, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_WARNING {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        $crate::DBG_PREFIX!($crate::ffi::DBGLVL_WARNING, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_NOTICE {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        $crate::DBG_PREFIX!($crate::ffi::DBGLVL_NOTICE, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_INFO {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        $crate::DBG_PREFIX!($crate::ffi::DBGLVL_INFO, $msg, $($arg),*)
    }}
}

#[macro_export]
macro_rules! DBG_DEBUG {
    ($msg:expr $(, $arg:expr)* $(,)?) => {{
        $crate::DBG_PREFIX!($crate::ffi::DBGLVL_DEBUG, $msg, $($arg),*)
    }}
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;
    use std::fs::File;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_debug_constants() {
        assert_eq!(MAX_DEBUG_LEVEL, ffi::MAX_DEBUG_LEVEL);
        assert_eq!(DBGLVL_ERR, ffi::DBGLVL_ERR);
        assert_eq!(DBGLVL_WARNING, ffi::DBGLVL_WARNING);
        assert_eq!(DBGLVL_NOTICE, ffi::DBGLVL_NOTICE);
        assert_eq!(DBGLVL_INFO, ffi::DBGLVL_INFO);
        assert_eq!(DBGLVL_DEBUG, ffi::DBGLVL_DEBUG);

        assert_eq!(
            DEBUG_DEFAULT_STDERR,
            ffi::debug_logtype_DEBUG_DEFAULT_STDERR
        );
        assert_eq!(
            DEBUG_DEFAULT_STDOUT,
            ffi::debug_logtype_DEBUG_DEFAULT_STDOUT
        );
        assert_eq!(DEBUG_FILE, ffi::debug_logtype_DEBUG_FILE);
        assert_eq!(DEBUG_STDOUT, ffi::debug_logtype_DEBUG_STDOUT);
        assert_eq!(DEBUG_STDERR, ffi::debug_logtype_DEBUG_STDERR);
        assert_eq!(DEBUG_CALLBACK, ffi::debug_logtype_DEBUG_CALLBACK);
    }

    macro_rules! test_dbg_macro {
        ($level:ident) => {
            paste! {
                #[test]
                fn [<test_dbg_ $level:lower _macro>]() {
                    let logfile = NamedTempFile::new().expect("Failed to create temporary file");
                    let logfile = logfile.path().to_str().unwrap();
                    setup_logging("test_program", DEBUG_FILE);
                    debug_set_logfile(logfile);

                    let logfile_output = concat!("This is a ", stringify!($level), " message");

                    debuglevel_set!([<DBGLVL_ $level:upper>]);

                    [<DBG_ $level:upper>]!("{}\n", logfile_output);
                    dbgflush();

                    let mut file = File::open(logfile).expect("Failed to open logfile");
                    let mut logfile_contents = String::new();
                    file.read_to_string(&mut logfile_contents)
                        .expect("Failed to read logfile");
                    assert!(
                        logfile_contents.contains(logfile_output),
                        "Test data missing from logfile: {}",
                        logfile_contents
                    );
                }
            }
        };
    }

    test_dbg_macro!(DEBUG);
    // Multiple re-inits of the debug env cause it to fail, so we can't
    // reliably test all of these in one go.
    //test_dbg_macro!(INFO);
    //test_dbg_macro!(NOTICE);
    //test_dbg_macro!(WARNING);
    //test_dbg_macro!(ERR);
}
