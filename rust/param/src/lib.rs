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

use chelps::{string_free, wrap_c_char, wrap_string};
use dbg::{DBG_ERR, DBG_INFO, DBG_WARNING};
use ntstatus_gen::NT_STATUS_UNSUCCESSFUL;
use std::error::Error;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};

mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(clippy::upper_case_acronyms)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct LoadParm {
    lp: Arc<Mutex<*mut ffi::loadparm_context>>,
}

macro_rules! lpcfg_str {
    ($var:ident) => {
        paste::item! {
            pub fn $var (&self) -> Result<Option<String>, Box<dyn Error + '_>> {
                let lp = self.lp.lock()?;
                let val = unsafe { ffi::[< lpcfg_ $var >] (*lp) } ;
                unsafe { Ok(wrap_c_char(val)) }
            }
        }
    };
}

macro_rules! lpcfg_i32 {
    ($var:ident) => {
        paste::item! {
            pub fn $var (&self) -> Result<i32, Box<dyn Error + '_>> {
                let lp = self.lp.lock()?;
                unsafe { Ok(ffi::[< lpcfg_ $var >] (*lp)) }
            }
        }
    };
}

macro_rules! lpcfg_bool {
    ($var:ident) => {
        paste::item! {
            pub fn $var (&self) -> Result<bool, Box<dyn Error + '_>> {
                let lp = self.lp.lock()?;
                unsafe { Ok(ffi::[< lpcfg_ $var >] (*lp) != 0) }
            }
        }
    };
}

impl LoadParm {
    pub fn new(configfile: Option<&str>) -> Result<Self, Box<dyn Error + '_>> {
        let lp = unsafe {
            match configfile {
                Some(configfile) => {
                    let configfile_cstr = wrap_string(configfile);
                    let lp = ffi::loadparm_init_global(0);
                    if ffi::lpcfg_load(lp, configfile_cstr) != 1 {
                        return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                    }
                    string_free(configfile_cstr);
                    lp
                }
                None => ffi::loadparm_init_global(1),
            }
        };
        Ok(LoadParm {
            lp: Arc::new(Mutex::new(lp)),
        })
    }

    pub fn private_path(
        &self,
        name: &str,
    ) -> Result<Option<String>, Box<dyn Error + '_>> {
        let lp = self.lp.lock()?;
        let path = unsafe {
            let name_cstr = wrap_string(name);
            let path =
                ffi::lpcfg_private_path(*lp as *mut c_void, *lp, name_cstr);
            string_free(name_cstr);
            path
        };
        unsafe { Ok(wrap_c_char(path)) }
    }

    pub fn logfile(&self) -> Result<Option<String>, Box<dyn Error + '_>> {
        let lp = self.lp.lock()?;
        let logfile = unsafe {
            let lp_sub = ffi::lpcfg_noop_substitution();
            ffi::lpcfg_logfile(*lp, lp_sub, *lp as *mut c_void)
        };
        unsafe { Ok(wrap_c_char(logfile)) }
    }

    pub fn idmap_range(
        &self,
        domain_name: &str,
    ) -> Result<(u32, u32), Box<dyn Error + '_>> {
        if let Ok(Some(backend)) = self.idmap_backend(domain_name) {
            if backend != "upn" {
                DBG_ERR!("Backend '{}' is not supported for Entra ID", backend);
                return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
            }
        } else if domain_name != "*" {
            DBG_WARNING!(
                "No idmap backend configured for domain '{}'",
                domain_name
            );
            DBG_INFO!("Falling back to default idmap configuration");
            return self.idmap_range("*");
        } else {
            DBG_WARNING!("No idmap backend configured");
            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
        }
        let lp = self.lp.lock()?;
        let parm_name = format!("idmap config {}", domain_name);
        let parm_opt = "range";
        let range = unsafe {
            let parm_name_cstr = wrap_string(&parm_name);
            let parm_opt_cstr = wrap_string(parm_opt);
            let parm_opt_value = ffi::lpcfg_parm_string(
                *lp,
                ptr::null_mut(),
                parm_name_cstr,
                parm_opt_cstr,
            );
            string_free(parm_name_cstr);
            string_free(parm_opt_cstr);
            wrap_c_char(parm_opt_value)
        }
        .ok_or(Box::new(NT_STATUS_UNSUCCESSFUL))?;
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            DBG_ERR!("Failed to parse the idmap range: {}", range);
            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
        }
        Ok((parts[0].parse::<u32>()?, parts[1].parse::<u32>()?))
    }

    pub fn idmap_backend(
        &self,
        domain_name: &str,
    ) -> Result<Option<String>, Box<dyn Error + '_>> {
        let lp = self.lp.lock()?;
        let parm_name = format!("idmap config {}", domain_name);
        let parm_opt = "backend";
        unsafe {
            let parm_name_cstr = wrap_string(&parm_name);
            let parm_opt_cstr = wrap_string(parm_opt);
            let parm_opt_value = ffi::lpcfg_parm_string(
                *lp,
                ptr::null_mut(),
                parm_name_cstr,
                parm_opt_cstr,
            );
            string_free(parm_name_cstr);
            string_free(parm_opt_cstr);
            Ok(wrap_c_char(parm_opt_value))
        }
    }

    lpcfg_str!(realm);
    lpcfg_str!(winbindd_socket_directory);
    lpcfg_i32!(winbind_request_timeout);
    lpcfg_bool!(himmelblaud_sfa_fallback);
    lpcfg_bool!(himmelblaud_hello_enabled);
    lpcfg_str!(cache_directory);
    lpcfg_str!(template_homedir);
    lpcfg_str!(template_shell);
    lpcfg_str!(himmelblaud_hsm_pin_path);
}

unsafe impl Send for LoadParm {}
unsafe impl Sync for LoadParm {}
