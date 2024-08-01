/*
   Himmelblaud

   ID-mapping library

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
use dbg::DBG_ERR;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::sync::{Arc, Mutex};

mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(PartialEq, Eq)]
pub struct IdmapError(u32);

pub const IDMAP_SUCCESS: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_SUCCESS);
pub const IDMAP_NOT_IMPLEMENTED: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NOT_IMPLEMENTED);
pub const IDMAP_ERROR: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_ERROR);
pub const IDMAP_OUT_OF_MEMORY: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_OUT_OF_MEMORY);
pub const IDMAP_NO_DOMAIN: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NO_DOMAIN);
pub const IDMAP_CONTEXT_INVALID: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_CONTEXT_INVALID);
pub const IDMAP_SID_INVALID: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_SID_INVALID);
pub const IDMAP_SID_UNKNOWN: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_SID_UNKNOWN);
pub const IDMAP_NO_RANGE: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NO_RANGE);
pub const IDMAP_BUILTIN_SID: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_BUILTIN_SID);
pub const IDMAP_OUT_OF_SLICES: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_OUT_OF_SLICES);
pub const IDMAP_COLLISION: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_COLLISION);
pub const IDMAP_EXTERNAL: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_EXTERNAL);
pub const IDMAP_NAME_UNKNOWN: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NAME_UNKNOWN);
pub const IDMAP_NO_REVERSE: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NO_REVERSE);
pub const IDMAP_ERR_LAST: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_ERR_LAST);

impl fmt::Display for IdmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdmapError({:#x})", self.0)
    }
}

impl fmt::Debug for IdmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdmapError({:#x})", self.0)
    }
}

impl std::error::Error for IdmapError {}

pub struct Idmap {
    ctx: Arc<Mutex<*mut ffi::sss_idmap_ctx>>,
}

impl Idmap {
    pub fn new() -> Result<Idmap, IdmapError> {
        let mut ctx = ptr::null_mut();
        unsafe {
            match IdmapError(ffi::sss_idmap_init(
                None,
                ptr::null_mut(),
                None,
                &mut ctx,
            )) {
                IDMAP_SUCCESS => Ok(Idmap {
                    ctx: Arc::new(Mutex::new(ctx)),
                }),
                e => Err(e),
            }
        }
    }

    pub fn add_gen_domain(
        &mut self,
        domain_name: &str,
        tenant_id: &str,
        range: (u32, u32),
    ) -> Result<(), IdmapError> {
        let ctx = self.ctx.lock().map_err(|e| {
            DBG_ERR!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IDMAP_ERROR
        })?;
        let domain_name_cstr =
            CString::new(domain_name).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let tenant_id_cstr =
            CString::new(tenant_id).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let mut idmap_range = ffi::sss_idmap_range {
            min: range.0,
            max: range.1,
        };
        unsafe {
            match IdmapError(ffi::sss_idmap_add_gen_domain_ex(
                *ctx,
                domain_name_cstr.as_ptr(),
                tenant_id_cstr.as_ptr(),
                &mut idmap_range,
                ptr::null_mut(),
                None,
                None,
                ptr::null_mut(),
                0,
                false,
            )) {
                IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn gen_to_unix(
        &self,
        tenant_id: &str,
        input: &str,
    ) -> Result<u32, IdmapError> {
        let ctx = self.ctx.lock().map_err(|e| {
            DBG_ERR!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IDMAP_ERROR
        })?;
        let tenant_id_cstr =
            CString::new(tenant_id).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let input_cstr = CString::new(input.to_lowercase())
            .map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        unsafe {
            let mut id: u32 = 0;
            match IdmapError(ffi::sss_idmap_gen_to_unix(
                *ctx,
                tenant_id_cstr.as_ptr(),
                input_cstr.as_ptr(),
                &mut id,
            )) {
                IDMAP_SUCCESS => Ok(id),
                e => Err(e),
            }
        }
    }
}

impl Drop for Idmap {
    fn drop(&mut self) {
        match self.ctx.lock() {
            Ok(ctx) => unsafe {
                let _ = ffi::sss_idmap_free(*ctx);
            },
            Err(e) => {
                DBG_ERR!(
                    "Failed obtaining write lock on sss_idmap_ctx during drop: {}",
                    e
                );
            }
        }
    }
}

unsafe impl Send for Idmap {}
unsafe impl Sync for Idmap {}

#[cfg(test)]
mod tests {
    use crate::Idmap;
    use std::collections::HashMap;
    pub const DEFAULT_IDMAP_RANGE: (u32, u32) = (200000, 2000200000);

    #[test]
    fn sssd_idmapping() {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new().expect("Idmap initialization failed");

        idmap
            .add_gen_domain(domain, tenant_id, DEFAULT_IDMAP_RANGE)
            .expect("Failed initializing test domain idmapping");

        // Verify we always get the same mapping for various users
        let mut usermap: HashMap<String, u32> = HashMap::new();
        usermap.insert("tux@contoso.onmicrosoft.com".to_string(), 1912749799);
        usermap.insert("admin@contoso.onmicrosoft.com".to_string(), 297515919);
        usermap.insert("dave@contoso.onmicrosoft.com".to_string(), 132631922);
        usermap.insert("joe@contoso.onmicrosoft.com".to_string(), 361591965);
        usermap.insert("georg@contoso.onmicrosoft.com".to_string(), 866887005);

        for (username, expected_uid) in &usermap {
            let uid = idmap.gen_to_unix(tenant_id, username).expect(&format!(
                "Failed converting username {} to uid",
                username
            ));
            assert_eq!(
                uid, *expected_uid,
                "Uid for {} did not match",
                username
            );
        }
    }
}
