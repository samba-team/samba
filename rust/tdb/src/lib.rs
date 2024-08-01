/*
   Unix SMB/CIFS implementation.

   trivial database library FFI

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

use chelps::wrap_string;
use dbg::DBG_ERR;
use libc::free;
use ntstatus_gen::NT_STATUS_UNSUCCESSFUL;
use std::error::Error;
use std::ffi::c_void;
use std::fmt;
use std::sync::{Arc, Mutex};

mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(clippy::upper_case_acronyms)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const TDB_SUCCESS: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_SUCCESS;
pub const TDB_ERR_CORRUPT: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_CORRUPT;
pub const TDB_ERR_IO: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_IO;
pub const TDB_ERR_LOCK: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_LOCK;
pub const TDB_ERR_OOM: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_OOM;
pub const TDB_ERR_EXISTS: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_EXISTS;
pub const TDB_ERR_NOLOCK: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_NOLOCK;
pub const TDB_ERR_LOCK_TIMEOUT: ffi::TDB_ERROR =
    ffi::TDB_ERROR_TDB_ERR_LOCK_TIMEOUT;
pub const TDB_ERR_NOEXIST: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_NOEXIST;
pub const TDB_ERR_EINVAL: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_EINVAL;
pub const TDB_ERR_RDONLY: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_RDONLY;
pub const TDB_ERR_NESTING: ffi::TDB_ERROR = ffi::TDB_ERROR_TDB_ERR_NESTING;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
pub struct TDB_ERROR(pub u32);

impl TDB_ERROR {
    fn description(&self) -> &str {
        match self.0 {
            ffi::TDB_ERROR_TDB_SUCCESS => "TDB_SUCCESS",
            ffi::TDB_ERROR_TDB_ERR_CORRUPT => "TDB_ERR_CORRUPT",
            ffi::TDB_ERROR_TDB_ERR_IO => "TDB_ERR_IO",
            ffi::TDB_ERROR_TDB_ERR_LOCK => "TDB_ERR_LOCK",
            ffi::TDB_ERROR_TDB_ERR_OOM => "TDB_ERR_OOM",
            ffi::TDB_ERROR_TDB_ERR_EXISTS => "TDB_ERR_EXISTS",
            ffi::TDB_ERROR_TDB_ERR_NOLOCK => "TDB_ERR_NOLOCK",
            ffi::TDB_ERROR_TDB_ERR_LOCK_TIMEOUT => "TDB_ERR_LOCK_TIMEOUT",
            ffi::TDB_ERROR_TDB_ERR_NOEXIST => "TDB_ERR_NOEXIST",
            ffi::TDB_ERROR_TDB_ERR_EINVAL => "TDB_ERR_EINVAL",
            ffi::TDB_ERROR_TDB_ERR_RDONLY => "TDB_ERR_RDONLY",
            ffi::TDB_ERROR_TDB_ERR_NESTING => "TDB_ERR_NESTING",
            _ => "Unknown TDB_ERROR error code",
        }
    }
}

macro_rules! lock_check {
    ($res:expr) => {{
        $res.map_err(|e| {
            DBG_ERR!("Failed to obtain tdb lock: {:?}", e);
            Box::new(TDB_ERROR(TDB_ERR_NOLOCK))
        })?
    }};
}

impl fmt::Display for TDB_ERROR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TDB_ERROR({:#x}): {}", self.0, self.description())
    }
}

impl fmt::Debug for TDB_ERROR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TDB_ERROR({:#x})", self.0)
    }
}

impl std::error::Error for TDB_ERROR {}

#[derive(Clone)]
pub struct Tdb {
    tdb: Arc<Mutex<*mut ffi::tdb_context>>,
}

impl Tdb {
    pub fn open(
        name: &str,
        hash_size: Option<i32>,
        tdb_flags: Option<i32>,
        open_flags: Option<i32>,
        mode: Option<u32>,
    ) -> Result<Self, Box<dyn Error + '_>> {
        let tdb = unsafe {
            ffi::tdb_open(
                wrap_string(name),
                hash_size.unwrap_or(0),
                tdb_flags.unwrap_or(ffi::TDB_DEFAULT as i32),
                open_flags.unwrap_or(libc::O_RDWR),
                mode.unwrap_or(0o600),
            )
        };
        if tdb.is_null() {
            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
        }
        Ok(Tdb {
            tdb: Arc::new(Mutex::new(tdb)),
        })
    }

    pub fn transaction_start(&mut self) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        unsafe { Ok(ffi::tdb_transaction_start(*tdb) == 0) }
    }

    pub fn transaction_commit(&mut self) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        unsafe { Ok(ffi::tdb_transaction_commit(*tdb) == 0) }
    }

    pub fn transaction_cancel(&mut self) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        unsafe { Ok(ffi::tdb_transaction_cancel(*tdb) == 0) }
    }

    pub fn exists(&self, key: &str) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = lock_check!(self.tdb.lock());
        let key = ffi::TDB_DATA {
            dptr: wrap_string(key) as *mut u8,
            dsize: key.len(),
        };
        unsafe { Ok(ffi::tdb_exists(*tdb, key) == 1) }
    }

    pub fn fetch(&self, key: &str) -> Result<String, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        let key = ffi::TDB_DATA {
            dptr: wrap_string(key) as *mut u8,
            dsize: key.len(),
        };
        let res = unsafe { ffi::tdb_fetch(*tdb, key) };
        if res.dptr.is_null() {
            let err = unsafe { ffi::tdb_error(*tdb) };
            return Err(Box::new(TDB_ERROR(err)));
        }
        Ok(unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                res.dptr, res.dsize,
            ))
        }
        .to_string())
    }

    pub fn delete(&mut self, key: &str) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        let key = ffi::TDB_DATA {
            dptr: wrap_string(key) as *mut u8,
            dsize: key.len(),
        };
        unsafe { Ok(ffi::tdb_delete(*tdb, key) == 0) }
    }

    pub fn store(
        &mut self,
        key: &str,
        dbuf: &[u8],
        flag: Option<u32>,
    ) -> Result<bool, Box<dyn Error + '_>> {
        let tdb = self.tdb.lock()?;
        let flag = match flag {
            Some(flag) => flag,
            None => ffi::TDB_REPLACE,
        };
        let key = ffi::TDB_DATA {
            dptr: wrap_string(key) as *mut u8,
            dsize: key.len(),
        };
        let dbuf = ffi::TDB_DATA {
            dptr: dbuf.as_ptr() as *mut u8,
            dsize: dbuf.len(),
        };
        unsafe { Ok(ffi::tdb_store(*tdb, key, dbuf, flag as i32) == 0) }
    }

    pub fn keys(&self) -> Result<Vec<String>, Box<dyn Error + '_>> {
        let mut res = Vec::new();
        let tdb = self.tdb.lock()?;
        let mut key = unsafe { ffi::tdb_firstkey(*tdb) };
        if key.dptr.is_null() {
            return Ok(res);
        }
        let rkey = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                key.dptr, key.dsize,
            ))
        }
        .to_string();
        res.push(rkey);

        loop {
            let next = unsafe { ffi::tdb_nextkey(*tdb, key) };
            unsafe { free(key.dptr as *mut c_void) };
            if next.dptr.is_null() {
                break;
            } else {
                let rkey = unsafe {
                    std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                        next.dptr, next.dsize,
                    ))
                }
                .to_string();
                res.push(rkey);
            }
            key = next;
        }

        Ok(res)
    }
}

impl Drop for Tdb {
    fn drop(&mut self) {
        let tdb = self.tdb.lock().unwrap();
        unsafe { ffi::tdb_close(*tdb) };
    }
}

unsafe impl Send for Tdb {}
unsafe impl Sync for Tdb {}
