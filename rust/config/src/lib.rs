/*
   Unix SMB/CIFS implementation.

   Samba config imported into Rust

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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_using_system_tdb() {
        // This test just ensures that USING_SYSTEM_TDB is available from the
        // config. None of the other options are really used at the moment.
        assert!(
            USING_SYSTEM_TDB == 0 || USING_SYSTEM_TDB == 1,
            "Unexpected value for USING_SYSTEM_TDB: {}",
            USING_SYSTEM_TDB
        );
    }
}
