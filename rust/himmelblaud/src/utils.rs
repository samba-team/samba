/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon common utilities

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
use ntstatus_gen::*;

pub fn split_username(
    username: &str,
) -> Result<(String, String), Box<NTSTATUS>> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Ok((tup[0].to_string(), tup[1].to_string()));
    }
    Err(Box::new(NT_STATUS_INVALID_USER_PRINCIPAL_NAME))
}
