/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getpwuid

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
use crate::himmelblaud::Resolver;
use libc::uid_t;
use ntstatus_gen::NTSTATUS;
use sock::Response;

impl Resolver {
    pub(crate) async fn getpwuid(
        &mut self,
        uid: uid_t,
    ) -> Result<Response, Box<NTSTATUS>> {
        if let Some(upn) = self.uid_cache.fetch(uid) {
            if let Some(entry) = self.user_cache.fetch(&upn) {
                Ok(Response::NssAccount(Some(
                    self.create_passwd_from_upn(&entry.upn, &entry.name)?,
                )))
            } else {
                Ok(Response::NssAccount(Some(
                    self.create_passwd_from_upn(&upn, "")?,
                )))
            }
        } else {
            Ok(Response::NssAccount(None))
        }
    }
}
