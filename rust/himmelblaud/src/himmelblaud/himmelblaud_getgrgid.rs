/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getgrgid

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
use libc::gid_t;
use ntstatus_gen::NTSTATUS;
use sock::{Group, Response};

impl Resolver {
    pub(crate) async fn getgrgid(
        &mut self,
        gid: gid_t,
    ) -> Result<Response, Box<NTSTATUS>> {
        if let Some(uuid) = self.uid_cache.fetch(gid) {
            if let Some(entry) = self.group_cache.fetch(&uuid) {
                return Ok(Response::NssGroup(Some(Group {
                    name: entry.uuid.clone(),
                    passwd: "x".to_string(),
                    gid,
                    members: entry.members(),
                })));
            }
        }
        Ok(Response::NssGroup(None))
    }
}
