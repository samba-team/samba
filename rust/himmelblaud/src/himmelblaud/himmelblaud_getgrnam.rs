/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getgrnam

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
use dbg::DBG_ERR;
use ntstatus_gen::*;
use sock::{Group, Response};

impl Resolver {
    pub(crate) async fn getgrnam(
        &mut self,
        grp_id: &str,
    ) -> Result<Response, Box<NTSTATUS>> {
        let entry = match self.group_cache.fetch(grp_id) {
            Some(entry) => entry,
            None => return Ok(Response::NssGroup(None)),
        };
        let gid = self
            .idmap
            .gen_to_unix(&self.tenant_id, &entry.uuid.to_uppercase())
            .map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_INVALID_TOKEN)
            })?;
        // Store the calculated gid -> uuid map in the cache
        self.uid_cache.store(gid, &entry.uuid.to_uppercase())?;
        let group = Group {
            name: entry.uuid.clone(),
            passwd: "x".to_string(),
            gid,
            members: entry.members(),
        };
        return Ok(Response::NssGroup(Some(group)));
    }
}
