/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getgrent

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
    pub(crate) async fn getgrent(&mut self) -> Result<Response, Box<NTSTATUS>> {
        let group_entries = self.group_cache.fetch_all()?;
        let mut res = Vec::new();
        for entry in group_entries {
            let name = entry.uuid.clone();
            let gid = self
                .idmap
                .gen_to_unix(&self.tenant_id, &entry.uuid.to_uppercase())
                .map_err(|e| {
                    DBG_ERR!("{:?}", e);
                    Box::new(NT_STATUS_NO_SUCH_GROUP)
                })?;
            let group = Group {
                name,
                passwd: "x".to_string(),
                gid,
                members: entry.members(),
            };
            res.push(group);
        }
        Ok(Response::NssGroups(res))
    }
}
