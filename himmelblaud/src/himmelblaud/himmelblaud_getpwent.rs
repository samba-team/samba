/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getpwent

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
use crate::utils::split_username;
use dbg::DBG_ERR;
use ntstatus_gen::*;
use sock::{Passwd, Response};

impl Resolver {
    pub(crate) async fn getpwent(&mut self) -> Result<Response, Box<NTSTATUS>> {
        let user_entries = self.user_cache.fetch_all()?;
        let template_homedir = self
            .lp
            .template_homedir()
            .map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_NOT_A_DIRECTORY)
            })?
            .ok_or_else(|| {
                DBG_ERR!("Failed to discover template homedir. Is it set?");
                Box::new(NT_STATUS_NOT_A_DIRECTORY)
            })?;
        let shell = self
            .lp
            .template_shell()
            .map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_NOT_A_DIRECTORY)
            })?
            .ok_or_else(|| {
                DBG_ERR!("Failed to discover template shell. Is it set?");
                Box::new(NT_STATUS_NOT_A_DIRECTORY)
            })?;
        let mut res = Vec::new();
        for entry in user_entries {
            let uid = self
                .idmap
                .gen_to_unix(&self.tenant_id, &entry.upn.to_lowercase())
                .map_err(|e| {
                    DBG_ERR!("{:?}", e);
                    Box::new(NT_STATUS_INVALID_TOKEN)
                })?;
            let upn = entry.upn.clone();
            let (cn, domain) = match split_username(&upn) {
                Ok(res) => res,
                Err(e) => {
                    DBG_ERR!(
                        "Failed to parse user upn '{}': {:?}",
                        &entry.upn,
                        e
                    );
                    return Err(Box::new(
                        NT_STATUS_INVALID_USER_PRINCIPAL_NAME,
                    ));
                }
            };
            let homedir = template_homedir
                .clone()
                .replace("%D", &domain)
                .replace("%U", &cn);
            let passwd = Passwd {
                name: entry.upn.clone(),
                passwd: "x".to_string(),
                uid,
                gid: uid,
                gecos: entry.name,
                dir: homedir,
                shell: shell.clone(),
            };
            res.push(passwd);
        }
        Ok(Response::NssAccounts(res))
    }
}
