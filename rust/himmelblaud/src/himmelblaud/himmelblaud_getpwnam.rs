/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for nss getpwnam

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
use dbg::{DBG_ERR, DBG_WARNING};
use ntstatus_gen::*;
use sock::{Passwd, Response};

impl Resolver {
    pub(crate) fn create_passwd_from_upn(
        &mut self,
        upn: &str,
        gecos: &str,
    ) -> Result<Passwd, Box<NTSTATUS>> {
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
        let uid = self
            .idmap
            .gen_to_unix(&self.tenant_id, &upn.to_lowercase())
            .map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_INVALID_TOKEN)
            })?;
        // Store the calculated uid -> upn map in the cache
        self.uid_cache.store(uid, &upn)?;
        let (cn, domain) = match split_username(&upn) {
            Ok(res) => res,
            Err(e) => {
                DBG_ERR!("Failed to parse user upn '{}': {:?}", upn, e);
                return Err(Box::new(NT_STATUS_INVALID_USER_PRINCIPAL_NAME));
            }
        };
        let homedir = template_homedir
            .clone()
            .replace("%D", &domain)
            .replace("%U", &cn);
        let passwd = Passwd {
            name: upn.to_string(),
            passwd: "x".to_string(),
            uid,
            gid: uid,
            gecos: gecos.to_string(),
            dir: homedir,
            shell: shell.clone(),
        };
        return Ok(passwd);
    }

    pub(crate) async fn getpwnam(
        &mut self,
        account_id: &str,
    ) -> Result<Response, Box<NTSTATUS>> {
        // We first try to fetch the user from the cache, so that we
        // get the gecos. Otherwise we can just create a passwd entry
        // based on whether the upn exists in Entra ID.
        let entry = match self.user_cache.fetch(account_id) {
            Some(entry) => entry,
            None => {
                // Check if the user exists in Entra ID
                let exists = match self
                    .client
                    .lock()
                    .await
                    .check_user_exists(&account_id)
                    .await
                {
                    Ok(exists) => exists,
                    Err(e) => {
                        DBG_WARNING!("{:?}", e);
                        return Ok(Response::NssAccount(None));
                    }
                };
                if exists {
                    return Ok(Response::NssAccount(Some(
                        self.create_passwd_from_upn(account_id, "")?,
                    )));
                }
                return Ok(Response::NssAccount(None));
            }
        };
        return Ok(Response::NssAccount(Some(
            self.create_passwd_from_upn(&entry.upn, &entry.name)?,
        )));
    }
}
