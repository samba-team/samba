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
                .gen_to_unix(&self.tenant_id, &entry.upn)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::UserEntry;
    use crate::{GroupCache, PrivateCache, UidCache, UserCache};
    use idmap::Idmap;
    use param::LoadParm;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_getpwent() {
        // Create a temporary directory for the cache
        let dir = tempdir().unwrap();

        // Initialize the caches
        let private_cache_path = dir
            .path()
            .join("himmelblau.tdb")
            .to_str()
            .unwrap()
            .to_string();
        let pcache = PrivateCache::new(&private_cache_path).unwrap();
        let user_cache_path = dir
            .path()
            .join("himmelblau_users.tdb")
            .to_str()
            .unwrap()
            .to_string();
        let mut user_cache = UserCache::new(&user_cache_path).unwrap();
        let uid_cache_path = dir
            .path()
            .join("uid_cache.tdb")
            .to_str()
            .unwrap()
            .to_string();
        let uid_cache = UidCache::new(&uid_cache_path).unwrap();
        let group_cache_path = dir
            .path()
            .join("himmelblau_groups.tdb")
            .to_str()
            .unwrap()
            .to_string();
        let group_cache = GroupCache::new(&group_cache_path).unwrap();

        // Insert dummy UserEntrys into the cache
        let dummy_user = UserEntry {
            upn: "user1@test.com".to_string(),
            uuid: "731e9af3-668d-4033-afd1-9f09b9120cc7".to_string(),
            name: "User One".to_string(),
        };
        user_cache
            .store(dummy_user.clone())
            .expect("Failed storing user in cache");

        let dummy_user2 = UserEntry {
            upn: "user2@test.com".to_string(),
            uuid: "7be6c0c5-5763-4633-aecf-f8c460b338fd".to_string(),
            name: "User Two".to_string(),
        };
        user_cache
            .store(dummy_user2.clone())
            .expect("Failed storing user in cache");

        // Initialize the Idmap with dummy configuration
        let realm = "test.com";
        let tenant_id = "89a61bb7-d1b9-4356-a1e0-75d88e06f14e";
        let mut idmap = Idmap::new().unwrap();
        idmap
            .add_gen_domain(realm, tenant_id, (1000, 2000))
            .unwrap();

        // Initialize dummy configuration for LoadParm
        let lp = LoadParm::new(None).expect("Failed loading default config");

        // Initialize the Resolver
        let mut resolver = Resolver {
            realm: realm.to_string(),
            tenant_id: tenant_id.to_string(),
            lp,
            idmap,
            pcache,
            user_cache,
            uid_cache,
            group_cache,
        };

        // Test the getpwent function
        let result = resolver.getpwent().await.unwrap();

        match result {
            Response::NssAccounts(accounts) => {
                assert_eq!(accounts.len(), 2);

                let account1 = &accounts[0];
                assert_eq!(account1.name, dummy_user.upn);
                assert_eq!(account1.uid, 1316);
                assert_eq!(account1.gid, 1316);
                assert_eq!(account1.gecos, dummy_user.name);
                assert_eq!(account1.dir, "/home/test.com/user1");
                assert_eq!(account1.shell, "/bin/false");

                let account2 = &accounts[1];
                assert_eq!(account2.name, dummy_user2.upn);
                assert_eq!(account2.uid, 1671);
                assert_eq!(account2.gid, 1671);
                assert_eq!(account2.gecos, dummy_user2.name);
                assert_eq!(account2.dir, "/home/test.com/user2");
                assert_eq!(account2.shell, "/bin/false");
            }
            other => panic!(
                "Expected NssAccounts with a list of accounts: {:?}",
                other
            ),
        }
    }
}
