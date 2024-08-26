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
use crate::cache::GroupEntry;
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
        let uid =
            self.idmap.gen_to_unix(&self.tenant_id, &upn).map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_INVALID_TOKEN)
            })?;
        // Store the calculated uid -> upn map in the cache
        self.uid_cache.store(uid, &upn)?;
        // Store the primary group (which is a fake group matching the user upn)
        let mut group = GroupEntry::new(upn);
        group.add_member(upn);
        self.group_cache.merge_groups(upn, vec![group])?;
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
            #[cfg(not(test))]
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
            #[cfg(test)]
            None => return Ok(Response::NssAccount(None)),
        };
        return Ok(Response::NssAccount(Some(
            self.create_passwd_from_upn(&entry.upn, &entry.name)?,
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::UserEntry;
    use crate::{GroupCache, PrivateCache, UidCache, UserCache};
    use idmap::Idmap;
    use param::LoadParm;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_getpwnam() {
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

        // Insert a dummy UserEntry into the cache
        let dummy_user = UserEntry {
            upn: "user1@test.com".to_string(),
            uuid: "731e9af3-668d-4033-afd1-9f09b9120cc7".to_string(),
            name: "User One".to_string(),
        };
        let _ = user_cache.store(dummy_user.clone());

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

        // Test the getpwnam function with a user that exists in the cache
        let result = resolver.getpwnam(&dummy_user.upn).await.unwrap();

        match result {
            Response::NssAccount(Some(account)) => {
                assert_eq!(account.name, dummy_user.upn);
                assert_eq!(account.uid, 1316);
                assert_eq!(account.gid, 1316);
                assert_eq!(account.gecos, dummy_user.name);
                assert_eq!(account.dir, "/home/test.com/user1");
                assert_eq!(account.shell, "/bin/false");
            }
            other => {
                panic!("Expected NssAccount with Some(account): {:?}", other)
            }
        }

        // Test the getpwnam function with a user that does not exist in the cache
        let nonexistent_user_upn = "nonexistent@test.com";
        let result = resolver.getpwnam(nonexistent_user_upn).await.unwrap();

        match result {
            Response::NssAccount(None) => {} // This is the expected result
            other => panic!("Expected NssAccount with None: {:?}", other),
        }
    }
}
