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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::UserEntry;
    use crate::{GroupCache, PrivateCache, UidCache, UserCache};
    use idmap::Idmap;
    use param::LoadParm;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_getpwuid() {
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
        let mut uid_cache = UidCache::new(&uid_cache_path).unwrap();
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

        let uid = idmap
            .gen_to_unix(tenant_id, &dummy_user.upn)
            .expect("Failed to generate uid for user");
        // Store the calculated uid -> upn map in the cache
        uid_cache
            .store(uid, &dummy_user.upn)
            .expect("Failed storing generated uid in the cache");

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

        // Test the getpwuid function with a uid that exists in the cache
        let result = resolver.getpwuid(uid).await.unwrap();

        match result {
            Response::NssAccount(Some(account)) => {
                assert_eq!(account.name, dummy_user.upn);
                assert_eq!(account.uid, uid);
                assert_eq!(account.gid, uid);
                assert_eq!(account.gecos, dummy_user.name);
                assert_eq!(account.dir, "/home/test.com/user1");
                assert_eq!(account.shell, "/bin/false");
            }
            other => {
                panic!("Expected NssAccount with Some(account): {:?}", other)
            }
        }

        // Test the getpwuid function with a uid that does not exist in the cache
        let nonexistent_uid = 9999;
        let result = resolver.getpwuid(nonexistent_uid).await.unwrap();

        match result {
            Response::NssAccount(None) => {} // This is the expected result
            other => panic!("Expected NssAccount with None: {:?}", other),
        }
    }
}
