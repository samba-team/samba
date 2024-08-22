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
            .gen_to_unix(&self.tenant_id, &entry.uuid)
            .map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_INVALID_TOKEN)
            })?;
        // Store the calculated gid -> uuid map in the cache
        self.uid_cache.store(gid, &entry.uuid)?;
        let group = Group {
            name: entry.uuid.clone(),
            passwd: "x".to_string(),
            gid,
            members: entry.members(),
        };
        return Ok(Response::NssGroup(Some(group)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::GroupEntry;
    use crate::{GroupCache, PrivateCache, UidCache, UserCache};
    use idmap::Idmap;
    use param::LoadParm;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_getgrnam() {
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
        let user_cache = UserCache::new(&user_cache_path).unwrap();
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
        let mut group_cache = GroupCache::new(&group_cache_path).unwrap();

        // Insert a dummy GroupEntry into the cache
        let group_uuid = "c490c3ea-fd98-4d45-b6aa-2a3520f804fa";
        let dummy_group = GroupEntry::new(group_uuid);
        group_cache
            .merge_groups("user1@test.com", vec![dummy_group.clone()])
            .unwrap();
        group_cache
            .merge_groups("user2@test.com", vec![dummy_group.clone()])
            .unwrap();

        // Initialize the Idmap with dummy configuration
        let realm = "test.com";
        let tenant_id = "89a61bb7-d1b9-4356-a1e0-75d88e06f14e";
        let mut idmap = Idmap::new().unwrap();
        idmap
            .add_gen_domain(realm, tenant_id, (1000, 2000))
            .unwrap();

        // Initialize dummy configuration
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

        // Test the getgrnam function with a group that exists
        let result = resolver.getgrnam(group_uuid).await.unwrap();

        match result {
            Response::NssGroup(Some(mut group)) => {
                group.members.sort();
                assert_eq!(group.name, dummy_group.uuid);
                assert_eq!(group.gid, 1388);
                assert_eq!(
                    group.members,
                    vec![
                        "user1@test.com".to_string(),
                        "user2@test.com".to_string()
                    ]
                );
            }
            other => panic!("Expected NssGroup with Some(group): {:?}", other),
        }

        // Test the getgrnam function with a group that does not exist
        let nonexistent_group_uuid = "2ea8f1d4-1b94-4003-865b-cb247a8a1f5d";
        let result = resolver.getgrnam(nonexistent_group_uuid).await.unwrap();
        match result {
            Response::NssGroup(None) => {} // This is the expected result
            _ => panic!("Expected NssGroup with None"),
        }
    }
}
