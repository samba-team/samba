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
                .gen_to_unix(&self.tenant_id, &entry.uuid)
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
    async fn test_getgrent() {
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

        // Insert dummy GroupEntries into the cache
        let group_uuid1 = "c490c3ea-fd98-4d45-b6aa-2a3520f804fa";
        let group_uuid2 = "f7a51b58-84de-42a3-b5b1-967b17c04f89";
        let dummy_group1 = GroupEntry::new(group_uuid1);
        let dummy_group2 = GroupEntry::new(group_uuid2);
        group_cache
            .merge_groups("user1@test.com", vec![dummy_group1.clone()])
            .unwrap();
        group_cache
            .merge_groups("user2@test.com", vec![dummy_group2.clone()])
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

        // Test the getgrent function
        let result = resolver.getgrent().await.unwrap();

        match result {
            Response::NssGroups(mut groups) => {
                groups.sort_by(|a, b| a.name.cmp(&b.name));
                assert_eq!(groups.len(), 2);

                let group1 = &groups[0];
                assert_eq!(group1.name, dummy_group1.uuid);
                assert_eq!(group1.gid, 1388);
                assert_eq!(group1.members, vec!["user1@test.com".to_string()]);

                let group2 = &groups[1];
                assert_eq!(group2.name, dummy_group2.uuid);
                assert_eq!(group2.gid, 1593);
                assert_eq!(group2.members, vec!["user2@test.com".to_string()]);
            }
            other => {
                panic!("Expected NssGroups with a list of groups: {:?}", other)
            }
        }
    }
}
