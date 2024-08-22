/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon cache

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
use dbg::DBG_ERR;
use himmelblau::error::MsalError;
use himmelblau::graph::DirectoryObject;
use himmelblau::UserToken;
use kanidm_hsm_crypto::{
    AuthValue, BoxedDynTpm, LoadableIdentityKey, LoadableMachineKey,
    LoadableMsOapxbcRsaKey, Tpm,
};
use libc::uid_t;
use ntstatus_gen::*;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice as json_from_slice, to_vec as json_to_vec};
use std::collections::HashSet;
use tdb::Tdb;

struct BasicCache {
    tdb: Tdb,
}

impl BasicCache {
    fn new(cache_path: &str) -> Result<Self, Box<NTSTATUS>> {
        let tdb =
            Tdb::open(cache_path, None, None, None, None).map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_FILE_INVALID)
            })?;
        Ok(BasicCache { tdb })
    }

    fn fetch_str(&self, key: &str) -> Option<String> {
        let key = key.to_string().to_lowercase();
        let exists = match self.tdb.exists(&key) {
            Ok(exists) => exists,
            Err(e) => {
                DBG_ERR!("Failed to fetch {}: {:?}", key, e);
                false
            }
        };
        if exists {
            match self.tdb.fetch(&key) {
                Ok(val) => Some(val),
                Err(e) => {
                    DBG_ERR!("Failed to fetch {}: {:?}", key, e);
                    None
                }
            }
        } else {
            None
        }
    }

    fn fetch<'a, T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = key.to_string().to_lowercase();
        match self.fetch_str(&key) {
            Some(val) => match json_from_slice::<T>(val.as_bytes()) {
                Ok(res) => Some(res),
                Err(e) => {
                    DBG_ERR!("Failed to decode {}: {:?}", key, e);
                    None
                }
            },
            None => {
                return None;
            }
        }
    }

    fn store_bytes(
        &mut self,
        key: &str,
        val: &[u8],
    ) -> Result<(), Box<NTSTATUS>> {
        let key = key.to_string().to_lowercase();
        match self.tdb.transaction_start() {
            Ok(start) => {
                if !start {
                    DBG_ERR!("Failed to start the database transaction.");
                    return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                }
            }
            Err(e) => {
                DBG_ERR!("Failed to start the database transaction: {:?}", e);
                return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
            }
        };

        let res = match self.tdb.store(&key, val, None) {
            Ok(res) => Some(res),
            Err(e) => {
                DBG_ERR!("Unable to persist {}: {:?}", key, e);
                None
            }
        };

        let res = match res {
            Some(res) => res,
            None => {
                let _ = self.tdb.transaction_cancel();
                return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
            }
        };
        if !res {
            DBG_ERR!("Unable to persist {}", key);
            let _ = self.tdb.transaction_cancel();
            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
        }

        let success = match self.tdb.transaction_commit() {
            Ok(success) => success,
            Err(e) => {
                DBG_ERR!("Failed to commit the database transaction: {:?}", e);
                return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
            }
        };
        if !success {
            DBG_ERR!("Failed to commit the database transaction.");
            let _ = self.tdb.transaction_cancel();
            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
        }

        Ok(())
    }

    fn store<T>(&mut self, key: &str, val: T) -> Result<(), Box<NTSTATUS>>
    where
        T: Serialize,
    {
        let key = key.to_string().to_lowercase();
        let val_bytes = match json_to_vec(&val) {
            Ok(val_bytes) => val_bytes,
            Err(e) => {
                DBG_ERR!("Unable to serialize {}: {:?}", key, e);
                return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
            }
        };
        self.store_bytes(&key, &val_bytes)
    }

    fn keys(&self) -> Result<Vec<String>, Box<NTSTATUS>> {
        self.tdb.keys().map_err(|e| {
            DBG_ERR!("{:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct UserEntry {
    pub(crate) upn: String,
    pub(crate) uuid: String,
    pub(crate) name: String,
}

impl TryFrom<&UserToken> for UserEntry {
    type Error = MsalError;

    fn try_from(token: &UserToken) -> Result<Self, Self::Error> {
        Ok(UserEntry {
            upn: token.spn()?,
            uuid: token.uuid()?.to_string(),
            name: token.id_token.name.clone(),
        })
    }
}

pub(crate) struct UserCache {
    cache: BasicCache,
}

impl UserCache {
    pub(crate) fn new(cache_path: &str) -> Result<Self, Box<NTSTATUS>> {
        Ok(UserCache {
            cache: BasicCache::new(cache_path)?,
        })
    }

    pub(crate) fn fetch(&mut self, upn: &str) -> Option<UserEntry> {
        self.cache.fetch::<UserEntry>(upn)
    }

    pub(crate) fn fetch_all(
        &mut self,
    ) -> Result<Vec<UserEntry>, Box<NTSTATUS>> {
        let keys = self.cache.keys()?;
        let mut res = Vec::new();
        for upn in keys {
            let entry = match self.cache.fetch::<UserEntry>(&upn) {
                Some(entry) => entry,
                None => {
                    DBG_ERR!("Unable to fetch user {}", upn);
                    return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                }
            };
            res.push(entry);
        }
        Ok(res)
    }

    pub(crate) fn store(
        &mut self,
        entry: UserEntry,
    ) -> Result<(), Box<NTSTATUS>> {
        let key = entry.upn.clone();
        self.cache.store::<UserEntry>(&key, entry)
    }
}

pub(crate) struct UidCache {
    cache: BasicCache,
}

impl UidCache {
    pub(crate) fn new(cache_path: &str) -> Result<Self, Box<NTSTATUS>> {
        Ok(UidCache {
            cache: BasicCache::new(cache_path)?,
        })
    }

    pub(crate) fn store(
        &mut self,
        uid: uid_t,
        upn: &str,
    ) -> Result<(), Box<NTSTATUS>> {
        let key = format!("{}", uid);
        let upn = upn.to_string().to_lowercase();
        self.cache.store_bytes(&key, upn.as_bytes())
    }

    pub(crate) fn fetch(&mut self, uid: uid_t) -> Option<String> {
        let key = format!("{}", uid);
        self.cache.fetch_str(&key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupEntry {
    pub(crate) uuid: String,
    members: HashSet<String>,
}

impl From<DirectoryObject> for GroupEntry {
    fn from(obj: DirectoryObject) -> Self {
        GroupEntry {
            uuid: obj.id.clone(),
            members: HashSet::new(),
        }
    }
}

impl GroupEntry {
    pub(crate) fn add_member(&mut self, member: &str) {
        // Only ever use lowercase names, otherwise the group
        // memberships will have duplicates.
        self.members.insert(member.to_lowercase());
    }

    pub(crate) fn remove_member(&mut self, member: &str) {
        // Only ever use lowercase names, otherwise the group
        // memberships will have duplicates.
        self.members.remove(&member.to_lowercase());
    }

    pub(crate) fn into_with_member(obj: DirectoryObject, member: &str) -> Self {
        let mut g: GroupEntry = obj.into();
        g.add_member(member);
        g
    }

    pub(crate) fn members(&self) -> Vec<String> {
        self.members.clone().into_iter().collect::<Vec<String>>()
    }
}

#[cfg(test)]
impl GroupEntry {
    pub fn new(uuid: &str) -> Self {
        GroupEntry {
            uuid: uuid.to_string(),
            members: HashSet::new(),
        }
    }
}

pub(crate) struct GroupCache {
    cache: BasicCache,
}

impl GroupCache {
    pub(crate) fn new(cache_path: &str) -> Result<Self, Box<NTSTATUS>> {
        Ok(GroupCache {
            cache: BasicCache::new(cache_path)?,
        })
    }

    pub(crate) fn fetch(&mut self, uuid: &str) -> Option<GroupEntry> {
        self.cache.fetch::<GroupEntry>(uuid)
    }

    pub(crate) fn fetch_all(
        &mut self,
    ) -> Result<Vec<GroupEntry>, Box<NTSTATUS>> {
        let keys = self.cache.keys()?;
        let mut res = Vec::new();
        for uuid in keys {
            let entry = match self.cache.fetch::<GroupEntry>(&uuid) {
                Some(entry) => entry,
                None => {
                    DBG_ERR!("Unable to fetch group {}", uuid);
                    return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                }
            };
            res.push(entry);
        }
        Ok(res)
    }

    pub(crate) fn merge_groups(
        &mut self,
        member: &str,
        mut entries: Vec<GroupEntry>,
    ) -> Result<(), Box<NTSTATUS>> {
        // We need to ensure the member is removed from non-intersecting
        // groups, otherwise we don't honor group membership removals.
        let group_uuids: HashSet<String> = entries
            .clone()
            .into_iter()
            .map(|g| g.uuid.clone())
            .collect();
        let existing_group_uuids = {
            let cache = &self.cache;
            match cache.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    DBG_ERR!("Unable to fetch groups: {:?}", e);
                    return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                }
            }
        };
        let existing_group_uuids: HashSet<String> =
            existing_group_uuids.into_iter().collect();
        let difference: HashSet<String> = existing_group_uuids
            .difference(&group_uuids)
            .cloned()
            .collect();
        for group_uuid in &difference {
            if let Some(mut group) =
                self.cache.fetch::<GroupEntry>(&group_uuid).clone()
            {
                group.remove_member(member);
                if let Err(e) =
                    self.cache.store::<GroupEntry>(&group.uuid.clone(), group)
                {
                    DBG_ERR!("Unable to store membership change: {:?}", e);
                    return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                }
            }
        }

        // Ensure the member is added to the listed groups
        for group in &mut entries {
            group.add_member(member);
        }

        // Now add the new entries, merging with existing memberships
        for group in entries {
            match self.cache.fetch::<GroupEntry>(&group.uuid) {
                Some(mut existing_group) => {
                    // Merge with an existing entry
                    existing_group.add_member(member);
                    if let Err(e) = self.cache.store::<GroupEntry>(
                        &existing_group.uuid.clone(),
                        existing_group,
                    ) {
                        DBG_ERR!("Unable to store membership change: {:?}", e);
                        return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                    }
                }
                None => {
                    if let Err(e) = self
                        .cache
                        .store::<GroupEntry>(&group.uuid.clone(), group)
                    {
                        DBG_ERR!("Unable to store membership change: {:?}", e);
                        return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct PrivateCache {
    cache: BasicCache,
}

impl PrivateCache {
    pub(crate) fn new(cache_path: &str) -> Result<Self, Box<NTSTATUS>> {
        Ok(PrivateCache {
            cache: BasicCache::new(cache_path)?,
        })
    }

    pub(crate) fn loadable_machine_key_fetch_or_create(
        &mut self,
        hsm: &mut BoxedDynTpm,
        auth_value: &AuthValue,
    ) -> Result<LoadableMachineKey, Box<NTSTATUS>> {
        match self
            .cache
            .fetch::<LoadableMachineKey>("loadable_machine_key")
        {
            Some(loadable_machine_key) => Ok(loadable_machine_key),
            None => {
                // No machine key found - create one, and store it.
                let loadable_machine_key =
                    match hsm.machine_key_create(&auth_value) {
                        Ok(loadable_machine_key) => loadable_machine_key,
                        Err(e) => {
                            DBG_ERR!(
                                "Unable to create hsm loadable \
                                machine key: {:?}",
                                e
                            );
                            return Err(Box::new(NT_STATUS_UNSUCCESSFUL));
                        }
                    };

                self.cache.store::<LoadableMachineKey>(
                    "loadable_machine_key",
                    loadable_machine_key.clone(),
                )?;

                Ok(loadable_machine_key)
            }
        }
    }

    pub(crate) fn loadable_transport_key_fetch(
        &mut self,
        realm: &str,
    ) -> Option<LoadableMsOapxbcRsaKey> {
        let transport_key_tag = format!("{}/transport", realm);
        self.cache
            .fetch::<LoadableMsOapxbcRsaKey>(&transport_key_tag)
    }

    pub(crate) fn loadable_cert_key_fetch(
        &mut self,
        realm: &str,
    ) -> Option<LoadableIdentityKey> {
        let cert_key_tag = format!("{}/certificate", realm);
        self.cache.fetch::<LoadableIdentityKey>(&cert_key_tag)
    }

    pub(crate) fn loadable_hello_key_fetch(
        &mut self,
        account_id: &str,
    ) -> Option<LoadableIdentityKey> {
        let hello_key_tag = format!("{}/hello", account_id);
        self.cache.fetch::<LoadableIdentityKey>(&hello_key_tag)
    }

    pub(crate) fn loadable_cert_key_store(
        &mut self,
        realm: &str,
        cert_key: LoadableIdentityKey,
    ) -> Result<(), Box<NTSTATUS>> {
        let cert_key_tag = format!("{}/certificate", realm);
        self.cache
            .store::<LoadableIdentityKey>(&cert_key_tag, cert_key)
    }

    pub(crate) fn loadable_hello_key_store(
        &mut self,
        account_id: &str,
        hello_key: LoadableIdentityKey,
    ) -> Result<(), Box<NTSTATUS>> {
        let hello_key_tag = format!("{}/hello", account_id);
        self.cache
            .store::<LoadableIdentityKey>(&hello_key_tag, hello_key)
    }

    pub(crate) fn loadable_transport_key_store(
        &mut self,
        realm: &str,
        transport_key: LoadableMsOapxbcRsaKey,
    ) -> Result<(), Box<NTSTATUS>> {
        let transport_key_tag = format!("{}/transport", realm);
        self.cache
            .store::<LoadableMsOapxbcRsaKey>(&transport_key_tag, transport_key)
    }

    pub(crate) fn device_id(&mut self, realm: &str) -> Option<String> {
        let device_id_tag = format!("{}/device_id", realm);
        self.cache.fetch_str(&device_id_tag)
    }

    pub(crate) fn device_id_store(
        &mut self,
        realm: &str,
        device_id: &str,
    ) -> Result<(), Box<NTSTATUS>> {
        let device_id_tag = format!("{}/device_id", realm);
        self.cache.store_bytes(&device_id_tag, device_id.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanidm_hsm_crypto::soft::SoftTpm;
    use std::str::FromStr;
    use tempfile::tempdir;

    #[test]
    fn test_basic_cache_new() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let cache = BasicCache::new(cache_path.to_str().unwrap());
        assert!(cache.is_ok());
    }

    #[test]
    fn test_basic_cache_store_fetch_str() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache = BasicCache::new(cache_path.to_str().unwrap()).unwrap();

        let key = "test_key";
        let value = "test_value";
        cache.store_bytes(key, value.as_bytes()).unwrap();
        let fetched_value = cache.fetch_str(key).unwrap();
        assert_eq!(fetched_value, value);
    }

    #[test]
    fn test_basic_cache_store_fetch() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache = BasicCache::new(cache_path.to_str().unwrap()).unwrap();

        let key = "test_key";
        let value = UserEntry {
            upn: "user@test.com".to_string(),
            uuid: "f63a43c7-b783-4da9-acb4-89f8ebfc49e9".to_string(),
            name: "Test User".to_string(),
        };

        cache.store(key, &value).unwrap();
        let fetched_value: Option<UserEntry> = cache.fetch(key);
        assert!(fetched_value.is_some());
        let fetched_value = fetched_value.unwrap();
        assert_eq!(fetched_value.upn, value.upn);
        assert_eq!(fetched_value.uuid, value.uuid);
        assert_eq!(fetched_value.name, value.name);
    }

    #[test]
    fn test_user_cache_store_fetch() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache = UserCache::new(cache_path.to_str().unwrap()).unwrap();

        let entry = UserEntry {
            upn: "user@test.com".to_string(),
            uuid: "f63a43c7-b783-4da9-acb4-89f8ebfc49e9".to_string(),
            name: "Test User".to_string(),
        };

        cache.store(entry.clone()).unwrap();
        let fetched_entry = cache.fetch(&entry.upn);
        assert!(fetched_entry.is_some());
        let fetched_entry = fetched_entry.unwrap();
        assert_eq!(fetched_entry.upn, entry.upn);
        assert_eq!(fetched_entry.uuid, entry.uuid);
        assert_eq!(fetched_entry.name, entry.name);
    }

    #[test]
    fn test_uid_cache_store_fetch() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache = UidCache::new(cache_path.to_str().unwrap()).unwrap();

        let uid: uid_t = 1000;
        let upn = "user@test.com";

        cache.store(uid, upn).unwrap();
        let fetched_upn = cache.fetch(uid);
        assert!(fetched_upn.is_some());
        assert_eq!(fetched_upn.unwrap(), upn);
    }

    #[test]
    fn test_group_cache_store_fetch() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache = GroupCache::new(cache_path.to_str().unwrap()).unwrap();

        let mut group = GroupEntry {
            uuid: "5f8be63a-a379-4324-9f42-9ea40bed9d7f".to_string(),
            members: HashSet::new(),
        };
        group.add_member("user@test.com");

        cache.cache.store(&group.uuid, &group).unwrap();
        let fetched_group = cache.fetch(&group.uuid);
        assert!(fetched_group.is_some());
        let fetched_group = fetched_group.unwrap();
        assert_eq!(fetched_group.uuid, group.uuid);
        assert!(fetched_group.members.contains("user@test.com"));
    }

    #[test]
    fn test_private_cache_loadable_machine_key_fetch_or_create() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test.tdb");
        let mut cache =
            PrivateCache::new(cache_path.to_str().unwrap()).unwrap();

        let mut hsm = BoxedDynTpm::new(SoftTpm::new());
        let auth_str = AuthValue::generate().expect("Failed to create hex pin");
        let auth_value = AuthValue::from_str(&auth_str)
            .expect("Unable to create auth value");

        let result =
            cache.loadable_machine_key_fetch_or_create(&mut hsm, &auth_value);
        assert!(result.is_ok());

        let fetched_key = cache
            .cache
            .fetch::<LoadableMachineKey>("loadable_machine_key");
        assert!(fetched_key.is_some());
    }
}
