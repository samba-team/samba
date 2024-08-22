/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon common utilities

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
use dbg::{DBG_ERR, DBG_INFO};
use kanidm_hsm_crypto::AuthValue;
use ntstatus_gen::*;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub fn split_username(
    username: &str,
) -> Result<(String, String), Box<NTSTATUS>> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Ok((tup[0].to_string(), tup[1].to_string()));
    }
    Err(Box::new(NT_STATUS_INVALID_USER_PRINCIPAL_NAME))
}

pub(crate) async fn hsm_pin_fetch_or_create(
    hsm_pin_path: &str,
) -> Result<AuthValue, Box<NTSTATUS>> {
    let auth_value = if !PathBuf::from_str(hsm_pin_path)
        .map_err(|e| {
            DBG_ERR!("Failed to create hsm pin: {:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })?
        .exists()
    {
        let auth_value = AuthValue::generate().map_err(|e| {
            DBG_ERR!("Failed to create hsm pin: {:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })?;
        std::fs::write(hsm_pin_path, auth_value.clone()).map_err(|e| {
            DBG_ERR!("Failed to write hsm pin: {:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })?;

        DBG_INFO!("Generated new HSM pin");
        auth_value
    } else {
        let mut file = File::open(hsm_pin_path).await.map_err(|e| {
            DBG_ERR!("Failed to read hsm pin: {:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })?;
        let mut auth_value = vec![];
        file.read_to_end(&mut auth_value).await.map_err(|e| {
            DBG_ERR!("Failed to read hsm pin: {:?}", e);
            Box::new(NT_STATUS_UNSUCCESSFUL)
        })?;
        std::str::from_utf8(&auth_value)
            .map_err(|e| {
                DBG_ERR!("Failed to read hsm pin: {:?}", e);
                Box::new(NT_STATUS_UNSUCCESSFUL)
            })?
            .to_string()
    };
    AuthValue::try_from(auth_value.as_bytes()).map_err(|e| {
        DBG_ERR!("Invalid hsm pin: {:?}", e);
        Box::new(NT_STATUS_UNSUCCESSFUL)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use tokio::fs;

    #[test]
    fn test_split_username_success() {
        let username = "user@domain.com";
        let result = split_username(username);
        assert!(result.is_ok());
        let (user, domain) = result.unwrap();
        assert_eq!(user, "user");
        assert_eq!(domain, "domain.com");
    }

    #[test]
    fn test_split_username_failure() {
        let username = "invalid_username";
        let result = split_username(username);
        assert!(result.is_err());
        assert_eq!(*result.unwrap_err(), NT_STATUS_INVALID_USER_PRINCIPAL_NAME);
    }

    #[tokio::test]
    async fn test_hsm_pin_fetch_or_create_generate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hsm_pin");

        let result = hsm_pin_fetch_or_create(path.to_str().unwrap()).await;
        assert!(result.is_ok());

        // Verify that the file is created and contains a valid auth value
        let saved_pin = fs::read(path).await.expect("Auth value missing");
        AuthValue::try_from(saved_pin.as_slice())
            .expect("Failed parsing auth value");
    }

    #[tokio::test]
    async fn test_hsm_pin_fetch_or_create_invalid_path() {
        let result = hsm_pin_fetch_or_create("invalid_path\0").await;
        assert!(result.is_err());
        match result {
            Err(e) => assert_eq!(*e, NT_STATUS_UNSUCCESSFUL),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_hsm_pin_fetch_or_create_invalid_auth_value() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hsm_pin");

        // Write invalid content to the file
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"invalid_auth_value").unwrap();

        // Test reading the invalid file
        let result = hsm_pin_fetch_or_create(path.to_str().unwrap()).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert_eq!(*e, NT_STATUS_UNSUCCESSFUL),
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}
