/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for PAM_AUTH

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
use crate::cache::{GroupEntry, UserEntry};
use crate::himmelblaud::Resolver;
use dbg::{DBG_DEBUG, DBG_ERR, DBG_INFO, DBG_WARNING};
use himmelblau::error::{
    MsalError, AUTH_PENDING, DEVICE_AUTH_FAIL, REQUIRES_MFA,
};
use himmelblau::{
    DeviceAuthorizationResponse, EnrollAttrs, MFAAuthContinue,
    UserToken as UnixUserToken,
};
use ntstatus_gen::*;
use serde::{Deserialize, Serialize};
use sock::{PamAuthRequest, PamAuthResponse, Response};
use std::env;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupToken {
    pub name: String,
    pub spn: String,
    pub object_id: String,
    pub gidnumber: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserToken {
    pub name: String,
    pub spn: String,
    pub object_id: String,
    pub gidnumber: u32,
    pub displayname: String,
    pub shell: Option<String>,
    pub groups: Vec<GroupToken>,
}

pub(crate) enum AuthCredHandler {
    MFA { flow: MFAAuthContinue },
    DeviceAuthorizationGrant { flow: DeviceAuthorizationResponse },
    SetupPin { token: UnixUserToken },
    None,
}

pub(crate) enum AuthSession {
    InProgress {
        account_id: String,
        cred_handler: AuthCredHandler,
    },
    Success,
    Denied,
}

impl Resolver {
    pub(crate) fn pam_auth_init(
        &mut self,
        account_id: &str,
    ) -> Result<(AuthSession, Response), Box<NTSTATUS>> {
        let auth_session = AuthSession::InProgress {
            account_id: account_id.to_string(),
            cred_handler: AuthCredHandler::None,
        };
        let hello_key = self.pcache.loadable_hello_key_fetch(account_id);
        // Skip Hello authentication if it is disabled by config
        let hello_enabled =
            self.lp.himmelblaud_hello_enabled().map_err(|e| {
                DBG_ERR!("{:?}", e);
                Box::new(NT_STATUS_LOGON_FAILURE)
            })?;
        if !self.is_domain_joined() || hello_key.is_none() || !hello_enabled {
            // Send a password request to the client
            Ok((
                auth_session,
                Response::PamAuthStepResponse(PamAuthResponse::Password),
            ))
        } else {
            // Send a pin request to the client
            Ok((
                auth_session,
                Response::PamAuthStepResponse(PamAuthResponse::Pin),
            ))
        }
    }

    pub(crate) async fn pam_auth_step(
        &mut self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
    ) -> Result<Response, Box<NTSTATUS>> {
        macro_rules! enroll_and_obtain_enrolled_token {
            ($token:ident) => {{
                if !self.is_domain_joined() {
                    DBG_DEBUG!("Device is not enrolled. Enrolling now.");
                    self.join_domain(&$token)
                        .await
                        .map_err(|e| {
                            DBG_ERR!("Failed to join domain: {:?}", e);
                            Box::new(NT_STATUS_LOGON_FAILURE)
                        })?;
                }
                let mut tpm = self.hsm.lock().await;
                let mtoken2 = self
                    .client
                    .lock()
                    .await
                    .acquire_token_by_refresh_token(
                        &$token.refresh_token,
                        vec!["User.Read"],
                        Some("https://graph.microsoft.com".to_string()),
                        &mut tpm,
                        &self.machine_key,
                    )
                    .await;
                match mtoken2 {
                    Ok(token) => token,
                    Err(e) => {
                        DBG_ERR!("{:?}", e);
                        match e {
                            MsalError::AcquireTokenFailed(err_resp) => {
                                if err_resp.error_codes.contains(&DEVICE_AUTH_FAIL) {
                                    /* A device authentication failure may happen
                                     * if Azure hasn't finished replicating the new
                                     * device object. Wait 5 seconds and try again. */
                                    DBG_INFO!("Azure hasn't finished replicating the device...");
                                    DBG_INFO!("Retrying in 5 seconds");
                                    sleep(Duration::from_secs(5));
                                    self.client
                                        .lock()
                                        .await
                                        .acquire_token_by_refresh_token(
                                            &$token.refresh_token,
                                            vec!["User.Read"],
                                            Some("https://graph.microsoft.com".to_string()),
                                            &mut tpm,
                                            &self.machine_key,
                                        )
                                        .await
                                        .map_err(|e| {
                                            DBG_ERR!("{:?}", e);
                                            Box::new(NT_STATUS_NOT_FOUND)
                                        })?
                                } else {
                                    return Err(Box::new(NT_STATUS_NOT_FOUND));
                                }
                            }
                            _ => return Err(Box::new(NT_STATUS_NOT_FOUND)),
                        }
                    }
                }
            }};
        }
        macro_rules! auth_and_validate_hello_key {
            ($hello_key:ident, $cred:ident) => {{
                let token = {
                    let mut tpm = self.hsm.lock().await;
                    self
                        .client
                        .lock()
                        .await
                        .acquire_token_by_hello_for_business_key(
                            account_id,
                            &$hello_key,
                            vec!["User.Read"],
                            Some("https://graph.microsoft.com".to_string()),
                            &mut tpm,
                            &self.machine_key,
                            &$cred,
                        )
                        .await
                        .map_err(|e| {
                            DBG_ERR!(
                                "Failed to authenticate with hello key: {:?}",
                                e
                            );
                            Box::new(NT_STATUS_LOGON_FAILURE)
                        })?
                    };

                self.token_validate(account_id, &token).await
            }};
        }
        match (&mut *cred_handler, pam_next_req) {
            (
                AuthCredHandler::SetupPin { token },
                PamAuthRequest::SetupPin { pin },
            ) => {
                let hello_key = {
                    let mut tpm = self.hsm.lock().await;
                    match self
                        .client
                        .lock()
                        .await
                        .provision_hello_for_business_key(
                            &token,
                            &mut tpm,
                            &self.machine_key,
                            &pin,
                        )
                        .await
                    {
                        Ok(hello_key) => hello_key,
                        Err(e) => {
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::SetupPin {
                                    msg: format!(
                                        "Failed to provision hello key: {:?}\n{}",
                                        e,
                                        "Create a PIN to use in place of passwords."
                                    ),
                                }
                            ));
                        }
                    }
                };
                self.pcache
                    .loadable_hello_key_store(account_id, hello_key.clone())
                    .map_err(|e| {
                        DBG_ERR!("Failed to provision hello key: {:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;

                auth_and_validate_hello_key!(hello_key, pin)
            }
            (_, PamAuthRequest::Pin { pin }) => {
                let hello_key = self
                    .pcache
                    .loadable_hello_key_fetch(account_id)
                    .ok_or_else(|| {
                        DBG_ERR!("Authentication failed. Hello key missing.");
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;

                auth_and_validate_hello_key!(hello_key, pin)
            }
            (_, PamAuthRequest::Password { cred }) => {
                // Always attempt to force MFA when enrolling the device, otherwise
                // the device object will not have the MFA claim. If we are already
                // enrolled but creating a new Hello Pin, we follow the same process,
                // since only an enrollment token can be exchanged for a PRT (which
                // will be needed to enroll the Hello Pin).
                let mresp = self
                    .client
                    .lock()
                    .await
                    .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                        account_id, &cred,
                    )
                    .await;
                // We need to wait to handle the response until after we've released
                // the lock on the client, otherwise we will deadlock.
                let resp = match mresp {
                    Ok(resp) => resp,
                    Err(e) => {
                        // If SFA is disabled, we need to skip the SFA fallback.
                        let sfa_enabled = self
                            .lp
                            .himmelblaud_sfa_fallback()
                            .map_err(|e| {
                                DBG_ERR!("{:?}", e);
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        macro_rules! init_dag {
                            ($msg:expr) => {{
                                DBG_WARNING!(
                                    "SFA auth failed, falling back to DAG: {}",
                                    $msg
                                );
                                // We've exhausted alternatives, and must perform a DAG
                                let resp = self
                                    .client
                                    .lock()
                                    .await
                                    .initiate_device_flow_for_device_enrollment()
                                    .await
                                    .map_err(|e| {
                                        DBG_ERR!("{:?}", e);
                                        Box::new(NT_STATUS_LOGON_FAILURE)
                                    })?;
                                let msg = match &resp.message {
                                    Some(msg) => msg.to_string(),
                                    None => format!("Using a browser on another \
                                        device, visit:\n{}\nAnd enter the code:\n{}",
                                        resp.verification_uri, resp.user_code),
                                };
                                let polling_interval = match resp.interval {
                                    Some(polling_interval) => polling_interval,
                                    None => 5,
                                };
                                *cred_handler = AuthCredHandler::DeviceAuthorizationGrant {
                                    flow: resp,
                                };
                                return Ok(Response::PamAuthStepResponse(
                                    PamAuthResponse::MFAPoll {
                                        msg,
                                        polling_interval,
                                    }
                                ));
                            }}
                        }
                        let token = if sfa_enabled {
                            DBG_WARNING!(
                                "MFA auth failed, falling back to SFA: {:?}",
                                e
                            );
                            // Again, we need to wait to handle the response until after
                            // we've released the write lock on the client, otherwise we
                            // will deadlock.
                            match self
                                .client
                                .lock()
                                .await
                                .acquire_token_by_username_password_for_device_enrollment(
                                    account_id, &cred,
                                )
                                .await
                            {
                                Ok(token) => token,
                                Err(e) => {
                                    DBG_ERR!("{:?}", e);
                                    match e {
                                        MsalError::AcquireTokenFailed(
                                            err_resp,
                                        ) => {
                                            if err_resp
                                                .error_codes
                                                .contains(&REQUIRES_MFA)
                                            {
                                                init_dag!(
                                                    err_resp.error_description
                                                );
                                            }
                                            return Err(Box::new(
                                                NT_STATUS_LOGON_FAILURE,
                                            ));
                                        }
                                        _ => {
                                            return Err(Box::new(
                                                NT_STATUS_LOGON_FAILURE,
                                            ))
                                        }
                                    }
                                }
                            }
                        } else {
                            init_dag!(
                                "SFA fallback is disabled by configuration"
                            )
                        };
                        let token2 = enroll_and_obtain_enrolled_token!(token);
                        return self.token_validate(account_id, &token2).await;
                    }
                };
                match resp.mfa_method.as_str() {
                    "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => {
                        let msg = resp.msg.clone();
                        *cred_handler = AuthCredHandler::MFA { flow: resp };
                        return Ok(Response::PamAuthStepResponse(
                            PamAuthResponse::MFACode { msg },
                        ));
                    }
                    _ => {
                        let msg = resp.msg.clone();
                        let polling_interval =
                            resp.polling_interval.ok_or_else(|| {
                                DBG_ERR!("Invalid response from the server");
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        *cred_handler = AuthCredHandler::MFA { flow: resp };
                        return Ok(Response::PamAuthStepResponse(
                            PamAuthResponse::MFAPoll {
                                msg,
                                // pam expects a polling_interval in
                                // seconds, not milliseconds.
                                polling_interval: polling_interval / 1000,
                            },
                        ));
                    }
                }
            }
            (
                AuthCredHandler::DeviceAuthorizationGrant { flow },
                PamAuthRequest::MFAPoll { .. },
            ) => {
                let token = match self
                    .client
                    .lock()
                    .await
                    .acquire_token_by_device_flow(flow.clone())
                    .await
                {
                    Err(MsalError::AcquireTokenFailed(ref resp)) => {
                        if resp.error_codes.contains(&AUTH_PENDING) {
                            DBG_DEBUG!(
                                "Polling for acquire_token_by_device_flow"
                            );
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::MFAPollWait,
                            ));
                        } else {
                            DBG_ERR!("{}", resp.error_description);
                            return Err(Box::new(NT_STATUS_LOGON_FAILURE));
                        }
                    }
                    Err(e) => {
                        DBG_ERR!("{:?}", e);
                        return Err(Box::new(NT_STATUS_LOGON_FAILURE));
                    }
                    Ok(token) => token,
                };
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
                    Ok(Response::PamAuthStepResponse(
                        PamAuthResponse::Success,
                    )) => {
                        let mfa = token2.amr_mfa().map_err(|e| {
                            DBG_ERR!("{:?}", e);
                            Box::new(NT_STATUS_NOT_FOUND)
                        })?;
                        // If the DAG didn't obtain an MFA amr, and SFA fallback
                        // is disabled, we need to reject the authentication
                        // attempt here.
                        let sfa_enabled = self
                            .lp
                            .himmelblaud_sfa_fallback()
                            .map_err(|e| {
                                DBG_ERR!("{:?}", e);
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        if !mfa && !sfa_enabled {
                            DBG_INFO!(
                                "A DAG produced an SFA token, yet SFA \
                                fallback is disabled by configuration"
                            );
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::Denied,
                            ));
                        }
                        // STOP! If the DAG doesn't hold an MFA amr, then we
                        // need to bail out here and refuse Hello enrollment
                        // (we can't enroll in Hello with an SFA token).
                        // Also skip Hello enrollment if it is disabled by config
                        let hello_enabled = self
                            .lp
                            .himmelblaud_hello_enabled()
                            .map_err(|e| {
                                DBG_ERR!("{:?}", e);
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        if !mfa || !hello_enabled {
                            if !mfa {
                                DBG_INFO!(
                                    "Skipping Hello enrollment because \
                                    the token doesn't contain an MFA amr"
                                );
                            } else if !hello_enabled {
                                DBG_INFO!(
                                    "Skipping Hello enrollment \
                                    because it is disabled"
                                );
                            }
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::Success,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok(Response::PamAuthStepResponse(
                            PamAuthResponse::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            },
                        ));
                    }
                    Ok(auth_result) => Ok(auth_result),
                    Err(e) => Err(e),
                }
            }
            (
                AuthCredHandler::MFA { ref mut flow },
                PamAuthRequest::MFACode { cred },
            ) => {
                let token = self
                    .client
                    .lock()
                    .await
                    .acquire_token_by_mfa_flow(
                        account_id,
                        Some(&cred),
                        None,
                        flow,
                    )
                    .await
                    .map_err(|e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_NOT_FOUND)
                    })?;
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
                    Ok(Response::PamAuthStepResponse(
                        PamAuthResponse::Success,
                    )) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self
                            .lp
                            .himmelblaud_hello_enabled()
                            .map_err(|e| {
                                DBG_ERR!("{:?}", e);
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        if !hello_enabled {
                            DBG_INFO!("Skipping Hello enrollment because it is disabled");
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::Success,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok(Response::PamAuthStepResponse(
                            PamAuthResponse::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            },
                        ));
                    }
                    Ok(auth_result) => Ok(auth_result),
                    Err(e) => Err(e),
                }
            }
            (
                AuthCredHandler::MFA { flow },
                PamAuthRequest::MFAPoll { poll_attempt },
            ) => {
                let max_poll_attempts =
                    flow.max_poll_attempts.ok_or_else(|| {
                        DBG_ERR!("Invalid response from the server");
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;
                if poll_attempt > max_poll_attempts {
                    DBG_ERR!("MFA polling timed out");
                    return Err(Box::new(NT_STATUS_LOGON_FAILURE));
                }
                let token = match self
                    .client
                    .lock()
                    .await
                    .acquire_token_by_mfa_flow(
                        account_id,
                        None,
                        Some(poll_attempt),
                        flow,
                    )
                    .await
                {
                    Ok(token) => token,
                    Err(e) => match e {
                        MsalError::MFAPollContinue => {
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::MFAPollWait,
                            ));
                        }
                        e => {
                            DBG_ERR!("{:?}", e);
                            return Err(Box::new(NT_STATUS_NOT_FOUND));
                        }
                    },
                };
                let token2 = enroll_and_obtain_enrolled_token!(token);
                match self.token_validate(account_id, &token2).await {
                    Ok(Response::PamAuthStepResponse(
                        PamAuthResponse::Success,
                    )) => {
                        // Skip Hello enrollment if it is disabled by config
                        let hello_enabled = self
                            .lp
                            .himmelblaud_hello_enabled()
                            .map_err(|e| {
                                DBG_ERR!("{:?}", e);
                                Box::new(NT_STATUS_LOGON_FAILURE)
                            })?;
                        if !hello_enabled {
                            DBG_INFO!("Skipping Hello enrollment because it is disabled");
                            return Ok(Response::PamAuthStepResponse(
                                PamAuthResponse::Success,
                            ));
                        }

                        // Setup Windows Hello
                        *cred_handler = AuthCredHandler::SetupPin { token };
                        return Ok(Response::PamAuthStepResponse(
                            PamAuthResponse::SetupPin {
                                msg: format!(
                                    "Set up a PIN\n {}{}",
                                    "A Hello PIN is a fast, secure way to sign",
                                    "in to your device, apps, and services."
                                ),
                            },
                        ));
                    }
                    Ok(auth_result) => Ok(auth_result),
                    Err(e) => Err(e),
                }
            }
            _ => {
                DBG_ERR!(
                    "Unexpected AuthCredHandler and PamAuthRequest pairing"
                );
                Err(Box::new(NT_STATUS_NOT_IMPLEMENTED))
            }
        }
    }

    async fn token_validate(
        &mut self,
        account_id: &str,
        token: &UnixUserToken,
    ) -> Result<Response, Box<NTSTATUS>> {
        match &token.access_token {
            Some(access_token) => {
                /* MFA can respond with different user than requested.
                 * Azure resource names are case insensitive.
                 */
                let spn = token.spn().map_err(|e| {
                    DBG_ERR!("Failed fetching user spn: {:?}", e);
                    Box::new(NT_STATUS_LOGON_FAILURE)
                })?;
                if account_id.to_string().to_lowercase()
                    != spn.to_string().to_lowercase()
                {
                    DBG_ERR!(
                        "Authenticated user {} does not match requested user {}",
                        spn, account_id
                    );
                    return Ok(Response::PamAuthStepResponse(
                        PamAuthResponse::Denied,
                    ));
                }
                DBG_INFO!(
                    "Authentication successful for user '{}'",
                    account_id
                );

                // Store the user in the cache
                let user_entry: UserEntry = token.try_into().map_err(|e| {
                    DBG_ERR!("{:?}", e);
                    Box::new(NT_STATUS_LOGON_FAILURE)
                })?;
                self.user_cache.store(user_entry).map_err(|e| {
                    DBG_ERR!("{:?}", e);
                    Box::new(NT_STATUS_LOGON_FAILURE)
                })?;

                // Get the users groups, and store those groups in the cache
                let groups: Vec<GroupEntry> = self
                    .graph
                    .request_user_groups(access_token)
                    .await
                    .map_err(|e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?
                    .into_iter()
                    .map(|g| GroupEntry::into_with_member(g, account_id))
                    .collect();
                self.group_cache.merge_groups(account_id, groups).map_err(
                    |e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    },
                )?;

                Ok(Response::PamAuthStepResponse(PamAuthResponse::Success))
            }
            None => {
                DBG_INFO!("Authentication failed for user '{}'", account_id);
                Err(Box::new(NT_STATUS_NOT_FOUND))
            }
        }
    }

    async fn join_domain(
        &mut self,
        token: &UnixUserToken,
    ) -> Result<(), Box<NTSTATUS>> {
        /* If not already joined, join the domain now. */
        let attrs = EnrollAttrs::new(
            self.realm.clone(),
            None,
            Some(env::consts::OS.to_string()),
            None,
            None,
        )
        .map_err(|e| {
            DBG_ERR!("{:?}", e);
            Box::new(NT_STATUS_LOGON_FAILURE)
        })?;
        let mut tpm = self.hsm.lock().await;
        match self
            .client
            .lock()
            .await
            .enroll_device(
                &token.refresh_token,
                attrs,
                &mut tpm,
                &self.machine_key,
            )
            .await
        {
            Ok((
                new_loadable_transport_key,
                new_loadable_cert_key,
                device_id,
            )) => {
                DBG_INFO!("Joined domain {} ({})", self.realm, device_id);
                // Store the new_loadable_cert_key in the keystore
                self.pcache
                    .loadable_cert_key_store(&self.realm, new_loadable_cert_key)
                    .map_err(|e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;
                // Store the new_loadable_transport_key
                self.pcache
                    .loadable_transport_key_store(
                        &self.realm,
                        new_loadable_transport_key,
                    )
                    .map_err(|e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;
                // Store the device_id
                self.pcache
                    .device_id_store(&self.realm, &device_id)
                    .map_err(|e| {
                        DBG_ERR!("{:?}", e);
                        Box::new(NT_STATUS_LOGON_FAILURE)
                    })?;
                Ok(())
            }
            Err(e) => {
                DBG_ERR!("{:?}", e);
                Err(Box::new(NT_STATUS_LOGON_FAILURE))
            }
        }
    }

    fn is_domain_joined(&mut self) -> bool {
        /* If we have access to tpm keys, and the domain device_id is
         * configured, we'll assume we are domain joined. */
        let device_id = self.pcache.device_id(&self.realm);
        if device_id.is_none() {
            return false;
        }
        let transport_key =
            self.pcache.loadable_transport_key_fetch(&self.realm);
        if transport_key.is_none() {
            return false;
        }
        let cert_key = self.pcache.loadable_cert_key_fetch(&self.realm);
        if cert_key.is_none() {
            return false;
        }
        true
    }
}
