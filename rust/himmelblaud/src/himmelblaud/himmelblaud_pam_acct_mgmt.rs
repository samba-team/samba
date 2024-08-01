/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon implementation for pam_acct_mgmt

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
use dbg::DBG_WARNING;
use ntstatus_gen::*;
use sock::Response;

impl Resolver {
    pub(crate) async fn pam_acct_mgmt(
        &self,
        account_id: &str,
    ) -> Result<Response, Box<NTSTATUS>> {
        // Check if the user exists in Entra ID
        // TODO: If we're offline, check the cache instead
        match self
            .client
            .lock()
            .await
            .check_user_exists(&account_id)
            .await
        {
            Ok(exists) => Ok(Response::PamStatus(Some(exists))),
            Err(e) => {
                DBG_WARNING!("{:?}", e);
                Ok(Response::PamStatus(None))
            }
        }
    }
}
