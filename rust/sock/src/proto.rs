/*
   Unix SMB/CIFS implementation.

   Unix socket communication for the Himmelblau daemon

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
use libc::uid_t;
use libnss::group::Group as NssGroup;
use libnss::passwd::Passwd as NssPasswd;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Passwd {
    pub name: String,
    pub passwd: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

impl From<Passwd> for NssPasswd {
    fn from(val: Passwd) -> Self {
        NssPasswd {
            name: val.name,
            passwd: val.passwd,
            uid: val.uid,
            gid: val.gid,
            gecos: val.gecos,
            dir: val.dir,
            shell: val.shell,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub passwd: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl From<Group> for NssGroup {
    fn from(val: Group) -> Self {
        NssGroup {
            name: val.name,
            passwd: val.passwd,
            gid: val.gid,
            members: val.members,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum PamAuthRequest {
    Password { cred: String },
    MFACode { cred: String },
    MFAPoll { poll_attempt: u32 },
    SetupPin { pin: String },
    Pin { pin: String },
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    NssAccounts,
    NssAccountByUid(uid_t),
    NssAccountByName(String),
    NssGroups,
    NssGroupByGid(uid_t),
    NssGroupByName(String),
    PamAuthenticateInit(String),
    PamAuthenticateStep(PamAuthRequest),
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PamAuthResponse {
    Unknown,
    Success,
    Denied,
    Password,
    MFACode { msg: String },
    MFAPoll { msg: String, polling_interval: u32 },
    MFAPollWait,
    SetupPin { msg: String },
    Pin,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    NssAccounts(Vec<Passwd>),
    NssAccount(Option<Passwd>),
    NssGroups(Vec<Group>),
    NssGroup(Option<Group>),
    PamStatus(Option<bool>),
    PamAuthStepResponse(PamAuthResponse),
    Success,
    Error,
}
