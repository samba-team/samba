/*
   Unix SMB/CIFS implementation.

   NSS module for the Himmelblau daemon

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

#[macro_use]
extern crate libnss;

use libnss::group::{Group as NssGroup, GroupHooks};
use libnss::interop::Response as NssResponse;
use libnss::passwd::{Passwd as NssPasswd, PasswdHooks};
use param::LoadParm;
use sock::{stream_and_timeout, Group, Passwd, Request, Response};

struct HimmelblauPasswd;
libnss_passwd_hooks!(himmelblau, HimmelblauPasswd);

impl PasswdHooks for HimmelblauPasswd {
    fn get_all_entries() -> NssResponse<Vec<NssPasswd>> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssAccounts;
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssAccounts(l) => {
                    l.into_iter().map(|passwd| passwd.into()).collect()
                }
                _ => vec![],
            })
            .map(NssResponse::Success)
            .unwrap_or_else(|_| NssResponse::Success(vec![]))
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> NssResponse<NssPasswd> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssAccountByUid(uid);
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssAccount(passwd) => passwd
                    .map(nsspasswd_from_passwd)
                    .map(NssResponse::Success)
                    .unwrap_or_else(|| NssResponse::NotFound),
                _ => NssResponse::NotFound,
            })
            .unwrap_or_else(|_| NssResponse::NotFound)
    }

    fn get_entry_by_name(name: String) -> NssResponse<NssPasswd> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssAccountByName(name);
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssAccount(passwd) => passwd
                    .map(nsspasswd_from_passwd)
                    .map(NssResponse::Success)
                    .unwrap_or_else(|| NssResponse::NotFound),
                _ => NssResponse::NotFound,
            })
            .unwrap_or_else(|_| NssResponse::NotFound)
    }
}

struct HimmelblauGroup;
libnss_group_hooks!(himmelblau, HimmelblauGroup);

impl GroupHooks for HimmelblauGroup {
    fn get_all_entries() -> NssResponse<Vec<NssGroup>> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssGroups;
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssGroups(l) => {
                    l.into_iter().map(|group| group.into()).collect()
                }
                _ => vec![],
            })
            .map(NssResponse::Success)
            .unwrap_or_else(|_| NssResponse::Success(vec![]))
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> NssResponse<NssGroup> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssGroupByGid(gid);
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssGroup(group) => group
                    .map(nssgroup_from_group)
                    .map(NssResponse::Success)
                    .unwrap_or_else(|| NssResponse::NotFound),
                _ => NssResponse::NotFound,
            })
            .unwrap_or_else(|_| NssResponse::NotFound)
    }

    fn get_entry_by_name(name: String) -> NssResponse<NssGroup> {
        let lp = match LoadParm::new(None) {
            Ok(lp) => lp,
            Err(_) => return NssResponse::Unavail,
        };
        let (mut stream, timeout) = match stream_and_timeout(&lp) {
            Ok((stream, timeout)) => (stream, timeout),
            Err(_) => return NssResponse::Unavail,
        };

        let req = Request::NssGroupByName(name);
        stream
            .send(&req, timeout)
            .map(|r| match r {
                Response::NssGroup(group) => group
                    .map(nssgroup_from_group)
                    .map(NssResponse::Success)
                    .unwrap_or_else(|| NssResponse::NotFound),
                _ => NssResponse::NotFound,
            })
            .unwrap_or_else(|_| NssResponse::NotFound)
    }
}

fn nsspasswd_from_passwd(passwd: Passwd) -> NssPasswd {
    passwd.into()
}

fn nssgroup_from_group(group: Group) -> NssGroup {
    group.into()
}
