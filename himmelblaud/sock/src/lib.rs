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

mod proto;
pub use proto::*;

use serde_json::{from_slice as json_from_slice, to_vec as json_to_vec};
use std::error::Error;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct ClientStream {
    stream: UnixStream,
}

impl ClientStream {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(ClientStream {
            stream: UnixStream::connect(path)?,
        })
    }

    pub fn send(
        &mut self,
        req: &Request,
        timeout: u64,
    ) -> Result<Response, Box<dyn Error>> {
        let timeout = Duration::from_secs(timeout);
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        let req_bytes = json_to_vec(req)?;
        self.stream.write_all(&req_bytes)?;
        let mut buf = Vec::new();
        self.stream.read_to_end(&mut buf)?;
        let resp: Response = json_from_slice(&buf)?;
        Ok(resp)
    }
}
