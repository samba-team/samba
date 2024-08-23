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

use dbg::DBG_ERR;
use ntstatus_gen::*;
use param::LoadParm;
use serde_json::{from_slice as json_from_slice, to_vec as json_to_vec};
use std::error::Error;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct ClientStream {
    stream: UnixStream,
}

impl ClientStream {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(ClientStream {
            stream: UnixStream::connect(path)
                .map_err(|e| {
                    DBG_ERR!("Unix socket stream setup error while connecting to {}: {:?}",
                        path, e
                    );
                    e
                })?,
        })
    }

    pub fn send(
        &mut self,
        req: &Request,
        timeout: u64,
    ) -> Result<Response, Box<dyn Error>> {
        // Set the timeout
        let timeout = Duration::from_secs(timeout);
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;

        // Encode the request as bytes
        let req_bytes = json_to_vec(req)?;

        // Send the request
        self.stream.write_all(&req_bytes)?;

        // Now wait on the response
        let start = SystemTime::now();
        let mut read_started = false;
        let mut data = Vec::with_capacity(1024);
        let mut counter = 0;

        loop {
            let mut buffer = [0; 1024];
            let durr =
                SystemTime::now().duration_since(start).map_err(Box::new)?;
            if durr > timeout {
                DBG_ERR!("Socket timeout");
                break;
            }
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if read_started {
                        break;
                    } else {
                        continue;
                    }
                }
                Ok(count) => {
                    data.extend_from_slice(&buffer);
                    counter += count;
                    if count == 1024 {
                        read_started = true;
                        continue;
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    DBG_ERR!(
                        "Stream read failure from {:?}: {:?}",
                        &self.stream,
                        e
                    );
                    return Err(Box::new(e));
                }
            }
        }

        data.truncate(counter);

        // Now decode the response
        let resp: Response = json_from_slice(data.as_slice())?;
        Ok(resp)
    }
}

pub fn stream_and_timeout(
    lp: &LoadParm,
) -> Result<(ClientStream, u64), Box<NTSTATUS>> {
    // Get the socket path
    let sock_dir_str = lp
        .winbindd_socket_directory()
        .map_err(|_| Box::new(NT_STATUS_NOT_FOUND))?
        .ok_or(Box::new(NT_STATUS_NOT_FOUND))?;
    let sock_dir = Path::new(&sock_dir_str);
    let mut sock_path = PathBuf::from(sock_dir);
    sock_path.push("hb_pipe");
    let sock_path = sock_path.to_str().ok_or(Box::new(NT_STATUS_NOT_FOUND))?;

    // Open the socket
    let timeout: u64 = lp
        .winbind_request_timeout()
        .map_err(|_| Box::new(NT_STATUS_NOT_FOUND))?
        .try_into()
        .map_err(|_| Box::new(NT_STATUS_NOT_FOUND))?;
    let stream = ClientStream::new(sock_path)
        .map_err(|_| Box::new(NT_STATUS_PIPE_NOT_AVAILABLE))?;
    Ok((stream, timeout))
}
