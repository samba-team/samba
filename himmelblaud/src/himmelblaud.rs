/*
   Unix SMB/CIFS implementation.

   Himmelblau daemon

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
use crate::cache::{GroupCache, PrivateCache, UserCache};
use bytes::{BufMut, BytesMut};
use dbg::{DBG_DEBUG, DBG_ERR};
use futures::{SinkExt, StreamExt};
use himmelblau::graph::Graph;
use himmelblau::BrokerClientApplication;
use idmap::Idmap;
use kanidm_hsm_crypto::{BoxedDynTpm, MachineKey};
use param::LoadParm;
use sock::{Request, Response};
use std::error::Error;
use std::io;
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, Framed};

pub(crate) struct Resolver {
    realm: String,
    tenant_id: String,
    lp: LoadParm,
    idmap: Idmap,
    graph: Graph,
    pcache: PrivateCache,
    user_cache: UserCache,
    group_cache: GroupCache,
    hsm: Mutex<BoxedDynTpm>,
    machine_key: MachineKey,
    client: Arc<Mutex<BrokerClientApplication>>,
}

impl Resolver {
    pub(crate) fn new(
        realm: &str,
        tenant_id: &str,
        lp: LoadParm,
        idmap: Idmap,
        graph: Graph,
        pcache: PrivateCache,
        user_cache: UserCache,
        group_cache: GroupCache,
        hsm: BoxedDynTpm,
        machine_key: MachineKey,
        client: BrokerClientApplication,
    ) -> Self {
        Resolver {
            realm: realm.to_string(),
            tenant_id: tenant_id.to_string(),
            lp,
            idmap,
            graph,
            pcache,
            user_cache,
            group_cache,
            hsm: Mutex::new(hsm),
            machine_key,
            client: Arc::new(Mutex::new(client)),
        }
    }
}

struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = Request;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<Request>(src) {
            Ok(msg) => {
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<Response> for ClientCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: Response,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        DBG_DEBUG!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            DBG_ERR!("socket encoding error -> {:?}", e);
            io::Error::new(ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

pub(crate) async fn handle_client(
    stream: UnixStream,
    resolver: Arc<Mutex<Resolver>>,
) -> Result<(), Box<dyn Error>> {
    DBG_DEBUG!("Accepted connection");

    let Ok(_ucred) = stream.peer_cred() else {
        return Err(Box::new(IoError::new(
            ErrorKind::Other,
            "Unable to verify peer credentials.",
        )));
    };

    let mut reqs = Framed::new(stream, ClientCodec::new());

    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            _ => todo!(),
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        DBG_DEBUG!("flushed response!");
    }

    DBG_DEBUG!("Disconnecting client ...");
    Ok(())
}
