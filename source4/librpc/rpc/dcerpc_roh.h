/*
   Unix SMB/CIFS implementation.

   [MS-RPCH] - RPC over HTTP

   Copyright (C) 2013 Samuel Cabrero <samuelcabrero@kernevil.me>

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

#ifndef DCERPC_ROH_H_
#define DCERPC_ROH_H_

#include "librpc/gen_ndr/misc.h"

struct tevent_queue;
struct tstream_context;
struct tstream_tls_params;

struct roh_channel {
	/*
	 * The ConnectionTimeout command specifies the desired frequency for
	 * sending keep-alive PDUs (2.2.3.5.3)
	 */
	unsigned int connection_timeout;

	unsigned int sent_bytes;

	struct GUID channel_cookie;

	struct http_conn *http_conn;
};

enum roh_protocol_version {
	ROH_V1,
	ROH_V2,
};

enum roh_connection_state {
	ROH_STATE_OPEN_START,
	ROH_STATE_OUT_CHANNEL_WAIT,
	ROH_STATE_WAIT_A3W,
	ROH_STATE_WAIT_C2,
	ROH_STATE_OPENED,
};

/*
 * protocol_version:	A client node should be capable of using v1 and v2,
 * 			try to use v2 in first place. If it fails, fallback
 *			to v1
 * connection_state:	Tracks the protocol current state
 * connection_cookie:	Identifies the virtual connection among a client, one
 * 			or more inbound proxies, one or more outbound proxies,
 *			and a server
 * association_group_id_cookie:	Used by higher layer protocols to link
 *			multiple virtual connections (2.2.3.1)
 * default_channel_in:
 * default_channel_out:
 * non_default_channel_in:
 * non_default_channel_out:
 */
struct roh_connection {
	enum roh_protocol_version protocol_version;
	enum roh_connection_state connection_state;

	struct GUID connection_cookie;
	struct GUID association_group_id_cookie;

	struct roh_channel *default_channel_in;
	struct roh_channel *non_default_channel_in;

	struct roh_channel *default_channel_out;
	struct roh_channel *non_default_channel_out;

	/* Client role specific fields (3.2.2.1) */
	bool proxy_use;
	uint32_t current_keep_alive_time;
	uint32_t current_keep_alive_interval;

	/* TODO Add timers 3.2.2.2 */
};

/* Command type constants */
#define ROH_CMD_TYPE_RECV_WINDOWS_SIZE	0x00000000	/* Section 2.2.3.5.1 */
#define ROH_CMD_TYPE_FLOW_CONTROL_ACK	0x00000001	/* Section 2.2.3.5.2 */
#define ROH_CMD_TYPE_CONNECTION_TIMEOUT	0x00000002	/* Section 2.2.3.5.3 */
#define ROH_CMD_TYPE_COOKIE		0x00000003	/* Section 2.2.3.5.4 */
#define ROH_CMD_TYPE_CHANNEL_LIFETIME	0x00000004	/* Section 2.2.3.5.5 */
#define ROH_CMD_TYPE_CLIENT_KEEPALIVE	0x00000005	/* Section 2.2.3.5.6 */
#define ROH_CMD_TYPE_VERSION		0x00000006	/* Section 2.2.3.5.7 */
#define ROH_CMD_TYPE_EMPTY		0x00000007	/* Section 2.2.3.5.8 */
#define ROH_CMD_TYPE_PADDING		0x00000008	/* Section 2.2.3.5.9 */
#define ROH_CMD_TYPE_NEGATIVE_ANCE	0x00000009	/* Section 2.2.3.5.10 */
#define ROH_CMD_TYPE_ANCE		0x0000000A	/* Section 2.2.3.5.11 */
#define ROH_CMD_TYPE_CLIENT_ADDRESS	0x0000000B	/* Section 2.2.3.5.12 */
#define ROH_CMD_TYPE_ASSOCIATION_GRP_ID	0x0000000C	/* Section 2.2.3.5.13 */
#define ROH_CMD_TYPE_DESTINATION	0x0000000D	/* Section 2.2.3.5.14 */
#define ROH_CMD_TYPE_PING		0x0000000E	/* Section 2.2.3.5.15 */

#endif /* DCERPC_ROH_H_ */
