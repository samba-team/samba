/*
 * Unix SMB/CIFS implementation.
 *
 * block SMB2 transports using iptables
 *
 * Copyright (C) Guenther Deschner, 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "system/network.h"
#include "lib/util/util_net.h"
#include "torture/smb2/block.h"
#include "libcli/smb/smbXcli_base.h"
#include "lib/util/tevent_ntstatus.h"
#include "oplock_break_handler.h"
#include "lease_break_handler.h"

/*
 * OUTPUT
 *  |
 *  -----> SMBTORTURE_OUTPUT
 *             |
 *             -----> SMBTORTURE_transportname1
 *             -----> SMBTORTURE_transportname2
 */


static bool run_cmd(const char *cmd)
{
	int ret;

	DEBUG(10, ("%s will call '%s'\n", __location__, cmd));

	ret = system(cmd);
	if (ret) {
		DEBUG(1, ("%s failed to execute system call: %s: %d\n",
			__location__, cmd, ret));
		return false;
	}

	return true;
}

static const char *iptables_command(struct torture_context *tctx)
{
	return torture_setting_string(tctx, "iptables_command",
				      "/usr/sbin/iptables");
}

char *escape_shell_string(const char *src);

/*
 * iptables v1.6.1: chain name `SMBTORTURE_INPUT_tree1->session->transport'
 * too long (must be under 29 chars)
 *
 * maybe truncate chainname ?
 */
static const char *samba_chain_name(struct torture_context *tctx,
				    const char *name,
				    const char *prefix)
{
	const char *s;
	char *sm;

	s = talloc_asprintf(tctx, "%s_%s", prefix, name);
	if (s == NULL) {
		return NULL;
	}

	sm = escape_shell_string(s);
	if (sm == NULL) {
		return NULL;
	}

	s = talloc_strdup(tctx, sm);
	free(sm);

	return s;
}

static bool iptables_setup_chain(struct torture_context *tctx,
				 const char *parent_chain,
				 const char *chain,
				 bool unblock)
{
	const char *ipt = iptables_command(tctx);
	const char *cmd;

	if (unblock) {
		cmd = talloc_asprintf(tctx,
				"%s -L %s > /dev/null 2>&1 && "
				"("
				"%s -F %s;"
				"%s -D %s -j %s > /dev/null 2>&1 || true;"
				"%s -X %s;"
				");"
				"%s -L %s > /dev/null 2>&1 || true;",
				ipt, chain,
				ipt, chain,
				ipt, parent_chain, chain,
				ipt, chain,
				ipt, chain);
	} else {
		cmd = talloc_asprintf(tctx,
				"%s -L %s > /dev/null 2>&1 || "
				"("
				"%s -N %s && "
				"%s -I %s -j %s;"
				");"
				"%s -F %s;",
				ipt, chain,
				ipt, chain,
				ipt, parent_chain, chain,
				ipt, chain);
	}

	if (cmd == NULL) {
		return false;
	}

	if (!run_cmd(cmd)) {
		return false;
	}

	return true;
}

uint16_t torture_get_local_port_from_transport(struct smb2_transport *t)
{
	const struct sockaddr_storage *local_ss;

	local_ss = smbXcli_conn_local_sockaddr(t->conn);

	return get_sockaddr_port(local_ss);
}

static bool torture_block_tcp_output_port_internal(
						struct torture_context *tctx,
						const char *name,
						uint16_t port,
						bool unblock)
{
	const char *ipt = iptables_command(tctx);
	const char *chain_out = NULL;
	char *cmd_out = NULL;

	chain_out = samba_chain_name(tctx, name, "SMBTORTURE");
	if (chain_out == NULL) {
		return false;
	}

	torture_comment(tctx, "%sblocking %s dport %d\n",
			unblock ? "un" : "", name, port);

	if (!unblock) {
		bool ok;

		iptables_setup_chain(tctx,
				     "SMBTORTURE_OUTPUT",
				     chain_out,
				     true);
		ok = iptables_setup_chain(tctx,
					  "SMBTORTURE_OUTPUT",
					  chain_out,
					  false);
		if (!ok) {
			return false;
		}
	}

	cmd_out = talloc_asprintf(tctx,
				  "%s %s %s -p tcp --sport %d -j DROP",
				  ipt, unblock ? "-D" : "-I", chain_out, port);
	if (cmd_out == NULL) {
		return false;
	}

	if (!run_cmd(cmd_out)) {
		return false;
	}

	if (unblock) {
		bool ok;

		ok = iptables_setup_chain(tctx,
					  "SMBTORTURE_OUTPUT",
					  chain_out,
					  true);
		if (!ok) {
			return false;
		}
	}

	return true;
}

bool torture_block_tcp_output_port(struct torture_context *tctx,
				   const char *name,
				   uint16_t port)
{
	return torture_block_tcp_output_port_internal(tctx, name, port, false);
}

bool torture_unblock_tcp_output_port(struct torture_context *tctx,
				     const char *name,
				     uint16_t port)
{
	return torture_block_tcp_output_port_internal(tctx, name, port, true);
}

bool torture_block_tcp_output_setup(struct torture_context *tctx)
{
	return iptables_setup_chain(tctx, "OUTPUT", "SMBTORTURE_OUTPUT", false);
}

bool torture_unblock_tcp_output_cleanup(struct torture_context *tctx)
{
	return iptables_setup_chain(tctx, "OUTPUT", "SMBTORTURE_OUTPUT", true);
}

/*
 * Use iptables to block channels
 */
static bool test_block_smb2_transport_iptables(struct torture_context *tctx,
					       struct smb2_transport *transport,
					       const char *name)
{
	uint16_t local_port;
	bool ret;

	local_port = torture_get_local_port_from_transport(transport);
	torture_comment(tctx, "transport[%s] uses tcp port: %d\n", name, local_port);
	ret = torture_block_tcp_output_port(tctx, name, local_port);
	torture_assert(tctx, ret, "we could not block tcp transport");

	return ret;
}

static bool test_unblock_smb2_transport_iptables(struct torture_context *tctx,
						 struct smb2_transport *transport,
						 const char *name)
{
	uint16_t local_port;
	bool ret;

	local_port = torture_get_local_port_from_transport(transport);
	torture_comment(tctx, "transport[%s] uses tcp port: %d\n", name, local_port);
	ret = torture_unblock_tcp_output_port(tctx, name, local_port);
	torture_assert(tctx, ret, "we could not block tcp transport");

	return ret;
}

static bool torture_blocked_lease_handler(struct smb2_transport *transport,
					  const struct smb2_lease_break *lb,
					  void *private_data)
{
	struct smb2_transport *transport_copy =
		talloc_get_type_abort(private_data,
		struct smb2_transport);
	bool lease_skip_ack = lease_break_info.lease_skip_ack;
	bool ok;

	lease_break_info.lease_skip_ack = true;
	ok = transport_copy->lease.handler(transport,
					   lb,
					   transport_copy->lease.private_data);
	lease_break_info.lease_skip_ack = lease_skip_ack;

	if (!ok) {
		return false;
	}

	if (lease_break_info.lease_skip_ack) {
		return true;
	}

	if (lb->break_flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED) {
		lease_break_info.failures++;
	}

	return true;
}

static bool torture_blocked_oplock_handler(struct smb2_transport *transport,
					   const struct smb2_handle *handle,
					   uint8_t level,
					   void *private_data)
{
	struct smb2_transport *transport_copy =
		talloc_get_type_abort(private_data,
		struct smb2_transport);
	bool oplock_skip_ack = break_info.oplock_skip_ack;
	bool ok;

	break_info.oplock_skip_ack = true;
	ok = transport_copy->oplock.handler(transport,
					    handle,
					    level,
					    transport_copy->oplock.private_data);
	break_info.oplock_skip_ack = oplock_skip_ack;

	if (!ok) {
		return false;
	}

	if (break_info.oplock_skip_ack) {
		return true;
	}

	break_info.failures++;
	break_info.failure_status = NT_STATUS_CONNECTION_DISCONNECTED;

	return true;
}

static bool test_block_smb2_transport_fsctl_smbtorture(struct torture_context *tctx,
						       struct smb2_transport *transport,
						       const char *name)
{
	struct smb2_transport *transport_copy = NULL;
	DATA_BLOB in_input_buffer = data_blob_null;
	DATA_BLOB in_output_buffer = data_blob_null;
	DATA_BLOB out_input_buffer = data_blob_null;
	DATA_BLOB out_output_buffer = data_blob_null;
	struct tevent_req *req = NULL;
	uint16_t local_port;
	NTSTATUS status;
	bool ok;

	transport_copy = talloc_zero(transport, struct smb2_transport);
	torture_assert(tctx, transport_copy, "talloc transport_copy");
	transport_copy->lease = transport->lease;
	transport_copy->oplock = transport->oplock;

	local_port = torture_get_local_port_from_transport(transport);
	torture_comment(tctx, "transport[%s] uses tcp port: %d\n", name, local_port);
	req = smb2cli_ioctl_send(tctx,
				 tctx->ev,
				 transport->conn,
				 1000, /* timeout_msec */
				 NULL, /* session */
				 NULL, /* tcon */
				 UINT64_MAX, /* in_fid_persistent */
				 UINT64_MAX, /* in_fid_volatile */
				 FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT,
				 0, /* in_max_input_length */
				 &in_input_buffer,
				 0, /* in_max_output_length */
				 &in_output_buffer,
				 SMB2_IOCTL_FLAG_IS_FSCTL);
	torture_assert(tctx, req != NULL, "smb2cli_ioctl_send() failed");
	ok = tevent_req_poll_ntstatus(req, tctx->ev, &status);
	if (ok) {
		status = NT_STATUS_OK;
	}
	torture_assert_ntstatus_ok(tctx, status, "tevent_req_poll_ntstatus() failed");
	status = smb2cli_ioctl_recv(req, tctx,
				    &out_input_buffer,
				    &out_output_buffer);
	torture_assert_ntstatus_ok(tctx, status,
		"FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT failed\n\n"
		"On a Samba server 'smbd:FSCTL_SMBTORTURE = yes' is needed!\n\n"
		"Otherwise you may need to use iptables like this:\n"
		"--option='torture:use_iptables=yes'\n"
		"And maybe something like this in addition:\n"
		"--option='torture:iptables_command=sudo /sbin/iptables'\n\n");
	TALLOC_FREE(req);

	if (transport->lease.handler != NULL) {
		transport->lease.handler = torture_blocked_lease_handler;
		transport->lease.private_data = transport_copy;
	}
	if (transport->oplock.handler != NULL) {
		transport->oplock.handler = torture_blocked_oplock_handler;
		transport->oplock.private_data = transport_copy;
	}

	return true;
}

bool _test_block_smb2_transport(struct torture_context *tctx,
				struct smb2_transport *transport,
				const char *name)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		return test_block_smb2_transport_iptables(tctx, transport, name);
	} else {
		return test_block_smb2_transport_fsctl_smbtorture(tctx, transport, name);
	}
}

bool _test_unblock_smb2_transport(struct torture_context *tctx,
				  struct smb2_transport *transport,
				  const char *name)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		return test_unblock_smb2_transport_iptables(tctx, transport, name);
	} else {
		return true;
	}
}

bool test_setup_blocked_transports(struct torture_context *tctx)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		return torture_block_tcp_output_setup(tctx);
	}

	return true;
}

void test_cleanup_blocked_transports(struct torture_context *tctx)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		torture_unblock_tcp_output_cleanup(tctx);
	}
}
