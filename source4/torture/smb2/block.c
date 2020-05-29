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
