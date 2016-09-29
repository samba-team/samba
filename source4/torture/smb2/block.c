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
 * INPUT
 *  |
 *  -----> SAMBA_INPUT
 *             |
 *             -----> SAMBA_INPUT_transportname1
 *             -----> SAMBA_INPUT_transportname2
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

int smbrun(const char *cmd, int *outfd, char * const *env);

static bool run_cmd_return_buf(TALLOC_CTX *mem_ctx,
			       const char *cmd,
			       int *num_lines, char ***buf)
{
	int ret;
	int fd = -1;

	DEBUG(10, ("%s will call '%s'\n", __location__, cmd));

	ret = smbrun(cmd, &fd, NULL);
	if (ret) {
		DEBUG(1, ("%s failed to execute system call: %s: %d\n",
			__location__, cmd, ret));
		if (fd != -1) {
			close(fd);
		}
		return false;
	}

	*buf = fd_lines_load(fd, num_lines, 0, mem_ctx);
	if (fd != -1) {
		close(fd);
	}
	if (*buf == NULL) {
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
 * iptables v1.6.1: chain name `SAMBA_INPUT_tree1->session->transport'
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

static bool filter_tcp_setup(struct torture_context *tctx,
			     bool unblock)
{
	const char *cmd_in, *cmd_out;
	const char *ipt = iptables_command(tctx);

	if (unblock) {
		cmd_in = talloc_asprintf(tctx,
				"%s -L SAMBA_INPUT > /dev/null 2>&1 && "
				"("
				"%s -F SAMBA_INPUT; "
				"%s -D INPUT -j SAMBA_INPUT; "
				"%s -X SAMBA_INPUT;"
				")",
				ipt, ipt, ipt, ipt);
		cmd_out = talloc_asprintf(tctx,
				"%s -L SAMBA_OUTPUT > /dev/null 2>&1 && "
				"("
				"%s -F SAMBA_OUTPUT;"
				"%s -D OUTPUT -j SAMBA_OUTPUT;"
				"%s -X SAMBA_OUTPUT;"
				")",
				ipt, ipt, ipt, ipt);
	} else {
		cmd_in = talloc_asprintf(tctx,
				"%s -L SAMBA_INPUT > /dev/null 2>&1 || "
				"("
				"%s -N SAMBA_INPUT && "
				"%s -I INPUT -j SAMBA_INPUT "
				")",
				ipt, ipt, ipt);
		cmd_out = talloc_asprintf(tctx,
				"%s -L SAMBA_OUTPUT > /dev/null 2>&1 || "
				"("
				"%s -N SAMBA_OUTPUT && "
				"%s -I OUTPUT -j SAMBA_OUTPUT;"
				")",
				ipt, ipt, ipt);
	}

	if (cmd_in == NULL || cmd_out == NULL) {
		return false;
	}

	if (!run_cmd(cmd_in)) {
		return false;
	}
	/* if (!run_cmd(cmd_out)) { return false; } */

	return true;
}

static bool filter_tcp_setup_name(struct torture_context *tctx,
				  const char *name, bool unblock)
{
	const char *cmd_in, *cmd_out;
	const char *chain_in, *chain_out;
	const char *ipt = iptables_command(tctx);

	chain_in = samba_chain_name(tctx, name, "SAMBA_INPUT");
	chain_out = samba_chain_name(tctx, name, "SAMBA_OUTPUT");
	if (chain_in == NULL || chain_out == NULL) {
		return false;
	}

	if (unblock) {
		cmd_in  = talloc_asprintf(tctx, "%s -F %s; "
						"%s -D SAMBA_INPUT -j %s; "
						"%s -X %s",
						ipt, chain_in,
						ipt, chain_in,
						ipt, chain_in);
		cmd_out = talloc_asprintf(tctx, "%s -F %s; "
						"%s -D SAMBA_OUTPUT -j %s; "
						"%s -X %s",
						ipt, chain_out,
						ipt, chain_out,
						ipt, chain_out);
	} else {
		cmd_in  = talloc_asprintf(tctx, "%s -L %s > /dev/null 2>&1 || "
						"%s -N %s && "
						"%s -I SAMBA_INPUT -j %s",
						ipt, chain_in,
						ipt, chain_in,
						ipt, chain_in);
		cmd_out = talloc_asprintf(tctx, "%s -L %s > /dev/null 2>&1 || "
						"%s -N %s && "
						"%s -I SAMBA_OUTPUT -j %s",
						ipt, chain_out,
						ipt, chain_out,
						ipt, chain_out);
	}

	if (cmd_in == NULL || cmd_out == NULL) {
		return false;
	}

	if (!run_cmd(cmd_in)) {
		return false;
	}
	/* if (!run_cmd(cmd_out)) return false; */

	return true;
}

/* '11   452 DROP tcp -- * *  0.0.0.0/0  0.0.0.0/0  tcp dpt:43062' */
static bool get_packet_count(const char *s, uint32_t *count)
{
	int i = 0;
	char *p;

	if (s == NULL) {
		return false;
	}

	while (s[i] == ' ') {
		s++;
	}

	p = strchr(s, ' ');
	if (p == NULL) {
		return false;
	}
	*p = '\0';

	*count = atoi(s);

	return true;
}

bool torture_list_tcp_transport_name(struct torture_context *tctx,
				    const char *name,
				    uint32_t *_packets)
{
	const char *chain_in, *cmd;
	int num_lines;
	char **buf;
	uint32_t packets = 0;
	const char *ipt = iptables_command(tctx);

	chain_in = samba_chain_name(tctx, name, "SAMBA_INPUT");
	if (chain_in == NULL) {
		return false;
	}

	cmd = talloc_asprintf(tctx, "%s -L %s -v -n", ipt, chain_in);
	if (cmd == NULL) {
		return false;
	}

	if (!run_cmd_return_buf(tctx, cmd, &num_lines, &buf)) {
		return false;
	}
	SMB_ASSERT(num_lines >= 3);

	if (!get_packet_count(buf[2], &packets)) {
		return false;
	}

	torture_comment(tctx, "chain: '%s', packets: %d\n", name, (int)packets);

	if (_packets != NULL) {
		*_packets = packets;
	}

	return true;
}

uint16_t torture_get_local_port_from_transport(struct smb2_transport *t)
{
	const struct sockaddr_storage *local_ss;

	local_ss = smbXcli_conn_local_sockaddr(t->conn);

	return get_sockaddr_port(local_ss);
}

static bool torture_block_tcp_transport_name_internal(
						struct torture_context *tctx,
						struct smb2_transport *t,
						const char *name,
						bool unblock)
{
	char *cmd_in;
	char *cmd_out;
	const char *chain_in, *chain_out;
	uint16_t port = torture_get_local_port_from_transport(t);
	const char *ipt = iptables_command(tctx);

	chain_in = samba_chain_name(tctx, name, "SAMBA_INPUT");
	chain_out = samba_chain_name(tctx, name, "SAMBA_OUTPUT");
	if (chain_in == NULL || chain_out == NULL) {
		return false;
	}

	if (!unblock) {
		filter_tcp_setup(tctx, false);
		filter_tcp_setup_name(tctx, name, false);
	}

	torture_comment(tctx, "%sblocking %s dport %d\n",
			unblock ? "un" : "", name, port);

	cmd_in = talloc_asprintf(tctx,
				 "%s %s %s -p tcp --dport %d -j DROP",
				 ipt, unblock ? "-D" : "-I", chain_in, port);
	cmd_out = talloc_asprintf(tctx,
				  "%s %s %s -p tcp --sport %d -j DROP",
				  ipt, unblock ? "-D" : "-I", chain_out, port);
	if (cmd_in == NULL || cmd_out == NULL) {
		return false;
	}

	if (!run_cmd(cmd_in)) {
		return false;
	}
	/* if (!run_cmd(cmd_out)) return false; */

	if (unblock) {
		filter_tcp_setup_name(tctx, name, true);
		/* better dont cleanup here */
		/* filter_tcp_setup(tctx, true); */
	}

	return true;
}

bool torture_block_tcp_transport_name(struct torture_context *tctx,
				      struct smb2_transport *t,
				      const char *name)
{
	return torture_block_tcp_transport_name_internal(tctx, t, name, false);
}

bool torture_unblock_tcp_transport_name(struct torture_context *tctx,
					struct smb2_transport *t,
					const char *name)
{
	return torture_block_tcp_transport_name_internal(tctx, t, name, true);
}

void torture_unblock_cleanup(struct torture_context *tctx)
{
	filter_tcp_setup(tctx, true);
}
