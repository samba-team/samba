/*
   Unix SMB/CIFS implementation.

   DNS query too for Samba with socketwrapper support

   Copyright (C) 2012 Kai Blin  <kai@samba.org>

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

#include "includes.h"
#include <talloc.h>
#include <tevent.h>
#include "lib/util/samba_util.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "libcli/dns/libdns.h"

static void usage(void)
{
	printf("Usage: samba-dig <dns-server-ip> <data> <record-type>\n\n");
}

static struct dns_name_packet *make_name_packet(TALLOC_CTX *mem_ctx,
						uint16_t operation)
{
	struct dns_name_packet *packet = talloc_zero(mem_ctx,
						     struct dns_name_packet);
	if (packet == NULL) {
		return NULL;
	}

	packet->id = random();
	packet->operation |= operation | DNS_FLAG_RECURSION_DESIRED;

	return packet;
}

#define QTYPE_MAP(type) if (strncmp(type_string, #type , strlen( #type )) == 0) \
	return DNS_QTYPE_ ## type ;

static enum dns_qtype parse_qtype(const char *type_string)
{
	QTYPE_MAP(AAAA);
	QTYPE_MAP(A);
	QTYPE_MAP(SOA);
	QTYPE_MAP(PTR);
	return -1;
}
#undef QTYPE_MAP

static struct dns_name_question *make_question(TALLOC_CTX *mem_ctx,
					       const char *name,
					       enum dns_qtype type)
{
	struct dns_name_question *question = talloc(mem_ctx,
			struct dns_name_question);
	if (question == NULL) {
		return NULL;
	}

	question->name = talloc_strdup(question, name);
	question->question_type = type;
	question->question_class = DNS_QCLASS_IN;

	return question;
}

int main(int argc, char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_init("samba-dig");
	struct tevent_context *ev;
	struct dns_name_packet *dns_packet, *in_packet;
	struct dns_name_question *question;
	enum dns_qtype type;
	enum ndr_err_code ndr_err;
	struct tevent_req *req;
	WERROR w_err;
	DATA_BLOB out, in;
	int ret = 0;

	if (argc < 4) {
		usage();
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	setup_logging("samba-dig", DEBUG_STDERR);
	debug_parse_levels("1");

	DEBUG(1,("Querying %s for %s %s\n", argv[1], argv[2], argv[3]));

	dns_packet = make_name_packet(mem_ctx, DNS_OPCODE_QUERY);

	type = parse_qtype(argv[3]);
	if (type == -1) {
		DEBUG(0, ("Invalid DNS_QTYPE %s\n", argv[3]));
		ret = 1;
		goto error;
	}

	question = make_question(dns_packet, argv[2], type);

	dns_packet->qdcount = 1;
	dns_packet->questions = question;
	NDR_PRINT_DEBUG(dns_name_packet, dns_packet);

	ndr_err = ndr_push_struct_blob(&out, mem_ctx, dns_packet,
			(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to marshall dns_name_packet: %d\n", ndr_err));
		ret = 1;
		goto error;
	}

	req = dns_udp_request_send(mem_ctx, ev, argv[1], out.data, out.length);
	if (req == NULL) {
		DEBUG(0, ("Failed to allocate memory for tevent_req\n"));
		ret = 1;
		goto error;
	}
	if (!tevent_req_poll(req, ev)) {
		DEBUG(0, ("Error sending dns request\n"));
		ret = 1;
		goto error;
	}
	w_err = dns_udp_request_recv(req, mem_ctx, &in.data, &in.length);
	if (!W_ERROR_IS_OK(w_err)) {
		DEBUG(0, ("Error receiving dns request: %s\n", win_errstr(w_err)));
		ret = 1;
		goto error;
	}

	in_packet = talloc(mem_ctx, struct dns_name_packet);

	ndr_err = ndr_pull_struct_blob(&in, in_packet, in_packet,
			(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to unmarshall dns_name_packet: %d\n", ndr_err));
		ret = 1;
		goto error;
	}

	NDR_PRINT_DEBUG(dns_name_packet, in_packet);

error:
	talloc_free(mem_ctx);
	return ret;
}
