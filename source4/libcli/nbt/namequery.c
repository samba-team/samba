/* 
   Unix SMB/CIFS implementation.

   make nbt name query requests

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/nbt/libnbt.h"
#include "system/network.h"

/*
  send a nbt name query
*/
struct nbt_name_request *nbt_name_query_send(struct nbt_name_socket *nbtsock,
					     struct nbt_name_query *io)
{
	struct nbt_name_request *req;
	struct nbt_name_packet *packet;

	packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (packet == NULL) return NULL;

	packet->qdcount = 1;
	packet->operation = NBT_OPCODE_QUERY;
	if (io->in.broadcast) {
		packet->operation |= NBT_FLAG_BROADCAST;
	}
	if (io->in.wins_lookup) {
		packet->operation |= NBT_FLAG_RECURSION_DESIRED;
	}

	packet->questions = talloc_array(packet, struct nbt_name_question, 1);
	if (packet->questions == NULL) goto failed;

	packet->questions[0].name = io->in.name;
	packet->questions[0].question_type = NBT_QTYPE_NETBIOS;
	packet->questions[0].question_class = NBT_QCLASS_IP;
	
	req = nbt_name_request_send(nbtsock, io->in.dest_addr, NBT_NAME_SERVICE_PORT, packet,
				    timeval_current_ofs(io->in.timeout, 0), False);
	if (req == NULL) goto failed;

	talloc_steal(req, packet);

	return req;

failed:
	talloc_free(packet);
	return NULL;	
}

/*
  wait for a name query replu
*/
NTSTATUS nbt_name_query_recv(struct nbt_name_request *req, 
			     TALLOC_CTX *mem_ctx, struct nbt_name_query *io)
{
	NTSTATUS status;
	struct nbt_name_packet *packet;
	const char *addr;
	struct in_addr in;

	status = nbt_name_request_recv(req);
	if (!NT_STATUS_IS_OK(status) ||
	    req->num_replies == 0) {
		talloc_free(req);
		return status;
	}
	
	packet = req->replies[0].packet;
	io->out.reply_from = talloc_steal(mem_ctx, req->replies[0].reply_addr);

	if (packet->ancount != 1 ||
	    packet->answers[0].rr_type != NBT_QTYPE_NETBIOS ||
	    packet->answers[0].rr_class != NBT_QCLASS_IP) {
		talloc_free(req);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	io->out.name = packet->answers[0].name;
	in.s_addr = htonl(packet->answers[0].rdata.netbios.ipaddr);
	addr = inet_ntoa(in);
	if (addr == NULL) {
		talloc_free(req);
		return NT_STATUS_NO_MEMORY;
	}
	io->out.reply_addr = talloc_strdup(mem_ctx, addr);
	talloc_steal(mem_ctx, io->out.name.name);
	talloc_steal(mem_ctx, io->out.name.scope);
	    
	talloc_free(req);

	return NT_STATUS_OK;
}

/*
  wait for a name query replu
*/
NTSTATUS nbt_name_query(struct nbt_name_socket *nbtsock, 
			TALLOC_CTX *mem_ctx, struct nbt_name_query *io)
{
	struct nbt_name_request *req = nbt_name_query_send(nbtsock, io);
	return nbt_name_query_recv(req, mem_ctx, io);
}


/*
  send a nbt name status
*/
struct nbt_name_request *nbt_name_status_send(struct nbt_name_socket *nbtsock,
					      struct nbt_name_status *io)
{
	struct nbt_name_request *req;
	struct nbt_name_packet *packet;

	packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (packet == NULL) return NULL;

	packet->qdcount = 1;
	packet->operation = NBT_OPCODE_QUERY;

	packet->questions = talloc_array(packet, struct nbt_name_question, 1);
	if (packet->questions == NULL) goto failed;

	packet->questions[0].name = io->in.name;
	packet->questions[0].question_type = NBT_QTYPE_STATUS;
	packet->questions[0].question_class = NBT_QCLASS_IP;
	
	req = nbt_name_request_send(nbtsock, io->in.dest_addr, NBT_NAME_SERVICE_PORT, packet,
				    timeval_current_ofs(io->in.timeout, 0), False);
	if (req == NULL) goto failed;

	talloc_steal(req, packet);

	return req;

failed:
	talloc_free(packet);
	return NULL;	
}

/*
  wait for a name status replu
*/
NTSTATUS nbt_name_status_recv(struct nbt_name_request *req, 
			     TALLOC_CTX *mem_ctx, struct nbt_name_status *io)
{
	NTSTATUS status;
	struct nbt_name_packet *packet;
	int i;

	status = nbt_name_request_recv(req);
	if (!NT_STATUS_IS_OK(status) ||
	    req->num_replies == 0) {
		talloc_free(req);
		return status;
	}
	
	packet = req->replies[0].packet;
	io->out.reply_from = talloc_steal(mem_ctx, req->replies[0].reply_addr);

	if (packet->ancount != 1 ||
	    packet->answers[0].rr_type != NBT_QTYPE_STATUS ||
	    packet->answers[0].rr_class != NBT_QCLASS_IP) {
		talloc_free(req);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	io->out.name = packet->answers[0].name;
	talloc_steal(mem_ctx, io->out.name.name);
	talloc_steal(mem_ctx, io->out.name.scope);

	io->out.status = packet->answers[0].rdata.status;
	talloc_steal(mem_ctx, io->out.status.names);
	for (i=0;i<io->out.status.num_names;i++) {
		talloc_steal(io->out.status.names, io->out.status.names[i].name);
	}

	    
	talloc_free(req);

	return NT_STATUS_OK;
}

/*
  wait for a name status replu
*/
NTSTATUS nbt_name_status(struct nbt_name_socket *nbtsock, 
			TALLOC_CTX *mem_ctx, struct nbt_name_status *io)
{
	struct nbt_name_request *req = nbt_name_status_send(nbtsock, io);
	return nbt_name_status_recv(req, mem_ctx, io);
}


/*
  some test functions - will be removed when nbt is hooked in everywhere
*/
void test_name_status(const char *name, const char *addr)
{
	struct nbt_name_status io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct nbt_name_socket *nbtsock;
	int i;

	nbtsock = nbt_name_socket_init(tmp_ctx, NULL);
	
	io.in.name.name = name;
	io.in.name.scope = NULL;
	io.in.name.type = NBT_NAME_CLIENT;
	io.in.dest_addr = addr;
	io.in.timeout = 5;

	status = nbt_name_status(nbtsock, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("status failed for %s - %s\n", name, nt_errstr(status));
		talloc_free(tmp_ctx);	
		exit(1);
		return;
	}

	printf("Received %d names for %s\n", io.out.status.num_names, io.out.name.name);
	for (i=0;i<io.out.status.num_names;i++) {
		printf("\t%s#%02x  0x%04x\n",
		       io.out.status.names[i].name,
		       io.out.status.names[i].type,
		       io.out.status.names[i].nb_flags);
	}
	talloc_free(tmp_ctx);	
}


void test_name_query(const char *name)
{
	struct nbt_name_query io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct nbt_name_socket *nbtsock;

	nbtsock = nbt_name_socket_init(tmp_ctx, NULL);
	
	io.in.name.name = name;
	io.in.name.scope = NULL;
	io.in.name.type = NBT_NAME_SERVER;
	io.in.dest_addr = "255.255.255.255";
	io.in.broadcast = True;
	io.in.wins_lookup = False;
	io.in.timeout = 5;

	status = nbt_name_query(nbtsock, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("query failed for %s - %s\n", name, nt_errstr(status));
	} else {
		printf("response %s is at %s\n", io.out.name.name, io.out.reply_addr);
		test_name_status("*", io.out.reply_addr);
	}

	talloc_free(tmp_ctx);	
}

