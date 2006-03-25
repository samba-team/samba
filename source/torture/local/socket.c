/* 
   Unix SMB/CIFS implementation.

   local testing of socket routines.

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
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "netif/netif.h"
#include "torture/torture.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  basic testing of udp routines
*/
static BOOL test_udp(TALLOC_CTX *mem_ctx)
{
	struct socket_context *sock1, *sock2;
	NTSTATUS status;
	struct socket_address *srv_addr, *from_addr, *localhost;
	size_t size = 100 + (random() % 100);
	DATA_BLOB blob, blob2;
	size_t sent, nread;
	BOOL ret = True;

	printf("TESTING UDP SOCKETS\n");

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &sock1, 0);
	CHECK_STATUS(status, NT_STATUS_OK);
	talloc_steal(mem_ctx, sock1);

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &sock2, 0);
	CHECK_STATUS(status, NT_STATUS_OK);
	talloc_steal(mem_ctx, sock2);

	localhost = socket_address_from_strings(sock1, sock1->backend_name, 
						iface_best_ip("127.0.0.1"), 0);
	if (!localhost) {
		return False;
	}

	status = socket_listen(sock1, localhost, 0, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	srv_addr = socket_get_my_addr(sock1, mem_ctx);
	if (srv_addr == NULL || strcmp(srv_addr->addr, iface_best_ip("127.0.0.1")) != 0) {
		printf("Expected server address of %s but got %s\n",
		       iface_best_ip("127.0.0.1"), srv_addr ? srv_addr->addr : NULL);
		return False;
	}

	printf("server port is %d\n", srv_addr->port);

	blob  = data_blob_talloc(mem_ctx, NULL, size);
	blob2 = data_blob_talloc(mem_ctx, NULL, size);
	generate_random_buffer(blob.data, blob.length);

	sent = size;
	status = socket_sendto(sock2, &blob, &sent, 0, srv_addr);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = socket_recvfrom(sock1, blob2.data, size, &nread, 0, 
				 sock1, &from_addr);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		printf("Unexpected recvfrom addr %s\n", from_addr->addr);
		ret = False;
	}
	if (nread != size) {
		printf("Unexpected recvfrom size %d should be %d\n", (int)nread, (int)size);
		ret = False;
	}

	if (memcmp(blob2.data, blob.data, size) != 0) {
		printf("Bad data in recvfrom\n");
		ret = False;
	}

	generate_random_buffer(blob.data, blob.length);
	status = socket_sendto(sock1, &blob, &sent, 0, from_addr);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = socket_recvfrom(sock2, blob2.data, size, &nread, 0, 
				 sock2, &from_addr);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		printf("Unexpected recvfrom addr %s\n", from_addr->addr);
		ret = False;
	}
	if (nread != size) {
		printf("Unexpected recvfrom size %d should be %d\n", (int)nread, (int)size);
		ret = False;
	}
	if (from_addr->port != srv_addr->port) {
		printf("Unexpected recvfrom port %d should be %d\n", 
		       from_addr->port, srv_addr->port);
		ret = False;
	}
	if (memcmp(blob2.data, blob.data, size) != 0) {
		printf("Bad data in recvfrom\n");
		ret = False;
	}

done:
	talloc_free(sock1);
	talloc_free(sock2);

	return ret;
}

/*
  basic testing of tcp routines
*/
static BOOL test_tcp(TALLOC_CTX *mem_ctx)
{
	struct socket_context *sock1, *sock2, *sock3;
	NTSTATUS status;
	struct socket_address *srv_addr, *from_addr, *localhost;
	size_t size = 100 + (random() % 100);
	DATA_BLOB blob, blob2;
	size_t sent, nread;
	BOOL ret = True;
	struct event_context *ev = event_context_init(mem_ctx);

	printf("TESTING TCP SOCKETS\n");

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock1, 0);
	CHECK_STATUS(status, NT_STATUS_OK);
	talloc_steal(mem_ctx, sock1);

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock2, 0);
	CHECK_STATUS(status, NT_STATUS_OK);
	talloc_steal(mem_ctx, sock2);

	localhost = socket_address_from_strings(sock1, sock1->backend_name, 
						iface_best_ip("127.0.0.1"), 0);
	if (!localhost) {
		return False;
	}

	status = socket_listen(sock1, localhost, 0, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	srv_addr = socket_get_my_addr(sock1, mem_ctx);
	if (srv_addr == NULL || !srv_addr->addr) {
		printf("Unexpected socket_get_my_addr NULL\n");
		return False;
	}

	if (strcmp(srv_addr->addr, iface_best_ip("127.0.0.1")) != 0) {
		printf("Expected server address of %s but got %s\n",
		       iface_best_ip("127.0.0.1"), srv_addr ? srv_addr->addr : NULL);
		return False;
	}

	printf("server port is %d\n", srv_addr->port);

	status = socket_connect_ev(sock2, NULL, srv_addr, 0, ev);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = socket_accept(sock1, &sock3);
	CHECK_STATUS(status, NT_STATUS_OK);
	talloc_steal(mem_ctx, sock3);
	talloc_free(sock1);

	blob  = data_blob_talloc(mem_ctx, NULL, size);
	blob2 = data_blob_talloc(mem_ctx, NULL, size);
	generate_random_buffer(blob.data, blob.length);

	sent = size;
	status = socket_send(sock2, &blob, &sent, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = socket_recv(sock3, blob2.data, size, &nread, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	from_addr = socket_get_peer_addr(sock3, mem_ctx);

	if (!from_addr || !from_addr->addr) {
		printf("Unexpected recvfrom addr NULL\n");
		return False;
	}
	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		printf("Unexpected recvfrom addr %s\n", from_addr ? from_addr->addr : NULL);
		ret = False;
	}
	if (nread != size) {
		printf("Unexpected recvfrom size %d should be %d\n", (int)nread, (int)size);
		ret = False;
	}

	if (memcmp(blob2.data, blob.data, size) != 0) {
		printf("Bad data in recvfrom\n");
		ret = False;
	}

	generate_random_buffer(blob.data, blob.length);
	status = socket_send(sock3, &blob, &sent, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = socket_recv(sock2, blob2.data, size, &nread, 0);
	CHECK_STATUS(status, NT_STATUS_OK);

	from_addr = socket_get_peer_addr(sock2, mem_ctx);

	if (!from_addr || !from_addr->addr) {
		printf("Unexpected recvfrom addr NULL\n");
		return False;
	}
	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		printf("Unexpected recvfrom addr %s\n", from_addr ? from_addr->addr : NULL);
		ret = False;
	}
	if (nread != size) {
		printf("Unexpected recvfrom size %d should be %d\n", (int)nread, (int)size);
		ret = False;
	}
	if (from_addr->port != srv_addr->port) {
		printf("Unexpected recvfrom port %d should be %d\n", 
		       from_addr->port, srv_addr->port);
		ret = False;
	}
	if (memcmp(blob2.data, blob.data, size) != 0) {
		printf("Bad data in recvfrom\n");
		ret = False;
	}

done:

	return ret;
}

BOOL torture_local_socket(struct torture_context *torture) 
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	ret &= test_udp(mem_ctx);
	ret &= test_tcp(mem_ctx);

	return ret;
}
