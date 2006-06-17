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

/*
  basic testing of udp routines
*/
static BOOL test_udp(struct torture_context *test, const void *data)
{
	struct socket_context *sock1, *sock2;
	NTSTATUS status;
	struct socket_address *srv_addr, *from_addr, *localhost;
	size_t size = 100 + (random() % 100);
	DATA_BLOB blob, blob2;
	size_t sent, nread;
	BOOL ret = True;

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &sock1, 0);
	torture_assert_ntstatus_ok(test, status, NULL);
	talloc_steal(test, sock1);

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &sock2, 0);
	torture_assert_ntstatus_ok(test, status, NULL);
	talloc_steal(test, sock2);

	localhost = socket_address_from_strings(sock1, sock1->backend_name, 
						iface_best_ip("127.0.0.1"), 0);

	torture_assert(test, localhost, "Localhost not found");

	status = socket_listen(sock1, localhost, 0, 0);
	torture_assert_ntstatus_ok(test, status, NULL);

	srv_addr = socket_get_my_addr(sock1, test);
	if (srv_addr == NULL || strcmp(srv_addr->addr, iface_best_ip("127.0.0.1")) != 0) {
		torture_fail(test, "Expected server address of %s but got %s",
		       iface_best_ip("127.0.0.1"), srv_addr ? srv_addr->addr : NULL);
		return False;
	}

	torture_comment(test, "server port is %d", srv_addr->port);

	blob  = data_blob_talloc(test, NULL, size);
	blob2 = data_blob_talloc(test, NULL, size);
	generate_random_buffer(blob.data, blob.length);

	sent = size;
	status = socket_sendto(sock2, &blob, &sent, srv_addr);
	torture_assert_ntstatus_ok(test, status, NULL);

	status = socket_recvfrom(sock1, blob2.data, size, &nread, 
				 sock1, &from_addr);
	torture_assert_ntstatus_ok(test, status, NULL);

	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		torture_fail(test, "Unexpected recvfrom addr %s", from_addr->addr);
		return False;
	}
	if (nread != size) {
		torture_fail(test, "Unexpected recvfrom size %d should be %d\n", 
					 (int)nread, (int)size);
		return False;
	}

	torture_assert(test, memcmp(blob2.data, blob.data, size) == 0,
		"Bad data in recvfrom");

	generate_random_buffer(blob.data, blob.length);
	status = socket_sendto(sock1, &blob, &sent, from_addr);
	torture_assert_ntstatus_ok(test, status, NULL);

	status = socket_recvfrom(sock2, blob2.data, size, &nread, 
				 sock2, &from_addr);
	torture_assert_ntstatus_ok(test, status, NULL);
	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		torture_fail(test, "Unexpected recvfrom addr %s\n", from_addr->addr);
		return False;
	}
	
	if (nread != size) {
		torture_fail(test, "Unexpected recvfrom size %d should be %d\n", 
					 (int)nread, (int)size);
		return False;
	}

	if (from_addr->port != srv_addr->port) {
		torture_fail(test, "Unexpected recvfrom port %d should be %d\n", 
		       from_addr->port, srv_addr->port);
		return False;
	}

	torture_assert(test, memcmp(blob2.data, blob.data, size) == 0, 
		"Bad data in recvfrom");

	talloc_free(sock1);
	talloc_free(sock2);

	return ret;
}

/*
  basic testing of tcp routines
*/
static BOOL test_tcp(struct torture_context *test, const void *data)
{
	struct socket_context *sock1, *sock2, *sock3;
	NTSTATUS status;
	struct socket_address *srv_addr, *from_addr, *localhost;
	size_t size = 100 + (random() % 100);
	DATA_BLOB blob, blob2;
	size_t sent, nread;
	struct event_context *ev = event_context_init(test);

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock1, 0);
	torture_assert_ntstatus_ok(test, status, NULL);
	talloc_steal(test, sock1);

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock2, 0);
	torture_assert_ntstatus_ok(test, status, NULL);
	talloc_steal(test, sock2);

	localhost = socket_address_from_strings(sock1, sock1->backend_name, 
						iface_best_ip("127.0.0.1"), 0);
	torture_assert(test, localhost, "Localhost not found");

	status = socket_listen(sock1, localhost, 0, 0);
	torture_assert_ntstatus_ok(test, status, NULL);

	srv_addr = socket_get_my_addr(sock1, test);
	torture_assert(test, srv_addr && srv_addr->addr, 
				   "Unexpected socket_get_my_addr NULL\n");

	if (strcmp(srv_addr->addr, iface_best_ip("127.0.0.1")) != 0) {
		torture_fail(test, "Expected server address of %s but got %s\n",
		       iface_best_ip("127.0.0.1"), srv_addr ? srv_addr->addr : NULL);
		return False;
	}

	torture_comment(test, "server port is %d", srv_addr->port);

	status = socket_connect_ev(sock2, NULL, srv_addr, 0, ev);
	torture_assert_ntstatus_ok(test, status, NULL);

	status = socket_accept(sock1, &sock3);
	torture_assert_ntstatus_ok(test, status, NULL);
	talloc_steal(test, sock3);
	talloc_free(sock1);

	blob  = data_blob_talloc(test, NULL, size);
	blob2 = data_blob_talloc(test, NULL, size);
	generate_random_buffer(blob.data, blob.length);

	sent = size;
	status = socket_send(sock2, &blob, &sent);
	torture_assert_ntstatus_ok(test, status, NULL);

	status = socket_recv(sock3, blob2.data, size, &nread);
	torture_assert_ntstatus_ok(test, status, NULL);

	from_addr = socket_get_peer_addr(sock3, test);

	torture_assert(test, from_addr && from_addr->addr, 
		"Unexpected recvfrom addr NULL");

	if (strcmp(from_addr->addr, srv_addr->addr) != 0) {
		torture_fail(test, "Unexpected recvfrom addr %s\n", 
					 from_addr ? from_addr->addr : NULL);
		return False;
	}
	if (nread != size) {
		torture_fail(test, "Unexpected recvfrom size %d should be %d\n", 
					 (int)nread, (int)size);
		return False;
	}

	torture_assert(test, 
				   memcmp(blob2.data, blob.data, size) == 0, 
				   "Bad data in recv");

	return True;
}

struct torture_suite *torture_local_socket(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "LOCAL-SOCKET");

	torture_suite_add_simple_tcase(suite, "udp", test_udp, NULL);
	torture_suite_add_simple_tcase(suite, "tcp", test_tcp, NULL);

	return suite;
}
