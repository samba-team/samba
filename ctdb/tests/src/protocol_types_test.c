/*
   protocol types tests

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"

#include <assert.h>

#include "protocol/protocol_basic.c"
#include "protocol/protocol_types.c"
#include "protocol/protocol_sock.c"

#include "tests/src/protocol_common.h"

PROTOCOL_TYPE2_TEST(TDB_DATA, ctdb_tdb_data);
PROTOCOL_TYPE2_TEST(TDB_DATA, ctdb_tdb_datan);
PROTOCOL_TYPE1_TEST(struct ctdb_latency_counter, ctdb_latency_counter);

PROTOCOL_TYPE3_TEST(struct ctdb_statistics, ctdb_statistics);
PROTOCOL_TYPE3_TEST(struct ctdb_vnn_map, ctdb_vnn_map);
PROTOCOL_TYPE3_TEST(struct ctdb_dbid, ctdb_dbid);
PROTOCOL_TYPE3_TEST(struct ctdb_dbid_map, ctdb_dbid_map);
PROTOCOL_TYPE3_TEST(struct ctdb_pulldb, ctdb_pulldb);
PROTOCOL_TYPE3_TEST(struct ctdb_pulldb_ext, ctdb_pulldb_ext);
PROTOCOL_TYPE3_TEST(struct ctdb_db_vacuum, ctdb_db_vacuum);
PROTOCOL_TYPE3_TEST(struct ctdb_echo_data, ctdb_echo_data);
PROTOCOL_TYPE1_TEST(struct ctdb_ltdb_header, ctdb_ltdb_header);
PROTOCOL_TYPE3_TEST(struct ctdb_rec_data, ctdb_rec_data);
PROTOCOL_TYPE3_TEST(struct ctdb_rec_buffer, ctdb_rec_buffer);
PROTOCOL_TYPE3_TEST(struct ctdb_traverse_start, ctdb_traverse_start);
PROTOCOL_TYPE3_TEST(struct ctdb_traverse_all, ctdb_traverse_all);
PROTOCOL_TYPE3_TEST(struct ctdb_traverse_start_ext, ctdb_traverse_start_ext);
PROTOCOL_TYPE3_TEST(struct ctdb_traverse_all_ext, ctdb_traverse_all_ext);
PROTOCOL_TYPE3_TEST(ctdb_sock_addr, ctdb_sock_addr);
PROTOCOL_TYPE3_TEST(struct ctdb_connection, ctdb_connection);
PROTOCOL_TYPE3_TEST(struct ctdb_connection_list, ctdb_connection_list);
PROTOCOL_TYPE3_TEST(struct ctdb_tunable, ctdb_tunable);
PROTOCOL_TYPE3_TEST(struct ctdb_node_flag_change, ctdb_node_flag_change);
PROTOCOL_TYPE3_TEST(struct ctdb_var_list, ctdb_var_list);
PROTOCOL_TYPE3_TEST(struct ctdb_tunable_list, ctdb_tunable_list);
PROTOCOL_TYPE3_TEST(struct ctdb_tickle_list, ctdb_tickle_list);
PROTOCOL_TYPE3_TEST(struct ctdb_addr_info, ctdb_addr_info);
PROTOCOL_TYPE3_TEST(struct ctdb_transdb, ctdb_transdb);
PROTOCOL_TYPE3_TEST(struct ctdb_uptime, ctdb_uptime);
PROTOCOL_TYPE3_TEST(struct ctdb_public_ip, ctdb_public_ip);
PROTOCOL_TYPE3_TEST(struct ctdb_public_ip_list, ctdb_public_ip_list);
PROTOCOL_TYPE3_TEST(struct ctdb_node_and_flags, ctdb_node_and_flags);
PROTOCOL_TYPE3_TEST(struct ctdb_node_map, ctdb_node_map);
PROTOCOL_TYPE3_TEST(struct ctdb_script, ctdb_script);
PROTOCOL_TYPE3_TEST(struct ctdb_script_list, ctdb_script_list);
PROTOCOL_TYPE3_TEST(struct ctdb_ban_state, ctdb_ban_state);
PROTOCOL_TYPE3_TEST(struct ctdb_notify_data, ctdb_notify_data);
PROTOCOL_TYPE3_TEST(struct ctdb_iface, ctdb_iface);
PROTOCOL_TYPE3_TEST(struct ctdb_iface_list, ctdb_iface_list);
PROTOCOL_TYPE3_TEST(struct ctdb_public_ip_info, ctdb_public_ip_info);
PROTOCOL_TYPE3_TEST(struct ctdb_statistics_list, ctdb_statistics_list);
PROTOCOL_TYPE3_TEST(struct ctdb_key_data, ctdb_key_data);
PROTOCOL_TYPE3_TEST(struct ctdb_db_statistics, ctdb_db_statistics);
PROTOCOL_TYPE3_TEST(struct ctdb_pid_srvid, ctdb_pid_srvid);
PROTOCOL_TYPE3_TEST(struct ctdb_election_message, ctdb_election_message);
PROTOCOL_TYPE3_TEST(struct ctdb_srvid_message, ctdb_srvid_message);
PROTOCOL_TYPE3_TEST(struct ctdb_disable_message, ctdb_disable_message);
PROTOCOL_TYPE1_TEST(struct ctdb_server_id, ctdb_server_id);
PROTOCOL_TYPE1_TEST(struct ctdb_g_lock, ctdb_g_lock);
PROTOCOL_TYPE3_TEST(struct ctdb_g_lock_list, ctdb_g_lock_list);

PROTOCOL_TYPE1_TEST(struct sock_packet_header, sock_packet_header);

static void test_ctdb_rec_buffer_read_write(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_rec_buffer *p1, **p2;
	const char *filename = "ctdb_rec_buffer_test.dat";
	int count = 100;
	int fd, i, ret;
	off_t offset;

	p1 = talloc_array(mem_ctx, struct ctdb_rec_buffer, count);
	assert(p1 != NULL);
	for (i=0; i<count; i++) {
		fill_ctdb_rec_buffer(mem_ctx, &p1[i]);
	}

	fd = open(filename, O_RDWR|O_CREAT, 0600);
	assert(fd != -1);
	unlink(filename);

	for (i=0; i<count; i++) {
		ret = ctdb_rec_buffer_write(&p1[i], fd);
		assert(ret == 0);
	}

	offset = lseek(fd, 0, SEEK_CUR);
	assert(offset != -1);
	offset = lseek(fd, -offset, SEEK_CUR);
	assert(offset == 0);

	p2 = talloc_array(mem_ctx, struct ctdb_rec_buffer *, count);
	assert(p2 != NULL);

	for (i=0; i<count; i++) {
		ret = ctdb_rec_buffer_read(fd, mem_ctx, &p2[i]);
		assert(ret == 0);
	}

	close(fd);

	for (i=0; i<count; i++) {
		verify_ctdb_rec_buffer(&p1[i], p2[i]);
	}

	talloc_free(mem_ctx);
}

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	TEST_FUNC(ctdb_tdb_data)();
	TEST_FUNC(ctdb_tdb_datan)();
	TEST_FUNC(ctdb_latency_counter)();

	TEST_FUNC(ctdb_statistics)();
	TEST_FUNC(ctdb_vnn_map)();
	TEST_FUNC(ctdb_dbid)();
	TEST_FUNC(ctdb_dbid_map)();
	TEST_FUNC(ctdb_pulldb)();
	TEST_FUNC(ctdb_pulldb_ext)();
	TEST_FUNC(ctdb_db_vacuum)();
	TEST_FUNC(ctdb_echo_data)();
	TEST_FUNC(ctdb_ltdb_header)();
	TEST_FUNC(ctdb_rec_data)();
	TEST_FUNC(ctdb_rec_buffer)();
	TEST_FUNC(ctdb_traverse_start)();
	TEST_FUNC(ctdb_traverse_all)();
	TEST_FUNC(ctdb_traverse_start_ext)();
	TEST_FUNC(ctdb_traverse_all_ext)();
	TEST_FUNC(ctdb_sock_addr)();
	TEST_FUNC(ctdb_connection)();
	TEST_FUNC(ctdb_connection_list)();
	TEST_FUNC(ctdb_tunable)();
	TEST_FUNC(ctdb_node_flag_change)();
	TEST_FUNC(ctdb_var_list)();
	TEST_FUNC(ctdb_tunable_list)();
	TEST_FUNC(ctdb_tickle_list)();
	TEST_FUNC(ctdb_addr_info)();
	TEST_FUNC(ctdb_transdb)();
	TEST_FUNC(ctdb_uptime)();
	TEST_FUNC(ctdb_public_ip)();
	TEST_FUNC(ctdb_public_ip_list)();
	TEST_FUNC(ctdb_node_and_flags)();
	TEST_FUNC(ctdb_node_map)();
	TEST_FUNC(ctdb_script)();
	TEST_FUNC(ctdb_script_list)();
	TEST_FUNC(ctdb_ban_state)();
	TEST_FUNC(ctdb_notify_data)();
	TEST_FUNC(ctdb_iface)();
	TEST_FUNC(ctdb_iface_list)();
	TEST_FUNC(ctdb_public_ip_info)();
	TEST_FUNC(ctdb_statistics_list)();
	TEST_FUNC(ctdb_key_data)();
	TEST_FUNC(ctdb_db_statistics)();
	TEST_FUNC(ctdb_pid_srvid)();
	TEST_FUNC(ctdb_election_message)();
	TEST_FUNC(ctdb_srvid_message)();
	TEST_FUNC(ctdb_disable_message)();
	TEST_FUNC(ctdb_server_id)();
	TEST_FUNC(ctdb_g_lock)();
	TEST_FUNC(ctdb_g_lock_list)();

	TEST_FUNC(sock_packet_header)();

	test_ctdb_rec_buffer_read_write();

	return 0;
}
