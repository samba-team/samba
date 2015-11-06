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
#include "system/network.h"

#include <assert.h>

#include "protocol/protocol_types.c"
#include "protocol/protocol_header.c"
#include "protocol/protocol_call.c"
#include "protocol/protocol_control.c"
#include "protocol/protocol_message.c"
#include "protocol/protocol_packet.c"

uint8_t BUFFER[1024*1024];

/*
 * Functions to generation random data
 */

static int rand_int(int max)
{
	return random() % max;
}

static uint8_t rand8(void)
{
	uint8_t val = rand_int(256) & 0xff;
	return val;
}

static uint32_t rand32(void)
{
	return random();
}

static uint64_t rand64(void)
{
	uint64_t t = random();
	t = (t << 32) | random();
	return t;
}

static double rand_double(void)
{
	return 1.0 / rand64();
}

static void fill_buffer(void *p, size_t len)
{
	int i;
	uint8_t *ptr = p;

	for (i=0; i<len; i++) {
		ptr[i] = rand8();
	}
}

static void verify_buffer(void *p1, void *p2, size_t len)
{
	if (len > 0) {
		assert(memcmp(p1, p2, len) == 0);
	}
}

/*
 * Functions to fill and verify data types
 */

static void fill_tdb_data(TALLOC_CTX *mem_ctx, TDB_DATA *p)
{
	p->dsize = rand_int(1024) + 1;
	p->dptr = talloc_array(mem_ctx, uint8_t, p->dsize);
	assert(p->dptr != NULL);
	fill_buffer(p->dptr, p->dsize);
}

static void verify_tdb_data(TDB_DATA *p1, TDB_DATA *p2)
{
	assert(p1->dsize == p2->dsize);
	verify_buffer(p1->dptr, p2->dptr, p1->dsize);
}

static void fill_ctdb_statistics(TALLOC_CTX *mem_ctx, struct ctdb_statistics *p)
{
	fill_buffer((uint8_t *)p, sizeof(struct ctdb_statistics));
}

static void verify_ctdb_statistics(struct ctdb_statistics *p1,
				   struct ctdb_statistics *p2)
{
	verify_buffer(p1, p2, sizeof(struct ctdb_statistics));
}

static void fill_ctdb_vnn_map(TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *p)
{
	int i;

	p->generation = rand32();
	p->size = rand_int(20) + 1;
	p->map = talloc_array(mem_ctx, uint32_t, p->size);
	assert(p->map != NULL);

	for (i=0; i<p->size; i++) {
		p->map[i] = rand32();
	}
}

static void verify_ctdb_vnn_map(struct ctdb_vnn_map *p1,
				struct ctdb_vnn_map *p2)
{
	int i;

	assert(p1->generation == p2->generation);
	assert(p1->size == p2->size);
	for (i=0; i<p1->size; i++) {
		assert(p1->map[i] == p2->map[i]);
	}
}

static void fill_ctdb_dbid(TALLOC_CTX *mem_ctx, struct ctdb_dbid *p)
{
	p->db_id = rand32();
	p->flags = rand8();
}

static void verify_ctdb_dbid(struct ctdb_dbid *p1, struct ctdb_dbid *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->flags == p2->flags);
}

static void fill_ctdb_dbid_map(TALLOC_CTX *mem_ctx, struct ctdb_dbid_map *p)
{
	int i;

	p->num = rand_int(40) + 1;
	p->dbs = talloc_array(mem_ctx, struct ctdb_dbid, p->num);
	assert(p->dbs != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_dbid(mem_ctx, &p->dbs[i]);
	}
}

static void verify_ctdb_dbid_map(struct ctdb_dbid_map *p1,
				 struct ctdb_dbid_map *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_dbid(&p1->dbs[i], &p2->dbs[i]);
	}
}

static void fill_ctdb_pulldb(TALLOC_CTX *mem_ctx, struct ctdb_pulldb *p)
{
	p->db_id = rand32();
	p->lmaster = rand32();
}

static void verify_ctdb_pulldb(struct ctdb_pulldb *p1, struct ctdb_pulldb *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->lmaster == p2->lmaster);
}

static void fill_ctdb_ltdb_header(TALLOC_CTX *mem_ctx,
				  struct ctdb_ltdb_header *p)
{
	p->rsn = rand64();
	p->dmaster = rand32();
	p->flags = rand32();
}

static void verify_ctdb_ltdb_header(struct ctdb_ltdb_header *p1,
				    struct ctdb_ltdb_header *p2)
{
	assert(p1->rsn == p2->rsn);
	assert(p1->dmaster == p2->dmaster);
	assert(p1->flags == p2->flags);
}

static void fill_ctdb_rec_data(TALLOC_CTX *mem_ctx, struct ctdb_rec_data *p)
{
	p->reqid = rand32();
	if (p->reqid % 5 == 0) {
		p->header = talloc(mem_ctx, struct ctdb_ltdb_header);
		assert(p->header != NULL);
		fill_ctdb_ltdb_header(mem_ctx, p->header);
	} else {
		p->header = NULL;
	}
	fill_tdb_data(mem_ctx, &p->key);
	fill_tdb_data(mem_ctx, &p->data);
}

static void verify_ctdb_rec_data(struct ctdb_rec_data *p1,
				 struct ctdb_rec_data *p2)
{
	struct ctdb_ltdb_header header;

	assert(p1->reqid == p2->reqid);
	if (p1->header != NULL) {
		assert(ctdb_ltdb_header_extract(&p2->data, &header) == 0);
		verify_ctdb_ltdb_header(p1->header, &header);
	}
	verify_tdb_data(&p1->key, &p2->key);
	verify_tdb_data(&p1->data, &p2->data);
}

static void fill_ctdb_rec_buffer(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *p)
{
	struct ctdb_rec_data rec;
	int ret, i;
	int count;

	p->db_id = rand32();
	p->count = 0;
	p->buf = NULL;
	p->buflen = 0;

	count = rand_int(100) + 1;
	for (i=0; i<count; i++) {
		fill_ctdb_rec_data(mem_ctx, &rec);
		ret = ctdb_rec_buffer_add(mem_ctx, p, rec.reqid, rec.header,
					  rec.key, rec.data);
		assert(ret == 0);
	}
}

static void verify_ctdb_rec_buffer(struct ctdb_rec_buffer *p1,
				   struct ctdb_rec_buffer *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->count == p2->count);
	assert(p1->buflen == p2->buflen);
	verify_buffer(p1->buf, p2->buf, p1->buflen);
}

static void fill_ctdb_traverse_start(TALLOC_CTX *mem_ctx,
				     struct ctdb_traverse_start *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->srvid = rand64();
}

static void verify_ctdb_traverse_start(struct ctdb_traverse_start *p1,
				       struct ctdb_traverse_start *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->srvid == p2->srvid);
}

static void fill_ctdb_traverse_all(TALLOC_CTX *mem_ctx,
				   struct ctdb_traverse_all *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->pnn = rand32();
	p->client_reqid = rand32();
	p->srvid = rand64();
}

static void verify_ctdb_traverse_all(struct ctdb_traverse_all *p1,
				     struct ctdb_traverse_all *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->pnn == p2->pnn);
	assert(p1->client_reqid == p2->client_reqid);
	assert(p1->srvid == p2->srvid);
}

static void fill_ctdb_traverse_start_ext(TALLOC_CTX *mem_ctx,
					 struct ctdb_traverse_start_ext *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->srvid = rand64();
	p->withemptyrecords = rand_int(2);
}

static void verify_ctdb_traverse_start_ext(struct ctdb_traverse_start_ext *p1,
					   struct ctdb_traverse_start_ext *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->srvid == p2->srvid);
	assert(p1->withemptyrecords == p2->withemptyrecords);
}

static void fill_ctdb_traverse_all_ext(TALLOC_CTX *mem_ctx,
				       struct ctdb_traverse_all_ext *p)
{
	p->db_id = rand32();
	p->reqid = rand32();
	p->pnn = rand32();
	p->client_reqid = rand32();
	p->srvid = rand64();
	p->withemptyrecords = rand_int(2);
}

static void verify_ctdb_traverse_all_ext(struct ctdb_traverse_all_ext *p1,
					 struct ctdb_traverse_all_ext *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->reqid == p2->reqid);
	assert(p1->pnn == p2->pnn);
	assert(p1->client_reqid == p2->client_reqid);
	assert(p1->srvid == p2->srvid);
	assert(p1->withemptyrecords == p2->withemptyrecords);
}

static void fill_ctdb_sock_addr(TALLOC_CTX *mem_ctx, ctdb_sock_addr *p)
{
	if (rand_int(2) == 0) {
		p->ip.sin_family = AF_INET;
		p->ip.sin_port = rand_int(65535);
		fill_buffer(&p->ip.sin_addr, sizeof(struct in_addr));
	} else {
		p->ip6.sin6_family = AF_INET6;
		p->ip6.sin6_port = rand_int(65535);
		fill_buffer(&p->ip6.sin6_addr, sizeof(struct in6_addr));
	}
}

static void verify_ctdb_sock_addr(ctdb_sock_addr *p1, ctdb_sock_addr *p2)
{
	assert(p1->sa.sa_family == p2->sa.sa_family);
	if (p1->sa.sa_family == AF_INET) {
		assert(p1->ip.sin_port == p2->ip.sin_port);
		verify_buffer(&p1->ip.sin_addr, &p2->ip.sin_addr,
				   sizeof(struct in_addr));
	} else {
		assert(p1->ip6.sin6_port == p2->ip6.sin6_port);
		verify_buffer(&p1->ip6.sin6_addr, &p2->ip6.sin6_addr,
				   sizeof(struct in6_addr));
	}
}

static void fill_ctdb_connection(TALLOC_CTX *mem_ctx,
				 struct ctdb_connection *p)
{
	fill_ctdb_sock_addr(mem_ctx, &p->src);
	fill_ctdb_sock_addr(mem_ctx, &p->dst);
}

static void verify_ctdb_connection(struct ctdb_connection *p1,
				   struct ctdb_connection *p2)
{
	verify_ctdb_sock_addr(&p1->src, &p2->src);
	verify_ctdb_sock_addr(&p1->dst, &p2->dst);
}

static void fill_ctdb_string(TALLOC_CTX *mem_ctx, const char **out)
{
	char *p;
	int len, i;

	len = rand_int(1024) + 1;
	p = talloc_size(mem_ctx, len+1);
	assert(p != NULL);

	for (i=0; i<len; i++) {
		p[i] = 'A' + rand_int(26);
	}
	p[len] = '\0';
	*out = p;
}

static void verify_ctdb_string(const char *p1, const char *p2)
{
	if (p1 == NULL || p2 == NULL) {
		assert(p1 == p2);
	} else {
		assert(strlen(p1) == strlen(p2));
		assert(strcmp(p1, p2) == 0);
	}
}

static void fill_ctdb_tunable(TALLOC_CTX *mem_ctx, struct ctdb_tunable *p)
{
	fill_ctdb_string(mem_ctx, discard_const(&p->name));
	p->value = rand32();
}

static void verify_ctdb_tunable(struct ctdb_tunable *p1,
				struct ctdb_tunable *p2)
{
	verify_ctdb_string(discard_const(p1->name), discard_const(p2->name));
	assert(p1->value == p2->value);
}

static void fill_ctdb_node_flag_change(TALLOC_CTX *mem_ctx,
				       struct ctdb_node_flag_change *p)
{
	p->pnn = rand32();
	p->new_flags = rand32();
	p->old_flags = rand32();
}

static void verify_ctdb_node_flag_change(struct ctdb_node_flag_change *p1,
					 struct ctdb_node_flag_change *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->new_flags == p2->new_flags);
	assert(p1->old_flags == p2->old_flags);
}

static void fill_ctdb_var_list(TALLOC_CTX *mem_ctx,
			       struct ctdb_var_list *p)
{
	int i;

	p->count = rand_int(100) + 1;
	p->var = talloc_array(mem_ctx, const char *, p->count);
	for (i=0; i<p->count; i++) {
		fill_ctdb_string(p->var, discard_const(&p->var[i]));
	}
}

static void verify_ctdb_var_list(struct ctdb_var_list *p1,
				 struct ctdb_var_list *p2)
{
	int i;

	assert(p1->count == p2->count);
	for (i=0; i<p1->count; i++) {
		verify_ctdb_string(discard_const(p1->var[i]),
				   discard_const(p2->var[i]));
	}
}

static void fill_ctdb_tunable_list(TALLOC_CTX *mem_ctx,
				   struct ctdb_tunable_list *p)
{
	fill_buffer(p, sizeof(struct ctdb_tunable_list));
}

static void verify_ctdb_tunable_list(struct ctdb_tunable_list *p1,
				     struct ctdb_tunable_list *p2)
{
	verify_buffer(p1, p2, sizeof(struct ctdb_tunable_list));
}

static void fill_ctdb_tickle_list(TALLOC_CTX *mem_ctx,
				  struct ctdb_tickle_list *p)
{
	int i;

	fill_ctdb_sock_addr(mem_ctx, &p->addr);
	p->num = rand_int(1000) + 1;
	p->conn = talloc_array(mem_ctx, struct ctdb_connection, p->num);
	assert(p->conn != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_connection(mem_ctx, &p->conn[i]);
	}
}

static void verify_ctdb_tickle_list(struct ctdb_tickle_list *p1,
				    struct ctdb_tickle_list *p2)
{
	int i;

	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_connection(&p1->conn[i], &p2->conn[i]);
	}
}

static void fill_ctdb_client_id(TALLOC_CTX *mem_ctx,
				struct ctdb_client_id *p)
{
	p->type = rand8();
	p->pnn = rand32();
	p->server_id = rand32();
}

static void verify_ctdb_client_id(struct ctdb_client_id *p1,
				  struct ctdb_client_id *p2)
{
	assert(p1->type == p2->type);
	assert(p1->pnn == p2->pnn);
	assert(p1->server_id == p2->server_id);
}

static void fill_ctdb_client_id_list(TALLOC_CTX *mem_ctx,
				     struct ctdb_client_id_list *p)
{
	int i;

	p->num = rand_int(1000) + 1;
	p->cid = talloc_array(mem_ctx, struct ctdb_client_id, p->num);
	assert(p->cid != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_client_id(mem_ctx, &p->cid[i]);
	}
}

static void verify_ctdb_client_id_list(struct ctdb_client_id_list *p1,
				       struct ctdb_client_id_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_client_id(&p1->cid[i], &p2->cid[i]);
	}
}

static void fill_ctdb_client_id_map(TALLOC_CTX *mem_ctx,
				    struct ctdb_client_id_map *p)
{
	int i;

	p->count = rand_int(10) + 1;
	p->list = talloc_array(mem_ctx, struct ctdb_client_id_list, p->count);
	assert(p->list != NULL);
	for (i=0; i<p->count; i++) {
		fill_ctdb_client_id_list(mem_ctx, &p->list[i]);
	}
}

static void verify_ctdb_client_id_map(struct ctdb_client_id_map *p1,
				      struct ctdb_client_id_map *p2)
{
	int i;

	assert(p1->count == p2->count);
	for (i=0; i<p1->count; i++) {
		verify_ctdb_client_id_list(&p1->list[i], &p2->list[i]);
	}
}

static void fill_ctdb_addr_info(TALLOC_CTX *mem_ctx, struct ctdb_addr_info *p)
{
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
	p->mask = rand_int(33);
	if (rand_int(2) == 0) {
		p->iface = NULL;
	} else {
		fill_ctdb_string(mem_ctx, &p->iface);
	}
}

static void verify_ctdb_addr_info(struct ctdb_addr_info *p1,
				  struct ctdb_addr_info *p2)
{
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
	assert(p1->mask == p2->mask);
	verify_ctdb_string(p1->iface, p2->iface);
}

static void fill_ctdb_transdb(TALLOC_CTX *mem_ctx, struct ctdb_transdb *p)
{
	p->db_id = rand32();
	p->tid = rand32();
}

static void verify_ctdb_transdb(struct ctdb_transdb *p1, struct ctdb_transdb *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->tid == p2->tid);
}

static void fill_ctdb_uptime(TALLOC_CTX *mem_ctx, struct ctdb_uptime *p)
{
	fill_buffer(p, sizeof(struct ctdb_uptime));
}

static void verify_ctdb_uptime(struct ctdb_uptime *p1, struct ctdb_uptime *p2)
{
	verify_buffer(p1, p2, sizeof(struct ctdb_uptime));
}

static void fill_ctdb_public_ip(TALLOC_CTX *mem_ctx, struct ctdb_public_ip *p)
{
	p->pnn = rand32();
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
}

static void verify_ctdb_public_ip(struct ctdb_public_ip *p1,
				  struct ctdb_public_ip *p2)
{
	assert(p1->pnn == p2->pnn);
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
}

static void fill_ctdb_public_ip_list(TALLOC_CTX *mem_ctx,
				     struct ctdb_public_ip_list *p)
{
	int i;

	p->num = rand_int(32);
	if (p->num == 0) {
		p->ip = NULL;
		return;
	}
	p->ip = talloc_array(mem_ctx, struct ctdb_public_ip, p->num);
	assert(p->ip != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_public_ip(mem_ctx, &p->ip[i]);
	}
}

static void verify_ctdb_public_ip_list(struct ctdb_public_ip_list *p1,
				       struct ctdb_public_ip_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_public_ip(&p1->ip[i], &p2->ip[i]);
	}
}

static void fill_ctdb_node_and_flags(TALLOC_CTX *mem_ctx,
				     struct ctdb_node_and_flags *p)
{
	p->pnn = rand32();
	p->flags = rand32();
	fill_ctdb_sock_addr(mem_ctx, &p->addr);
}

static void verify_ctdb_node_and_flags(struct ctdb_node_and_flags *p1,
				       struct ctdb_node_and_flags *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->flags == p2->flags);
	verify_ctdb_sock_addr(&p1->addr, &p2->addr);
}

static void fill_ctdb_node_map(TALLOC_CTX *mem_ctx, struct ctdb_node_map *p)
{
	int i;

	p->num = rand_int(32) + 1;
	p->node = talloc_array(mem_ctx, struct ctdb_node_and_flags, p->num);
	assert(p->node != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_node_and_flags(mem_ctx, &p->node[i]);
	}
}

static void verify_ctdb_node_map(struct ctdb_node_map *p1,
				 struct ctdb_node_map *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_node_and_flags(&p1->node[i], &p2->node[i]);
	}
}

static void fill_ctdb_script(TALLOC_CTX *mem_ctx, struct ctdb_script *p)
{
	fill_buffer(p, sizeof(struct ctdb_script));
}

static void verify_ctdb_script(struct ctdb_script *p1, struct ctdb_script *p2)
{
	verify_buffer(p1, p2, sizeof(struct ctdb_script));
}

static void fill_ctdb_script_list(TALLOC_CTX *mem_ctx,
				  struct ctdb_script_list *p)
{
	int i;

	p->num_scripts = rand_int(32) + 1;
	p->script = talloc_array(mem_ctx, struct ctdb_script, p->num_scripts);
	assert(p->script != NULL);
	for (i=0; i<p->num_scripts; i++) {
		fill_ctdb_script(mem_ctx, &p->script[i]);
	}
}

static void verify_ctdb_script_list(struct ctdb_script_list *p1,
				    struct ctdb_script_list *p2)
{
	int i;

	assert(p1->num_scripts == p2->num_scripts);
	for (i=0; i<p1->num_scripts; i++) {
		verify_ctdb_script(&p1->script[i], &p2->script[i]);
	}
}

static void fill_ctdb_ban_state(TALLOC_CTX *mem_ctx, struct ctdb_ban_state *p)
{
	p->pnn = rand32();
	p->time = rand32();
}

static void verify_ctdb_ban_state(struct ctdb_ban_state *p1,
				  struct ctdb_ban_state *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->time == p2->time);
}

static void fill_ctdb_db_priority(TALLOC_CTX *mem_ctx,
				  struct ctdb_db_priority *p)
{
	p->db_id = rand32();
	p->priority = rand32();
}

static void verify_ctdb_db_priority(struct ctdb_db_priority *p1,
				    struct ctdb_db_priority *p2)
{
	assert(p1->db_id == p2->db_id);
	assert(p1->priority == p2->priority);
}

static void fill_ctdb_notify_data(TALLOC_CTX *mem_ctx,
				  struct ctdb_notify_data *p)
{
	p->srvid = rand64();
	fill_tdb_data(mem_ctx, &p->data);
}

static void verify_ctdb_notify_data(struct ctdb_notify_data *p1,
				    struct ctdb_notify_data *p2)
{
	assert(p1->srvid == p2->srvid);
	verify_tdb_data(&p1->data, &p2->data);
}

static void fill_ctdb_iface(TALLOC_CTX *mem_ctx, struct ctdb_iface *p)
{
	fill_buffer(p, sizeof(struct ctdb_iface));
}

static void verify_ctdb_iface(struct ctdb_iface *p1, struct ctdb_iface *p2)
{
	verify_buffer(p1, p2, sizeof(struct ctdb_iface));
}

static void fill_ctdb_iface_list(TALLOC_CTX *mem_ctx,
				 struct ctdb_iface_list *p)
{
	int i;

	p->num = rand_int(32) + 1;
	p->iface = talloc_array(mem_ctx, struct ctdb_iface, p->num);
	assert(p->iface != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_iface(mem_ctx, &p->iface[i]);
	}
}

static void verify_ctdb_iface_list(struct ctdb_iface_list *p1,
				   struct ctdb_iface_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_iface(&p1->iface[i], &p2->iface[i]);
	}
}

static void fill_ctdb_public_ip_info(TALLOC_CTX *mem_ctx,
				     struct ctdb_public_ip_info *p)
{
	fill_ctdb_public_ip(mem_ctx, &p->ip);
	p->active_idx = rand_int(32) + 1;
	p->ifaces = talloc(mem_ctx, struct ctdb_iface_list);
	assert(p->ifaces != NULL);
	fill_ctdb_iface_list(mem_ctx, p->ifaces);
}

static void verify_ctdb_public_ip_info(struct ctdb_public_ip_info *p1,
				       struct ctdb_public_ip_info *p2)
{
	verify_ctdb_public_ip(&p1->ip, &p2->ip);
	assert(p1->active_idx == p2->active_idx);
	verify_ctdb_iface_list(p1->ifaces, p2->ifaces);
}

static void fill_ctdb_statistics_list(TALLOC_CTX *mem_ctx,
				      struct ctdb_statistics_list *p)
{
	int i;

	p->num = rand_int(10) + 1;
	p->stats = talloc_array(mem_ctx, struct ctdb_statistics, p->num);
	assert(p->stats != NULL);

	for (i=0; i<p->num; i++) {
		fill_ctdb_statistics(mem_ctx, &p->stats[i]);
	}
}

static void verify_ctdb_statistics_list(struct ctdb_statistics_list *p1,
					struct ctdb_statistics_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_statistics(&p1->stats[i], &p2->stats[i]);
	}
}

static void fill_ctdb_key_data(TALLOC_CTX *mem_ctx, struct ctdb_key_data *p)
{
	p->db_id = rand32();
	fill_ctdb_ltdb_header(mem_ctx, &p->header);
	fill_tdb_data(mem_ctx, &p->key);
}

static void verify_ctdb_key_data(struct ctdb_key_data *p1,
				 struct ctdb_key_data *p2)
{
	assert(p1->db_id == p2->db_id);
	verify_ctdb_ltdb_header(&p1->header, &p2->header);
	verify_tdb_data(&p1->key, &p2->key);
}

static void fill_ctdb_uint8_array(TALLOC_CTX *mem_ctx,
				  struct ctdb_uint8_array *p)
{
	int i;

	p->num = rand_int(1024) + 1;
	p->val = talloc_array(mem_ctx, uint8_t, p->num);
	assert(p->val != NULL);

	for (i=0; i<p->num; i++) {
		p->val[i] = rand8();
	}
}

static void verify_ctdb_uint8_array(struct ctdb_uint8_array *p1,
				    struct ctdb_uint8_array *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		assert(p1->val[i] == p2->val[i]);
	}
}

static void fill_ctdb_uint64_array(TALLOC_CTX *mem_ctx,
				   struct ctdb_uint64_array *p)
{
	int i;

	p->num = rand_int(1024) + 1;
	p->val = talloc_array(mem_ctx, uint64_t, p->num);
	assert(p->val != NULL);

	for (i=0; i<p->num; i++) {
		p->val[i] = rand64();
	}
}

static void verify_ctdb_uint64_array(struct ctdb_uint64_array *p1,
				     struct ctdb_uint64_array *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		assert(p1->val[i] == p2->val[i]);
	}
}

static void fill_ctdb_db_statistics(TALLOC_CTX *mem_ctx,
				   struct ctdb_db_statistics *p)
{
	int i;

	fill_buffer(p, offsetof(struct ctdb_db_statistics, num_hot_keys));
	p->num_hot_keys = 10;
	for (i=0; i<p->num_hot_keys; i++) {
		p->hot_keys[i].count = rand32();
		fill_tdb_data(mem_ctx, &p->hot_keys[i].key);
	}
}

static void verify_ctdb_db_statistics(struct ctdb_db_statistics *p1,
				      struct ctdb_db_statistics *p2)
{
	int i;

	verify_buffer(p1, p2, offsetof(struct ctdb_db_statistics,
					    num_hot_keys));
	assert(p1->num_hot_keys == p2->num_hot_keys);
	for (i=0; i<p1->num_hot_keys; i++) {
		assert(p1->hot_keys[i].count == p2->hot_keys[i].count);
		verify_tdb_data(&p1->hot_keys[i].key, &p2->hot_keys[i].key);
	}
}

#ifndef PROTOCOL_TEST

static void fill_ctdb_election_message(TALLOC_CTX *mem_ctx,
				       struct ctdb_election_message *p)
{
	p->num_connected = rand_int(32);
	fill_buffer(&p->priority_time, sizeof(struct timeval));
	p->pnn = rand_int(32);
	p->node_flags = rand32();
}

static void verify_ctdb_election_message(struct ctdb_election_message *p1,
					 struct ctdb_election_message *p2)
{
	assert(p1->num_connected == p2->num_connected);
	verify_buffer(p1, p2, sizeof(struct timeval));
	assert(p1->pnn == p2->pnn);
	assert(p1->node_flags == p2->node_flags);
}

static void fill_ctdb_srvid_message(TALLOC_CTX *mem_ctx,
				    struct ctdb_srvid_message *p)
{
	p->pnn = rand_int(32);
	p->srvid = rand64();
}

static void verify_ctdb_srvid_message(struct ctdb_srvid_message *p1,
				      struct ctdb_srvid_message *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->srvid == p2->srvid);
}

static void fill_ctdb_disable_message(TALLOC_CTX *mem_ctx,
				      struct ctdb_disable_message *p)
{
	p->pnn = rand_int(32);
	p->srvid = rand64();
	p->timeout = rand32();
}

static void verify_ctdb_disable_message(struct ctdb_disable_message *p1,
					struct ctdb_disable_message *p2)
{
	assert(p1->pnn == p2->pnn);
	assert(p1->srvid == p2->srvid);
	assert(p1->timeout == p2->timeout);
}

static void fill_ctdb_server_id(TALLOC_CTX *mem_ctx,
				struct ctdb_server_id *p)
{
	p->pid = rand64();
	p->task_id = rand32();
	p->vnn = rand_int(32);
	p->unique_id = rand64();
}

static void verify_ctdb_server_id(struct ctdb_server_id *p1,
				  struct ctdb_server_id *p2)
{
	assert(p1->pid == p2->pid);
	assert(p1->task_id == p2->task_id);
	assert(p1->vnn == p2->vnn);
	assert(p1->unique_id == p2->unique_id);
}

static void fill_ctdb_g_lock(TALLOC_CTX *mem_ctx, struct ctdb_g_lock *p)
{
	p->type = rand_int(2);
	fill_ctdb_server_id(mem_ctx, &p->sid);
}

static void verify_ctdb_g_lock(struct ctdb_g_lock *p1, struct ctdb_g_lock *p2)
{
	assert(p1->type == p2->type);
	verify_ctdb_server_id(&p1->sid, &p2->sid);
}

static void fill_ctdb_g_lock_list(TALLOC_CTX *mem_ctx,
				  struct ctdb_g_lock_list *p)
{
	int i;

	p->num = rand_int(20) + 1;
	p->lock = talloc_array(mem_ctx, struct ctdb_g_lock, p->num);
	assert(p->lock != NULL);
	for (i=0; i<p->num; i++) {
		fill_ctdb_g_lock(mem_ctx, &p->lock[i]);
	}
}

static void verify_ctdb_g_lock_list(struct ctdb_g_lock_list *p1,
				    struct ctdb_g_lock_list *p2)
{
	int i;

	assert(p1->num == p2->num);
	for (i=0; i<p1->num; i++) {
		verify_ctdb_g_lock(&p1->lock[i], &p2->lock[i]);
	}
}

/*
 * Functions to test marshalling routines
 */

static void test_ctdb_uint32(void)
{
	uint32_t p1, p2;
	size_t buflen;
	int ret;

	p1 = rand32();
	buflen = ctdb_uint32_len(p1);
	ctdb_uint32_push(p1, BUFFER);
	ret = ctdb_uint32_pull(BUFFER, buflen, NULL, &p2);
	assert(ret == 0);
	assert(p1 == p2);
}

static void test_ctdb_uint64(void)
{
	uint64_t p1, p2;
	size_t buflen;
	int ret;

	p1 = rand64();
	buflen = ctdb_uint64_len(p1);
	ctdb_uint64_push(p1, BUFFER);
	ret = ctdb_uint64_pull(BUFFER, buflen, NULL, &p2);
	assert(ret == 0);
	assert(p1 == p2);
}

static void test_ctdb_double(void)
{
	double p1, p2;
	size_t buflen;
	int ret;

	p1 = rand_double();
	buflen = ctdb_double_len(p1);
	ctdb_double_push(p1, BUFFER);
	ret = ctdb_double_pull(BUFFER, buflen, NULL, &p2);
	assert(ret == 0);
	assert(p1 == p2);
}

static void test_ctdb_pid(void)
{
	pid_t p1, p2;
	size_t buflen;
	int ret;

	p1 = rand32();
	buflen = ctdb_pid_len(p1);
	ctdb_pid_push(p1, BUFFER);
	ret = ctdb_pid_pull(BUFFER, buflen, NULL, &p2);
	assert(ret == 0);
	assert(p1 == p2);
}

#define TEST_FUNC(NAME)		test_ ##NAME
#define FILL_FUNC(NAME)		fill_ ##NAME
#define VERIFY_FUNC(NAME)	verify_ ##NAME
#define LEN_FUNC(NAME)		NAME## _len
#define PUSH_FUNC(NAME)		NAME## _push
#define PULL_FUNC(NAME)		NAME## _pull

#define DEFINE_TEST(TYPE, NAME)	\
static void TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx = talloc_new(NULL); \
	TYPE *p1, *p2; \
	size_t buflen; \
	int ret; \
\
	p1 = talloc_zero(mem_ctx, TYPE); \
	assert(p1 != NULL); \
	FILL_FUNC(NAME)(p1, p1); \
	buflen = LEN_FUNC(NAME)(p1); \
	PUSH_FUNC(NAME)(p1, BUFFER); \
	ret = PULL_FUNC(NAME)(BUFFER, buflen, mem_ctx, &p2); \
	assert(ret == 0); \
	VERIFY_FUNC(NAME)(p1, p2); \
	talloc_free(mem_ctx); \
}


static void test_ctdb_string(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char *p1, *p2;
	size_t buflen;
	int ret;

	fill_ctdb_string(mem_ctx, &p1);
	buflen = ctdb_string_len(p1);
	ctdb_string_push(p1, BUFFER);
	ret = ctdb_string_pull(BUFFER, buflen, mem_ctx, &p2);
	assert(ret == 0);
	verify_ctdb_string(p1, p2);
	talloc_free(mem_ctx);
}

static void test_ctdb_stringn(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char *p1, *p2;
	size_t buflen;
	int ret;

	fill_ctdb_string(mem_ctx, &p1);
	buflen = ctdb_stringn_len(p1);
	ctdb_stringn_push(p1, BUFFER);
	ret = ctdb_stringn_pull(BUFFER, buflen, mem_ctx, &p2);
	assert(ret == 0);
	verify_ctdb_string(p1, p2);
	talloc_free(mem_ctx);
}

static void test_ctdb_ltdb_header(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_ltdb_header p1, p2;
	size_t buflen;
	int ret;

	fill_ctdb_ltdb_header(mem_ctx, &p1);
	buflen = ctdb_ltdb_header_len(&p1);
	ctdb_ltdb_header_push(&p1, BUFFER);
	ret = ctdb_ltdb_header_pull(BUFFER, buflen, &p2);
	assert(ret == 0);
	verify_ctdb_ltdb_header(&p1, &p2);
	talloc_free(mem_ctx);
}

static void test_ctdb_g_lock(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_g_lock p1, p2;
	size_t buflen;
	int ret;

	fill_ctdb_g_lock(mem_ctx, &p1);
	buflen = ctdb_g_lock_len(&p1);
	ctdb_g_lock_push(&p1, BUFFER);
	ret = ctdb_g_lock_pull(BUFFER, buflen, &p2);
	assert(ret == 0);
	verify_ctdb_g_lock(&p1, &p2);
	talloc_free(mem_ctx);
}

DEFINE_TEST(struct ctdb_statistics, ctdb_statistics);
DEFINE_TEST(struct ctdb_vnn_map, ctdb_vnn_map);
DEFINE_TEST(struct ctdb_dbid_map, ctdb_dbid_map);
DEFINE_TEST(struct ctdb_pulldb, ctdb_pulldb);
DEFINE_TEST(struct ctdb_rec_data, ctdb_rec_data);
DEFINE_TEST(struct ctdb_rec_buffer, ctdb_rec_buffer);
DEFINE_TEST(struct ctdb_traverse_start, ctdb_traverse_start);
DEFINE_TEST(struct ctdb_traverse_all, ctdb_traverse_all);
DEFINE_TEST(struct ctdb_traverse_start_ext, ctdb_traverse_start_ext);
DEFINE_TEST(struct ctdb_traverse_all_ext, ctdb_traverse_all_ext);
DEFINE_TEST(ctdb_sock_addr, ctdb_sock_addr);
DEFINE_TEST(struct ctdb_connection, ctdb_connection);
DEFINE_TEST(struct ctdb_tunable, ctdb_tunable);
DEFINE_TEST(struct ctdb_node_flag_change, ctdb_node_flag_change);
DEFINE_TEST(struct ctdb_var_list, ctdb_var_list);
DEFINE_TEST(struct ctdb_tunable_list, ctdb_tunable_list);
DEFINE_TEST(struct ctdb_tickle_list, ctdb_tickle_list);
DEFINE_TEST(struct ctdb_client_id, ctdb_client_id);
DEFINE_TEST(struct ctdb_client_id_list, ctdb_client_id_list);
DEFINE_TEST(struct ctdb_client_id_map, ctdb_client_id_map);
DEFINE_TEST(struct ctdb_addr_info, ctdb_addr_info);
DEFINE_TEST(struct ctdb_transdb, ctdb_transdb);
DEFINE_TEST(struct ctdb_uptime, ctdb_uptime);
DEFINE_TEST(struct ctdb_public_ip, ctdb_public_ip);
DEFINE_TEST(struct ctdb_public_ip_list, ctdb_public_ip_list);
DEFINE_TEST(struct ctdb_node_and_flags, ctdb_node_and_flags);
DEFINE_TEST(struct ctdb_node_map, ctdb_node_map);
DEFINE_TEST(struct ctdb_script, ctdb_script);
DEFINE_TEST(struct ctdb_script_list, ctdb_script_list);
DEFINE_TEST(struct ctdb_ban_state, ctdb_ban_state);
DEFINE_TEST(struct ctdb_db_priority, ctdb_db_priority);
DEFINE_TEST(struct ctdb_notify_data, ctdb_notify_data);
DEFINE_TEST(struct ctdb_iface, ctdb_iface);
DEFINE_TEST(struct ctdb_iface_list, ctdb_iface_list);
DEFINE_TEST(struct ctdb_public_ip_info, ctdb_public_ip_info);
DEFINE_TEST(struct ctdb_statistics_list, ctdb_statistics_list);
DEFINE_TEST(struct ctdb_key_data, ctdb_key_data);
DEFINE_TEST(struct ctdb_uint8_array, ctdb_uint8_array);
DEFINE_TEST(struct ctdb_uint64_array, ctdb_uint64_array);
DEFINE_TEST(struct ctdb_db_statistics, ctdb_db_statistics);
DEFINE_TEST(struct ctdb_election_message, ctdb_election_message);
DEFINE_TEST(struct ctdb_srvid_message, ctdb_srvid_message);
DEFINE_TEST(struct ctdb_disable_message, ctdb_disable_message);
DEFINE_TEST(struct ctdb_g_lock_list, ctdb_g_lock_list);

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	test_ctdb_uint32();
	test_ctdb_uint64();
	test_ctdb_double();
	test_ctdb_pid();

	test_ctdb_string();
	test_ctdb_stringn();

	test_ctdb_ltdb_header();
	test_ctdb_g_lock();

	TEST_FUNC(ctdb_statistics)();
	TEST_FUNC(ctdb_vnn_map)();
	TEST_FUNC(ctdb_dbid_map)();
	TEST_FUNC(ctdb_pulldb)();
	TEST_FUNC(ctdb_rec_data)();
	TEST_FUNC(ctdb_rec_buffer)();
	TEST_FUNC(ctdb_traverse_start)();
	TEST_FUNC(ctdb_traverse_all)();
	TEST_FUNC(ctdb_traverse_start_ext)();
	TEST_FUNC(ctdb_traverse_all_ext)();
	TEST_FUNC(ctdb_sock_addr)();
	TEST_FUNC(ctdb_connection)();
	TEST_FUNC(ctdb_tunable)();
	TEST_FUNC(ctdb_node_flag_change)();
	TEST_FUNC(ctdb_var_list)();
	TEST_FUNC(ctdb_tunable_list)();
	TEST_FUNC(ctdb_tickle_list)();
	TEST_FUNC(ctdb_client_id)();
	TEST_FUNC(ctdb_client_id_list)();
	TEST_FUNC(ctdb_client_id_map)();
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
	TEST_FUNC(ctdb_db_priority)();
	TEST_FUNC(ctdb_notify_data)();
	TEST_FUNC(ctdb_iface)();
	TEST_FUNC(ctdb_iface_list)();
	TEST_FUNC(ctdb_public_ip_info)();
	TEST_FUNC(ctdb_statistics_list)();
	TEST_FUNC(ctdb_key_data)();
	TEST_FUNC(ctdb_uint8_array)();
	TEST_FUNC(ctdb_uint64_array)();
	TEST_FUNC(ctdb_db_statistics)();
	TEST_FUNC(ctdb_election_message)();
	TEST_FUNC(ctdb_srvid_message)();
	TEST_FUNC(ctdb_disable_message)();
	TEST_FUNC(ctdb_g_lock_list)();

	return 0;
}

#endif
