/*
   Misc control routines of libctdb

   Copyright (C) Rusty Russell 2010

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
#include <sys/socket.h>
#include <string.h>
#include <ctdb.h>
#include <ctdb_protocol.h>
#include "libctdb_private.h"

/* Remove type-safety macros. */
#undef ctdb_getrecmaster_send
#undef ctdb_getrecmode_send
#undef ctdb_getpnn_send
#undef ctdb_getdbstat_send
#undef ctdb_check_message_handlers_send
#undef ctdb_getnodemap_send
#undef ctdb_getpublicips_send
#undef ctdb_getdbseqnum_send
#undef ctdb_getifaces_send
#undef ctdb_getvnnmap_send
#undef ctdb_getcapabilities_send

bool ctdb_getrecmaster_recv(struct ctdb_connection *ctdb,
			   struct ctdb_request *req, uint32_t *recmaster)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_RECMASTER);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getrecmaster_recv: status -1");
		return false;
	}
	*recmaster = reply->status;
	return true;
}

struct ctdb_request *ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_RECMASTER,
					destnode, NULL, 0,
					callback, private_data);
}

bool ctdb_getrecmode_recv(struct ctdb_connection *ctdb,
			  struct ctdb_request *req, uint32_t *recmode)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_RECMODE);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getrecmode_recv: status -1");
		return false;
	}
	*recmode = reply->status;
	return true;
}

struct ctdb_request *ctdb_getrecmode_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_RECMODE,
					destnode, NULL, 0,
					callback, private_data);
}

bool ctdb_getpnn_recv(struct ctdb_connection *ctdb,
		     struct ctdb_request *req, uint32_t *pnn)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_PNN);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpnn_recv: status -1");
		return false;
	}
	*pnn = reply->status;
	return true;
}

struct ctdb_request *ctdb_getpnn_send(struct ctdb_connection *ctdb,
				      uint32_t destnode,
				      ctdb_callback_t callback,
				      void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PNN, destnode,
					NULL, 0, callback, private_data);
}

bool ctdb_getdbstat_recv(struct ctdb_connection *ctdb,
			 struct ctdb_request *req,
			 struct ctdb_db_statistics **stat)
{
	struct ctdb_reply_control *reply;
	struct ctdb_db_statistics *s;
	struct ctdb_db_statistics_wire *wire;
	int i;
	char *ptr;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_DB_STATISTICS);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpnn_recv: status -1");
		return false;
	}
	if (reply->datalen < offsetof(struct ctdb_db_statistics_wire, hot_keys)) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getdbstat_recv: returned data is %d bytes but should be >= %d", reply->datalen, (int)sizeof(struct ctdb_db_statistics));
		return false;
	}

	wire = (struct ctdb_db_statistics_wire *)reply->data;

	s = malloc(offsetof(struct ctdb_db_statistics, hot_keys) + sizeof(struct ctdb_db_hot_key) * wire->num_hot_keys);
	if (!s) {
		return false;
	}
	s->db_ro_delegations = wire->db_ro_delegations;
	s->db_ro_revokes     = wire->db_ro_revokes;
	for (i = 0; i < MAX_COUNT_BUCKETS; i++) {
		s->hop_count_bucket[i] = wire->hop_count_bucket[i];
	}
	s->num_hot_keys      = wire->num_hot_keys;
	ptr = &wire->hot_keys[0];
	for (i = 0; i < wire->num_hot_keys; i++) {
		s->hot_keys[i].count = *(uint32_t *)ptr;
		ptr += 4;

		s->hot_keys[i].key.dsize = *(uint32_t *)ptr;
		ptr += 4;

		s->hot_keys[i].key.dptr = malloc(s->hot_keys[i].key.dsize);
		memcpy(s->hot_keys[i].key.dptr, ptr, s->hot_keys[i].key.dsize);
		ptr += s->hot_keys[i].key.dsize;
	}

	*stat = s;

	return true;
}

struct ctdb_request *ctdb_getdbstat_send(struct ctdb_connection *ctdb,
				      uint32_t destnode,
				      uint32_t db_id,
				      ctdb_callback_t callback,
				      void *private_data)
{
	uint32_t indata = db_id;

	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_DB_STATISTICS, destnode,
					&indata, sizeof(indata), callback, private_data);
}

void ctdb_free_dbstat(struct ctdb_db_statistics *stat)
{
	int i;

	if (stat == NULL) {
		return;
	}

	for (i = 0; i < stat->num_hot_keys; i++) {
		if (stat->hot_keys[i].key.dptr != NULL) {
			free(stat->hot_keys[i].key.dptr);
		}
	}

	free(stat);
}

bool ctdb_getnodemap_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, struct ctdb_node_map **nodemap)
{
	struct ctdb_reply_control *reply;

	*nodemap = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GET_NODEMAP);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: returned data is 0 bytes");
		return false;
	}

	*nodemap = malloc(reply->datalen);
	if (*nodemap == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: failed to malloc buffer");
		return false;
	}
	memcpy(*nodemap, reply->data, reply->datalen);

	return true;
}
struct ctdb_request *ctdb_getnodemap_send(struct ctdb_connection *ctdb,
					  uint32_t destnode,
					  ctdb_callback_t callback,
					  void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_NODEMAP,
					destnode,
					NULL, 0, callback, private_data);
}

void ctdb_free_nodemap(struct ctdb_node_map *nodemap)
{
	if (nodemap == NULL) {
		return;
	}
	free(nodemap);
}

bool ctdb_getpublicips_recv(struct ctdb_connection *ctdb,
			    struct ctdb_request *req,
			    struct ctdb_all_public_ips **ips)
{
	struct ctdb_reply_control *reply;

	*ips = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GET_PUBLIC_IPS);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: returned data is 0 bytes");
		return false;
	}

	*ips = malloc(reply->datalen);
	if (*ips == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: failed to malloc buffer");
		return false;
	}
	memcpy(*ips, reply->data, reply->datalen);

	return true;
}
struct ctdb_request *ctdb_getpublicips_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PUBLIC_IPS,
					destnode,
					NULL, 0, callback, private_data);
}

void ctdb_free_publicips(struct ctdb_all_public_ips *ips)
{
	if (ips == NULL) {
		return;
	}
	free(ips);
}

bool ctdb_getdbseqnum_recv(struct ctdb_connection *ctdb,
			   struct ctdb_request *req, uint64_t *seqnum)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_DB_SEQNUM);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getdbseqnum_recv: status -1");
		return false;
	}

	if (reply->datalen != sizeof(uint64_t)) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getdbseqnum wrong size of data was %d but expected %d bytes", reply->datalen, (int)sizeof(uint64_t));
		return false;
	}

	*seqnum = *((uint64_t *)reply->data);

	return true;
}

struct ctdb_request *ctdb_getdbseqnum_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    uint32_t dbid,
					    ctdb_callback_t callback,
					    void *private_data)
{
	uint64_t indata;

	*((uint32_t *)&indata) = dbid;

	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_DB_SEQNUM,
					destnode, &indata, sizeof(uint64_t),
					callback, private_data);
}

bool ctdb_check_message_handlers_recv(struct ctdb_connection *ctdb,
				      struct ctdb_request *req,
				      uint32_t num, uint8_t *result)
{
	struct ctdb_reply_control *reply;
	int i, count;

	reply = unpack_reply_control(req, CTDB_CONTROL_CHECK_SRVIDS);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_check_message_handlers_recv: status -1");
		return false;
	}
	
	count = (num + 7) / 8;
	if (count != reply->datalen) {
		DEBUG(ctdb, LOG_ERR, "ctdb_check_message_handlers_recv: wrong amount of data returned, expected %d bytes for %d srvids but received %d bytes", count, num, reply->datalen);
		return false;
	}

	for (i = 0; i < num; i++) {
		result[i] = !!(reply->data[i / 8] & (1 << (i % 8)));
	}

	return true;
}

struct ctdb_request *
ctdb_check_message_handlers_send(struct ctdb_connection *ctdb,
				uint32_t destnode,
				uint32_t num,
				uint64_t *mhs,
				ctdb_callback_t callback,
				void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_CHECK_SRVIDS,
					destnode,
					mhs, num * sizeof(uint64_t) ,
					callback, private_data);
}


bool ctdb_getifaces_recv(struct ctdb_connection *ctdb,
			 struct ctdb_request *req,
			 struct ctdb_ifaces_list **ifaces)
{
	struct ctdb_reply_control *reply;
	struct ctdb_ifaces_list *ifc;
	int i, len;

	*ifaces = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GET_IFACES);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getifaces_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getifaces_recv: returned data is 0 bytes");
		return false;
	}

	len = offsetof(struct ctdb_ifaces_list, ifaces);
	if (len > reply->datalen) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getifaces_recv: returned data is %d bytes but %d is minimum", reply->datalen,  (int)offsetof(struct ctdb_ifaces_list, ifaces));
		return false;
	}

	ifc = (struct ctdb_ifaces_list *)(reply->data);
	len += ifc->num * sizeof(struct ctdb_iface_info);

	if (len != reply->datalen) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getifaces_recv: returned data is %d bytes but should be %d", reply->datalen,  len);
		return false;
	}

	ifc = malloc(reply->datalen);
	if (ifc == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getifaces_recv: failed to malloc buffer");
		return false;
	}
	memcpy(ifc, reply->data, reply->datalen);

	/* make sure we null terminate the returned strings */
	for (i = 0; i < ifc->num; i++) {
		ifc->ifaces[i].name[CTDB_IFACE_SIZE] = '\0';
	}

	*ifaces = ifc;

	return true;
}

void ctdb_free_ifaces(struct ctdb_ifaces_list *ifaces)
{
	free(ifaces);
}

struct ctdb_request *ctdb_getifaces_send(struct ctdb_connection *ctdb,
					  uint32_t destnode,
					  ctdb_callback_t callback,
					  void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_IFACES,
					destnode,
					NULL, 0, callback, private_data);
}

bool ctdb_getvnnmap_recv(struct ctdb_connection *ctdb,
			 struct ctdb_request *req,
			 struct ctdb_vnn_map **vnnmap)
{
	struct ctdb_reply_control *reply;
	struct ctdb_vnn_map_wire *map;
	struct ctdb_vnn_map *tmap;
	int len;

	*vnnmap = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GETVNNMAP);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: returned data is 0 bytes");
		return false;
	}

	len = offsetof(struct ctdb_vnn_map_wire, map);
	if (len > reply->datalen) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: returned data is %d bytes but %d is minimum", reply->datalen,  (int)offsetof(struct ctdb_vnn_map_wire, map));
		return false;
	}

	map = (struct ctdb_vnn_map_wire *)(reply->data);
	len += map->size * sizeof(uint32_t);

	if (len != reply->datalen) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: returned data is %d bytes but should be %d", reply->datalen,  len);
		return false;
	}

	tmap = malloc(sizeof(struct ctdb_vnn_map));
	if (tmap == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: failed to malloc buffer");
		return false;
	}

	tmap->generation = map->generation;
	tmap->size       = map->size;
	tmap->map        = malloc(sizeof(uint32_t) * map->size);
	if (tmap->map == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getvnnmap_recv: failed to malloc buffer");
		free(tmap);
		return false;
	}

	memcpy(tmap->map, map->map, sizeof(uint32_t)*map->size);

	*vnnmap = tmap;

	return true;
}

void ctdb_free_vnnmap(struct ctdb_vnn_map *vnnmap)
{
	free(vnnmap->map);
	free(vnnmap);
}

struct ctdb_request *ctdb_getvnnmap_send(struct ctdb_connection *ctdb,
					 uint32_t destnode,
					 ctdb_callback_t callback,
					 void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GETVNNMAP,
					destnode,
					NULL, 0, callback, private_data);
}

bool ctdb_getcapabilities_recv(struct ctdb_connection *ctdb,
			       struct ctdb_request *req, uint32_t *capabilities)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_CAPABILITIES);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getcapabilities_recv: status -1");
		return false;
	}
	*capabilities = *((uint32_t *)reply->data);
	return true;
}

struct ctdb_request *ctdb_getcapabilities_send(struct ctdb_connection *ctdb,
					       uint32_t destnode,
					       ctdb_callback_t callback,
					       void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_CAPABILITIES,
					destnode,
					NULL, 0, callback, private_data);
}

