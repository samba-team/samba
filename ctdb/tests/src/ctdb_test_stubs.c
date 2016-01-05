/*
   Test stubs and support functions for some CTDB client functions

   Copyright (C) Martin Schwenke  2011

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

/* Useful for functions that don't get struct ctdb_context passed */
static struct ctdb_context *ctdb_global;

static struct ctdb_node_capabilities *global_caps = NULL;

/* Read a nodemap from stdin.  Each line looks like:
 *  <PNN> <FLAGS> [RECMASTER] [CURRENT] [CAPABILITIES]
 * EOF or a blank line terminates input.
 *
 * By default, capablities for each node are
 * CTDB_CAP_RECMASTER|CTDB_CAP_LMASTER.  These 2
 * capabilities can be faked off by adding, for example,
 * -CTDB_CAP_RECMASTER.  LVS can be faked on by adding
 * CTDB_CAP_LVS.
 */

/* A fake flag that is only supported by some functions */
#define NODE_FLAGS_FAKE_TIMEOUT 0x80000000

static void ctdb_test_stubs_read_nodemap(struct ctdb_context *ctdb)
{
	char line[1024];

	TALLOC_FREE(ctdb->nodes);
	ctdb->pnn = -1;
	ctdb->num_nodes = 0;

	ctdb->nodes = NULL;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint32_t pnn, flags, capabilities;
		char *tok, *t;
		char *ip;
		ctdb_sock_addr saddr;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Get PNN */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (PNN) ignored \"%s\"\n", line));
			continue;
		}
		pnn = (uint32_t)strtoul(tok, NULL, 0);

		/* Get IP */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (no IP) ignored \"%s\"\n", line));
			continue;
		}
		if (!parse_ip(tok, NULL, 0, &saddr)) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (IP) ignored \"%s\"\n", line));
			continue;
		}
		ip = talloc_strdup(ctdb, tok);

		/* Get flags */
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line (flags) ignored \"%s\"\n", line));
			continue;
		}
		flags = (uint32_t)strtoul(tok, NULL, 0);
		/* Handle deleted nodes */
		if (flags & NODE_FLAGS_DELETED) {
			talloc_free(ip);
			ip = talloc_strdup(ctdb, "0.0.0.0");
		}
		capabilities = CTDB_CAP_RECMASTER|CTDB_CAP_LMASTER;

		tok = strtok(NULL, " \t");
		while (tok != NULL) {
			if (strcmp(tok, "CURRENT") == 0) {
				ctdb->pnn = pnn;
			} else if (strcmp(tok, "RECMASTER") == 0) {
				ctdb->recovery_master = pnn;
			} else if (strcmp(tok, "-CTDB_CAP_RECMASTER") == 0) {
				capabilities &= ~CTDB_CAP_RECMASTER;
			} else if (strcmp(tok, "-CTDB_CAP_LMASTER") == 0) {
				capabilities &= ~CTDB_CAP_LMASTER;
			} else if (strcmp(tok, "CTDB_CAP_LVS") == 0) {
				capabilities |= CTDB_CAP_LVS;
			} else if (strcmp(tok, "TIMEOUT") == 0) {
				/* This can be done with just a flag
				 * value but it is probably clearer
				 * and less error-prone to fake this
				 * with an explicit token */
				flags |= NODE_FLAGS_FAKE_TIMEOUT;
			}
			tok = strtok(NULL, " \t");
		}

		ctdb->nodes = talloc_realloc(ctdb, ctdb->nodes, struct ctdb_node *, ctdb->num_nodes + 1);
		if (ctdb->nodes == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating nodes array\n"));
			exit (1);
		}
		ctdb->nodes[ctdb->num_nodes] = talloc_zero(ctdb, struct ctdb_node);
		if (ctdb->nodes[ctdb->num_nodes] == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating node structure\n"));
			exit (1);
		}

		ctdb->nodes[ctdb->num_nodes]->ctdb = ctdb;
		ctdb->nodes[ctdb->num_nodes]->name = "fakectdb";
		ctdb->nodes[ctdb->num_nodes]->pnn = pnn;
		parse_ip(ip, NULL, 0, &ctdb->nodes[ctdb->num_nodes]->address);
		ctdb->nodes[ctdb->num_nodes]->flags = flags;

		global_caps = talloc_realloc(ctdb, global_caps,
					     struct ctdb_node_capabilities,
					     ctdb->num_nodes+1);
		global_caps[ctdb->num_nodes].capabilities = capabilities;
		global_caps[ctdb->num_nodes].retrieved = true;

		ctdb->num_nodes++;
	}
}

static void assert_nodes_set(struct ctdb_context *ctdb)
{
	if (ctdb->nodes == NULL) {
		printf("ctdb->nodes not initialised - missing a NODEMAP section?");
		exit(1);
	}
}

#ifdef CTDB_TEST_OVERRIDE_MAIN
static void ctdb_test_stubs_print_nodemap(struct ctdb_context *ctdb)
{
	int i;

	assert_nodes_set(ctdb);

	for (i = 0; i < ctdb->num_nodes; i++) {
		printf("%ld\t0x%lx%s%s\n",
		       (unsigned long) ctdb->nodes[i]->pnn,
		       (unsigned long) ctdb->nodes[i]->flags,
		       ctdb->nodes[i]->pnn == ctdb->pnn ? "\tCURRENT" : "",
		       ctdb->nodes[i]->pnn == ctdb->recovery_master ? "\tRECMASTER" : "");
	}
}
#endif

/* Read interfaces information.  Same format as "ctdb ifaces -Y"
 * output:
 *   :Name:LinkStatus:References:
 *   :eth2:1:4294967294
 *   :eth1:1:4294967292
 */

struct ctdb_interface {
	struct ctdb_interface *prev, *next;
	const char *name;
	bool link_up;
	uint32_t references;
};

static void ctdb_test_stubs_read_ifaces(struct ctdb_context *ctdb)
{
	char line[1024];
	struct ctdb_interface *iface;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint16_t link_state;
		uint32_t references;
		char *tok, *t, *name;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, ":Name:LinkStatus:References:") == 0) {
			continue;
		}

		/* name */
		//tok = strtok(line, ":"); /* Leading colon... */
		tok = strtok(line, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		name = tok;

		/* link_state */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		link_state = (uint16_t)strtoul(tok, NULL, 0);

		/* references... */
		tok = strtok(NULL, ":");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored \"%s\"\n", line));
			continue;
		}
		references = (uint32_t)strtoul(tok, NULL, 0);

		iface = talloc_zero(ctdb, struct ctdb_interface);

		if (iface == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating iface\n"));
			exit (1);
		}

		iface->name = talloc_strdup(iface, name);
		iface->link_up = link_state;
		iface->references = references;

		DLIST_ADD(ctdb->ifaces, iface);
	}
}

static void assert_ifaces_set(struct ctdb_context *ctdb)
{
	if (ctdb->ifaces == NULL) {
		printf("ctdb->ifaces not initialised - missing an IFACES section?");
		exit(1);
	}
}

#ifdef CTDB_TEST_OVERRIDE_MAIN
static void ctdb_test_stubs_print_ifaces(struct ctdb_context *ctdb)
{
	struct ctdb_interface *iface;

	assert_ifaces_set(ctdb);

	printf(":Name:LinkStatus:References:\n");
	for (iface = ctdb->ifaces; iface != NULL; iface = iface->next) {
		printf(":%s:%u:%u:\n",
		       iface->name,
		       iface->link_up,
		       iface->references);
	}
}
#endif

/* Read vnn map.
 * output:
 *   <GENERATION>
 *   <LMASTER0>
 *   <LMASTER1>
 *   ...
 */

/*
struct ctdb_vnn_map {
	uint32_t generation;
	uint32_t size;
	uint32_t *map;
};
*/
static void ctdb_test_stubs_read_vnnmap(struct ctdb_context *ctdb)
{
	char line[1024];

	TALLOC_FREE(ctdb->vnn_map);

	ctdb->vnn_map = talloc_zero(ctdb, struct ctdb_vnn_map);
	if (ctdb->vnn_map == NULL) {
		DEBUG(DEBUG_ERR, ("OOM allocating vnnmap\n"));
		exit (1);
	}
	ctdb->vnn_map->generation = INVALID_GENERATION;
	ctdb->vnn_map->size = 0;
	ctdb->vnn_map->map = NULL;

	while ((fgets(line, sizeof(line), stdin) != NULL) &&
	       (line[0] != '\n')) {
		uint32_t n;
		char *t;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		n = (uint32_t) strtol(line, NULL, 0);

		/* generation */
		if (ctdb->vnn_map->generation == INVALID_GENERATION) {
			ctdb->vnn_map->generation = n;
			continue;
		}

		ctdb->vnn_map->map = talloc_realloc(ctdb, ctdb->vnn_map->map, uint32_t, ctdb->vnn_map->size + 1);
		if (ctdb->vnn_map->map == NULL) {
			DEBUG(DEBUG_ERR, ("OOM allocating vnn_map->map\n"));
			exit (1);
		}

		ctdb->vnn_map->map[ctdb->vnn_map->size] = n;
		ctdb->vnn_map->size++;
	}
}

static void assert_vnn_map_set(struct ctdb_context *ctdb)
{
	if (ctdb->vnn_map == NULL) {
		printf("ctdb->vnn_map not initialised - missing a VNNMAP section?");
		exit(1);
	}
}

#ifdef CTDB_TEST_OVERRIDE_MAIN
static void ctdb_test_stubs_print_vnnmap(struct ctdb_context *ctdb)
{
	int i;

	assert_vnn_map_set(ctdb);

	printf("%d\n", ctdb->vnn_map->generation);
	for (i = 0; i < ctdb->vnn_map->size; i++) {
		printf("%d\n", ctdb->vnn_map->map[i]);
	}
}
#endif

static void ctdb_test_stubs_fake_setup(struct ctdb_context *ctdb)
{
	char line[1024];

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char *t;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		if (strcmp(line, "NODEMAP") == 0) {
			ctdb_test_stubs_read_nodemap(ctdb);
		} else if (strcmp(line, "IFACES") == 0) {
			ctdb_test_stubs_read_ifaces(ctdb);
		} else if (strcmp(line, "VNNMAP") == 0) {
			ctdb_test_stubs_read_vnnmap(ctdb);
		} else {
			printf("Unknown line %s\n", line);
			exit(1);
		}
	}
}

/* Support... */
static bool current_node_is_connected (struct ctdb_context *ctdb)
{
	int i;

	assert_nodes_set(ctdb);

	for (i = 0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->pnn == ctdb->pnn) {
			if (ctdb->nodes[i]->flags &
			    (NODE_FLAGS_DISCONNECTED | NODE_FLAGS_DELETED)) {
				return false;
			} else {
				return true;
			}
		}
	}

	/* Shouldn't really happen, so fag an error */
	return false;
}

/* Stubs... */

struct ctdb_context *ctdb_cmdline_client_stub(struct tevent_context *ev,
					      struct timeval req_timeout)
{
	const char *t = getenv("CTDB_DEBUGLEVEL");
	if (t != NULL) {
		DEBUGLEVEL= atoi(t);
	} else {
		DEBUGLEVEL = 0;
	}

	ctdb_global->ev = ev;

	return ctdb_global;
}

struct tevent_context *tevent_context_init_stub(TALLOC_CTX *mem_ctx)
{
	struct ctdb_context *ctdb;

	/* This needs to be initialised prior to the client setup, for
	   the xpnn stub */
	ctdb = talloc_zero(NULL, struct ctdb_context);

	ctdb_set_socketname(ctdb, "fake");

	ctdb_test_stubs_fake_setup(ctdb);

	ctdb_global = ctdb;

	return tevent_context_init_byname(mem_ctx, NULL);
}

int
ctdb_ctrl_getnodemap_stub(struct ctdb_context *ctdb,
			  struct timeval timeout, uint32_t destnode,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_node_map_old **nodemap)
{
	assert_nodes_set(ctdb);

	if (!current_node_is_connected(ctdb)) {
		return -1;
	}

	*nodemap = ctdb_node_list_to_map(ctdb->nodes, ctdb->num_nodes,
					 mem_ctx);

	return 0;
}

int
ctdb_ctrl_getnodesfile_stub(struct ctdb_context *ctdb,
			    struct timeval timeout, uint32_t destnode,
			    TALLOC_CTX *mem_ctx, struct ctdb_node_map_old **nodemap)
{
	char *v, *f;

	/* If there's an environment variable for a node-specific file
	 * then use it.  Otherwise use the global file. */
	v = talloc_asprintf(mem_ctx, "CTDB_NODES_%u", destnode);
	f = getenv(v);
	if (f == NULL) {
		f = getenv("CTDB_NODES");
	}

	*nodemap = ctdb_read_nodes_file(mem_ctx, f);

	return *nodemap == NULL ? -1 : 0;
}

int
ctdb_ctrl_getvnnmap_stub(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx, struct ctdb_vnn_map **vnnmap)
{
	assert_vnn_map_set(ctdb);

	*vnnmap = talloc(ctdb, struct ctdb_vnn_map);
	if (*vnnmap == NULL) {
		DEBUG(DEBUG_ERR, (__location__ "OOM\n"));
		exit (1);
	}
	(*vnnmap)->map = talloc_array(*vnnmap, uint32_t, ctdb->vnn_map->size);

	(*vnnmap)->generation = ctdb->vnn_map->generation;
	(*vnnmap)->size = ctdb->vnn_map->size;
	memcpy((*vnnmap)->map, ctdb->vnn_map->map, sizeof(uint32_t) * (*vnnmap)->size);

	return 0;
}

int
ctdb_ctrl_getrecmode_stub(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			  struct timeval timeout, uint32_t destnode,
			  uint32_t *recmode)
{
	*recmode = ctdb->recovery_mode;

	return 0;
}

int ctdb_ctrl_setrecmode_stub(struct ctdb_context *ctdb, struct timeval timeout,
			      uint32_t destnode, uint32_t recmode)
{
	ctdb->recovery_mode = recmode;

	if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE) {
		/* Recovery is complete! That was quick.... */
		ctdb->recovery_mode = CTDB_RECOVERY_NORMAL;
		assert_vnn_map_set(ctdb);
		ctdb->vnn_map->generation++;
	}

	return 0;
}

int
ctdb_ctrl_getrecmaster_stub(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			    struct timeval timeout, uint32_t destnode,
			    uint32_t *recmaster)
{
	*recmaster = ctdb->recovery_master;

	return 0;
}

int
ctdb_ctrl_getpnn_stub(struct ctdb_context *ctdb, struct timeval timeout,
		      uint32_t destnode)
{
	if (!current_node_is_connected(ctdb)) {
		return -1;
	}

	if (destnode == CTDB_CURRENT_NODE) {
		return ctdb->pnn;
	} else {
		return destnode;
	}
}

/* From ctdb_takeover.c */
int32_t ctdb_control_get_ifaces(struct ctdb_context *ctdb,
				struct ctdb_req_control_old *c,
				TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_iface_list_old *ifaces;
	struct ctdb_interface *cur;

	assert_ifaces_set(ctdb);

	/* count how many public ip structures we have */
	num = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		num++;
	}

	len = offsetof(struct ctdb_iface_list_old, ifaces) +
		num*sizeof(struct ctdb_iface);
	ifaces = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ifaces);

	i = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		size_t nlen = strlcpy(ifaces->ifaces[i].name, cur->name,
				      sizeof(ifaces->ifaces[i].name));
		if (nlen >= sizeof(ifaces->ifaces[i].name)) {
			/* Ignore invalid name */
			continue;
		}
		ifaces->ifaces[i].link_state = cur->link_up;
		ifaces->ifaces[i].references = cur->references;
		i++;
	}
	ifaces->num = i;
	len = offsetof(struct ctdb_iface_list_old, ifaces) +
		i*sizeof(struct ctdb_iface);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ifaces;

	return 0;
}

int
ctdb_ctrl_get_ifaces_stub(struct ctdb_context *ctdb,
			  struct timeval timeout, uint32_t destnode,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_iface_list_old **ifaces)
{
	TDB_DATA *outdata;
	int ret;

	if (!current_node_is_connected(ctdb)) {
		return -1;
	}

	outdata = talloc(mem_ctx, TDB_DATA);

	ret = ctdb_control_get_ifaces(ctdb, NULL, outdata);

	if (ret == 0) {
		*ifaces = (struct ctdb_iface_list_old *)outdata->dptr;
	}

	return ret;
}

/* In reality handlers can be registered for many srvids.  However,
 * the ctdb tool only registers one at a time so keep this simple. */
static struct {
	uint64_t srvid;
	srvid_handler_fn message_handler;
	void *message_private;
} ctdb_message_list_fake = {
	.srvid = 0,
	.message_handler = NULL,
	.message_private = NULL,
};

int ctdb_client_set_message_handler_stub(struct ctdb_context *ctdb,
					 uint64_t srvid,
					 srvid_handler_fn handler,
					 void *private_data)
{
	ctdb_message_list_fake.srvid = srvid;
	ctdb_message_list_fake.message_handler = handler;
	ctdb_message_list_fake.message_private = private_data;

	return 0;
}

int ctdb_client_remove_message_handler_stub(struct ctdb_context *ctdb,
					    uint64_t srvid,
					    void *private_data)
{
	ctdb_message_list_fake.srvid = 0;
	ctdb_message_list_fake.message_handler = NULL;
	ctdb_message_list_fake.message_private = NULL;

	return 0;
}

static void ctdb_fake_handler_pnn_reply(struct ctdb_context *ctdb,
					uint32_t pnn)
{
	TDB_DATA reply_data;

	reply_data.dsize = sizeof(pnn);
	reply_data.dptr = (uint8_t *)&pnn;
	ctdb_message_list_fake.message_handler(
		ctdb_message_list_fake.srvid,
		reply_data,
		ctdb_message_list_fake.message_private);
}

int ctdb_client_send_message_stub(struct ctdb_context *ctdb,
				  uint32_t pnn,
				  uint64_t srvid, TDB_DATA data)
{
	struct srvid_reply_handler_data *d;
	int i;

	if (ctdb_message_list_fake.message_handler == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       " no message handler registered for srvid %llu\n",
		       (unsigned long long)srvid));
		return -1;
	}

	switch (srvid) {
	case CTDB_SRVID_TAKEOVER_RUN:
		/* Fake a single reply from recovery master */
		DEBUG(DEBUG_NOTICE,
		      ("Fake takeover run on recovery master %u\n",
		       ctdb->recovery_master));
		ctdb_fake_handler_pnn_reply(ctdb, ctdb->recovery_master);
		break;

	case CTDB_SRVID_DISABLE_RECOVERIES:
	case CTDB_SRVID_DISABLE_TAKEOVER_RUNS:
		/* Assume srvid_broadcast() is in use and reply on
		 * behalf of relevant nodes */
		if (pnn != CTDB_BROADCAST_CONNECTED) {
			DEBUG(DEBUG_ERR,
			      (__location__
			       " srvid %llu must use pnn CTDB_BROADCAST_CONNECTED\n",
			       (unsigned long long)srvid));
			return -1;
		}

		d = (struct srvid_reply_handler_data *)ctdb_message_list_fake.message_private;
		if (d == NULL) {
			DEBUG(DEBUG_ERR,
			      (__location__ " No private data registered\n"));
			return -1;
		}
		if (d->nodes == NULL) {
			DEBUG(DEBUG_ERR,
			      (__location__
			       " No nodes to reply to in private data\n"));
			return -1;
		}

		for (i = 0; i < talloc_array_length(d->nodes); i++) {
			if (d->nodes[i] != -1) {
				ctdb_fake_handler_pnn_reply(ctdb, d->nodes[i]);
			}
		}
		break;

	default:
		DEBUG(DEBUG_ERR,
		      (__location__ " srvid %llu not implemented\n",
		       (unsigned long long)srvid));
		return -1;
	}

	return 0;
}

int ctdb_client_check_message_handlers_stub(struct ctdb_context *ctdb,
					    uint64_t *ids, uint32_t num,
					    uint8_t *result)
{
	DEBUG(DEBUG_ERR, (__location__ " NOT IMPLEMENTED\n"));
	return -1;
}

int ctdb_ctrl_getcapabilities_stub(struct ctdb_context *ctdb,
				   struct timeval timeout, uint32_t destnode,
				   uint32_t *capabilities)
{
	uint32_t *capp;

	assert_nodes_set(ctdb);

	if (ctdb->nodes[destnode]->flags & NODE_FLAGS_FAKE_TIMEOUT) {
		/* Placeholder for line#, instead of __location__ */
		DEBUG(DEBUG_ERR,
		      ("__LOCATION__ control timed out."
		       " reqid:1234567890 opcode:80 dstnode:%d\n", destnode));
		DEBUG(DEBUG_ERR,
		      ("__LOCATION__ ctdb_control_recv failed\n"));
		DEBUG(DEBUG_ERR,
		      ("__LOCATION__ ctdb_ctrl_getcapabilities_recv failed\n"));
		return -1;
	}

	if (ctdb->nodes[destnode]->flags & NODE_FLAGS_DISCONNECTED) {
		DEBUG(DEBUG_ERR,
		      ("ctdb_control error: 'ctdb_control to disconnected node\n"));
		/* Placeholder for line#, instead of __location__ */
		DEBUG(DEBUG_ERR,
		      ("__LOCATION__ ctdb_ctrl_getcapabilities_recv failed\n"));
		return -1;
	}

	capp = ctdb_get_node_capabilities(global_caps, destnode);
	if (capp == NULL) {
		DEBUG(DEBUG_ERR, ("__LOCATION__ invalid PNN\n"));
		return -1;
	}
	*capabilities = *capp;
	return 0;
}

int ctdb_ctrl_reload_nodes_file_stub(struct ctdb_context *ctdb,
				     struct timeval timeout, uint32_t destnode)
{
	DEBUG(DEBUG_NOTICE, ("ctdb_ctrl_reload_nodes_file: node %u\n", destnode));
	return 0;
}

/* This is to support testing ctdb xpnn */

bool ctdb_sys_have_ip_stub(ctdb_sock_addr *addr)
{
	int i;
	struct ctdb_context *ctdb = ctdb_global;

	assert_nodes_set(ctdb);

	for (i = 0; i < ctdb->num_nodes; i++) {
		if (ctdb->pnn == ctdb->nodes[i]->pnn) {
			if (ctdb_same_ip(addr, &ctdb->nodes[i]->address)) {
				return true;
			}
		}
	}

	return false;
}

int
ctdb_client_async_control_stub(struct ctdb_context *ctdb,
			       enum ctdb_controls opcode,
			       uint32_t *nodes,
			       uint64_t srvid,
			       struct timeval timeout,
			       bool dont_log_errors,
			       TDB_DATA data,
			       client_async_callback client_callback,
			       client_async_callback fail_callback,
			       void *callback_data)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int i, ret;

	ret = 0;
	for (i = 0; i < talloc_array_length(nodes); i++) {
		uint32_t pnn = nodes[i];
		TDB_DATA outdata;
		int res;

		/* Not so async... but good enough for testing! */
		switch (opcode) {
		case CTDB_CONTROL_RELOAD_NODES_FILE:
			res = ctdb_ctrl_reload_nodes_file_stub(ctdb, timeout, pnn);
			break;
		case CTDB_CONTROL_RELOAD_PUBLIC_IPS:
			DEBUG(DEBUG_NOTICE, ("Fake reload public IPs on node %u\n", pnn));
			res = 0;
			break;
		case CTDB_CONTROL_GET_NODES_FILE: {
			struct ctdb_node_map_old *nodemap;
			res = ctdb_ctrl_getnodesfile_stub(ctdb, timeout, pnn,
							  tmp_ctx, &nodemap);
			if (res == 0) {
				outdata.dsize = talloc_get_size(nodemap);
				outdata.dptr = (uint8_t *) nodemap;
			}
		}
			break;
		default:
			DEBUG(DEBUG_ERR, (__location__ " Control not implemented %u\n",
					  opcode));
			talloc_free(tmp_ctx);
			return -1;
		}

		if (res == 0) {
			if (client_callback != NULL) {
				client_callback(ctdb, pnn, res, outdata, callback_data);
			}
		} else {
			ret = -1;
			if (fail_callback != NULL) {
				fail_callback(ctdb, pnn, res, outdata, callback_data);
			}
		}
	}

	talloc_free(tmp_ctx);
	return ret;
}

struct ctdb_node_capabilities *
ctdb_get_capabilities_stub(struct ctdb_context *ctdb,
			   TALLOC_CTX *mem_ctx,
			   struct timeval timeout,
			   struct ctdb_node_map_old *nodemap)
{
	return global_caps;
}
