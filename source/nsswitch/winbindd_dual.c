/* 
   Unix SMB/CIFS implementation.

   Winbind background daemon

   Copyright (C) Andrew Tridgell 2002
   
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

/*
  the idea of the optional dual daemon mode is ot prevent slow domain
  responses from clagging up the rest of the system. When in dual
  daemon mode winbindd always responds to requests from cache if the
  request is in cache, and if the cached answer is stale then it asks
  the "dual daemon" to update the cache for that request

 */

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern BOOL opt_dual_daemon;
BOOL background_process = False;
int dual_daemon_pipe = -1;


/* a list of requests ready to be sent to the dual daemon */
struct dual_list {
	struct dual_list *next;
	char *data;
	int length;
	int offset;
};

static struct dual_list *dual_list;
static struct dual_list *dual_list_end;

/*
  setup a select() including the dual daemon pipe
 */
int dual_select_setup(fd_set *fds, int maxfd)
{
	if (dual_daemon_pipe == -1 ||
	    !dual_list) {
		return maxfd;
	}

	FD_SET(dual_daemon_pipe, fds);
	if (dual_daemon_pipe > maxfd) {
		maxfd = dual_daemon_pipe;
	}
	return maxfd;
}


/*
  a hook called from the main winbindd select() loop to handle writes
  to the dual daemon pipe 
*/
void dual_select(fd_set *fds)
{
	int n;

	if (dual_daemon_pipe == -1 ||
	    !dual_list ||
	    !FD_ISSET(dual_daemon_pipe, fds)) {
		return;
	}

	n = sys_write(dual_daemon_pipe, 
		  &dual_list->data[dual_list->offset],
		  dual_list->length - dual_list->offset);

	if (n <= 0) {
		/* the pipe is dead! fall back to normal operation */
		dual_daemon_pipe = -1;
		return;
	}

	dual_list->offset += n;

	if (dual_list->offset == dual_list->length) {
		struct dual_list *next;
		next = dual_list->next;
		free(dual_list->data);
		free(dual_list);
		dual_list = next;
		if (!dual_list) {
			dual_list_end = NULL;
		}
	}
}

/* 
   send a request to the background daemon 
   this is called for stale cached entries
*/
void dual_send_request(struct winbindd_cli_state *state)
{
	struct dual_list *list;

	if (!background_process) return;

	list = malloc(sizeof(*list));
	if (!list) return;

	list->next = NULL;
	list->data = memdup(&state->request, sizeof(state->request));
	list->length = sizeof(state->request);
	list->offset = 0;
	
	if (!dual_list_end) {
		dual_list = list;
		dual_list_end = list;
	} else {
		dual_list_end->next = list;
		dual_list_end = list;
	}

	background_process = False;
}


/* 
the main dual daemon 
*/
void do_dual_daemon(void)
{
	int fdpair[2];
	struct winbindd_cli_state state;
	
	if (pipe(fdpair) != 0) {
		return;
	}

	ZERO_STRUCT(state);
	state.pid = getpid();

	dual_daemon_pipe = fdpair[1];
	state.sock = fdpair[0];

	if (fork() != 0) {
		close(fdpair[0]);
		return;
	}
	close(fdpair[1]);

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
		_exit(0);
	}
	
	dual_daemon_pipe = -1;
	opt_dual_daemon = False;

	while (1) {
		/* free up any talloc memory */
		lp_talloc_free();
		main_loop_talloc_free();

		/* fetch a request from the main daemon */
		winbind_client_read(&state);

		if (state.finished) {
			/* we lost contact with our parent */
			exit(0);
		}

		/* process full rquests */
		if (state.read_buf_len == sizeof(state.request)) {
			DEBUG(4,("dual daemon request %d\n", (int)state.request.cmd));

			/* special handling for the stateful requests */
			switch (state.request.cmd) {
			case WINBINDD_GETPWENT:
				winbindd_setpwent(&state);
				break;
				
			case WINBINDD_GETGRENT:
			case WINBINDD_GETGRLST:
				winbindd_setgrent(&state);
				break;
			default:
				break;
			}

			winbind_process_packet(&state);
			message_send_pid(getppid(), MSG_WINBIND_FINISHED,
					 &state.request.client_fd,
					 sizeof(state.request.client_fd),
					 True);
			SAFE_FREE(state.response.extra_data);

			free_getent_state(state.getpwent_state);
			free_getent_state(state.getgrent_state);
			state.getpwent_state = NULL;
			state.getgrent_state = NULL;
		}
	}
}

struct winbindd_single_client {
	struct winbindd_single_client *next, *prev;
	int sock;
	BOOL reading;
	BOOL finished;
	int bytes_read, bytes_written;
	fstring request;
	char *response;
};

enum wb_connection_type { WB_LSA_PROXY, WB_SAMR_PROXY, WB_IDMAP_DAEMON };

struct winbindd_connection {
	enum wb_connection_type type;
	fstring socket_name;
	fstring dc_name;
	struct in_addr dc_ip;

	fstring domain_name; 	/* For samr children */
	DOM_SID sam_sid;
};

struct winbindd_single_daemon {
	struct winbindd_connection conn;
	int socket;
	struct cli_state *cli;
	POLICY_HND pol;

	struct winbindd_single_function *functions;
	struct winbindd_single_client *clients;
	int num_clients;
};

struct winbindd_child {

	struct winbindd_child *prev, *next;

	struct winbindd_connection conn;

	pid_t pid;
};

struct winbindd_single_function {
	const char *name;
	NTSTATUS (*process)(struct winbindd_single_daemon *d,
			    TALLOC_CTX *mem_ctx,
			    struct winbindd_single_client *cli,
			    const char *request_data);
};

static void winbindd_init_single_daemon(struct winbindd_single_daemon *d)
{
	d->socket = -1;
	d->cli = NULL;
	ZERO_STRUCT(d->pol);
	d->clients = NULL;
	d->num_clients = 0;
}

static struct winbindd_single_client *
winbindd_single_client_list(struct winbindd_single_daemon *d)
{
	return d->clients;
}
	
/* Add a connection to the list */

static void winbindd_add_single_client(struct winbindd_single_daemon *d,
				       struct winbindd_single_client *cli)
{
	DLIST_ADD(d->clients, cli);
	d->num_clients++;
}

/* Remove a client from the list */

static void winbindd_remove_single_client(struct winbindd_single_daemon *d,
					  struct winbindd_single_client *cli)
{
	DLIST_REMOVE(d->clients, cli);
	d->num_clients--;
}

static void new_single_client(struct winbindd_single_daemon *d,
			      int listen_sock)
{
	struct sockaddr_un sunaddr;
	struct winbindd_single_client *client;
	socklen_t len;
	int sock;
	
	/* Accept connection */
	
	len = sizeof(sunaddr);

	do {
		sock = accept(listen_sock, (struct sockaddr *)&sunaddr, &len);
	} while (sock == -1 && errno == EINTR);

	if (sock == -1)
		return;
	
	DEBUG(6,("accepted socket %d\n", sock));
	
	/* Create new connection structure */

	client = (struct winbindd_single_client *)malloc(sizeof(*client));

	if (client == NULL)
		return;
	
	client->sock = sock;
	client->reading = True;
	client->bytes_read = 0;
	client->finished = False;
	client->response = NULL;
	winbindd_add_single_client(d, client);
}

static NTSTATUS winbindd_lsa_nametosid(struct winbindd_single_daemon *d,
				       TALLOC_CTX *mem_ctx,
				       struct winbindd_single_client *client,
				       const char *request_data)
{
	DOM_SID *sids;
	uint32 *types;
	NTSTATUS result;

	result = cli_lsa_lookup_names(d->cli, mem_ctx, &d->pol, 1,
				      &request_data, &sids, &types);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%s %d\n", sid_string_static(&sids[0]),
		 types[0]);
	return result;
}

static NTSTATUS winbindd_lsa_sidtoname(struct winbindd_single_daemon *d,
				       TALLOC_CTX *mem_ctx,
				       struct winbindd_single_client *client,
				       const char *request_data)
{
	char **domains;
	char **names;
	uint32 *types;
	DOM_SID sid;
	NTSTATUS result;

	if (!string_to_sid(&sid, request_data))
		return NT_STATUS_INVALID_PARAMETER;

	result = cli_lsa_lookup_sids(d->cli, mem_ctx, &d->pol, 1, &sid,
				     &domains, &names, &types);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%s\\%s\\%d\n", domains[0], names[0],
		 types[0]);
	return result;
}

static NTSTATUS winbindd_lsa_dominfo(struct winbindd_single_daemon *d,
				     TALLOC_CTX *mem_ctx,
				     struct winbindd_single_client *client,
				     const char *request_data)
{
	char *domain_name;
	DOM_SID *domain_sid;
	NTSTATUS result;

	result = cli_lsa_query_info_policy(d->cli, mem_ctx, &d->pol, 3,
					   &domain_name, &domain_sid);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%s\\%s\n", domain_name,
		 sid_string_static(domain_sid));
	return result;
}

static NTSTATUS winbindd_lsa_enumtrust(struct winbindd_single_daemon *d,
				       TALLOC_CTX *mem_ctx,
				       struct winbindd_single_client *client,
				       const char *request_data)
{
	char **names;
	DOM_SID *sids;
	int i, num_domains;
	uint32 enum_ctx = 0;
	NTSTATUS result;

	result = cli_lsa_enum_trust_dom(d->cli, mem_ctx, &d->pol, &enum_ctx,
					&num_domains, &names, &sids);

	if (!NT_STATUS_EQUAL(result, NT_STATUS_NO_MORE_ENTRIES) &&
	    !NT_STATUS_IS_OK(result))
		return NT_STATUS_UNSUCCESSFUL;

	asprintf(&client->response, "%d\n", num_domains);

	for (i=0; i<num_domains; i++) {
		char *tmp = client->response;
		asprintf(&client->response, "%s%s\\%s\n", client->response,
			 names[i], sid_string_static(&sids[i]));
		free(tmp);
	}

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_samr_groupmem(struct winbindd_single_daemon *d,
				       TALLOC_CTX *mem_ctx,
				       struct winbindd_single_client *client,
				       const char *request_data)
{
	uint32 rid;
	POLICY_HND group_pol;
	NTSTATUS result;
	int i, num_rids;
	uint32 *rids;
	uint32 *types;

	rid = strtol(request_data, NULL, 10);

	result = cli_samr_open_group(d->cli, mem_ctx, &d->pol,
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     rid, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_query_groupmem(d->cli, mem_ctx, &group_pol, &num_rids,
					 &rids, &types);

	cli_samr_close(d->cli, mem_ctx, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	client->response = strdup("");

	for (i=0; i<num_rids; i++) {
		char *tmp = client->response;
		asprintf(&client->response, "%s%d\n", client->response, rids[i]);
		free(tmp);
	}

	return result;
}

static NTSTATUS winbindd_samr_usergroups(struct winbindd_single_daemon *d,
					 TALLOC_CTX *mem_ctx,
					 struct winbindd_single_client *client,
					 const char *request_data)
{
	uint32 rid;
	POLICY_HND user_pol;
	NTSTATUS result;
	int i, num_rids;
	DOM_GID *rids;

	rid = strtol(request_data, NULL, 10);

	result = cli_samr_open_user(d->cli, mem_ctx, &d->pol,
				    SEC_RIGHTS_MAXIMUM_ALLOWED,
				    rid, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_query_usergroups(d->cli, mem_ctx, &user_pol, &num_rids,
					   &rids);

	cli_samr_close(d->cli, mem_ctx, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	client->response = strdup("");

	for (i=0; i<num_rids; i++) {
		char *tmp = client->response;
		asprintf(&client->response, "%s%d\n", client->response,
			 rids[i].g_rid);
		free(tmp);
	}

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_samr_enumusers(struct winbindd_single_daemon *d,
					TALLOC_CTX *mem_ctx,
					struct winbindd_single_client *client,
					const char *request_data)
{
	uint32 resume;
	NTSTATUS result;
	char **users;
	uint32 *rids;
	uint32 i, num_users;

	resume = strtol(request_data, NULL, 10);

	result = cli_samr_enum_dom_users(d->cli, mem_ctx, &d->pol, &resume,
					 ACB_NORMAL, 0xffff, &users, &rids,
					 &num_users);

	if (NT_STATUS_IS_OK(result)) {
		asprintf(&client->response, "DONE %d\n", num_users);
	} else if (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
		asprintf(&client->response, "RESUME %d %d\n", resume,
			 num_users);
	} else {
		return result;
	}

	for (i=0; i<num_users; i++) {
		char *tmp = client->response;
		asprintf(&client->response, "%s%s-%d %s\n", client->response,
			 sid_string_static(&d->conn.sam_sid), rids[i],
			 users[i]);
		free(tmp);
	}

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_idmap_sidtouid(struct winbindd_single_daemon *d,
					TALLOC_CTX *mem_ctx,
					struct winbindd_single_client *client,
					const char *request_data)
{
	DOM_SID sid;
	NTSTATUS result;
	uid_t uid;

	if (!string_to_sid(&sid, request_data))
		return NT_STATUS_INVALID_PARAMETER;

	result = idmap_sid_to_uid(&sid, &uid, 0);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%d\n", uid);

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_idmap_sidtogid(struct winbindd_single_daemon *d,
					TALLOC_CTX *mem_ctx,
					struct winbindd_single_client *client,
					const char *request_data)
{
	DOM_SID sid;
	NTSTATUS result;
	gid_t gid;

	if (!string_to_sid(&sid, request_data))
		return NT_STATUS_INVALID_PARAMETER;

	result = idmap_sid_to_gid(&sid, &gid, 0);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%d\n", gid);

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_idmap_uidtosid(struct winbindd_single_daemon *d,
					TALLOC_CTX *mem_ctx,
					struct winbindd_single_client *client,
					const char *request_data)
{
	DOM_SID sid;
	NTSTATUS result;
	uid_t uid;

	uid = strtol(request_data, NULL, 10);

	result = idmap_uid_to_sid(&sid, uid);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%s\n", sid_string_static(&sid));

	return NT_STATUS_OK;
}

static NTSTATUS winbindd_idmap_gidtosid(struct winbindd_single_daemon *d,
					TALLOC_CTX *mem_ctx,
					struct winbindd_single_client *client,
					const char *request_data)
{
	DOM_SID sid;
	NTSTATUS result;
	gid_t gid;

	gid = strtol(request_data, NULL, 10);

	result = idmap_gid_to_sid(&sid, gid);

	if (!NT_STATUS_IS_OK(result))
		return result;

	asprintf(&client->response, "%s\n", sid_string_static(&sid));

	return NT_STATUS_OK;
}

static void winbind_single_process(struct winbindd_single_daemon *d,
				   struct winbindd_single_client *client)
{
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	struct winbindd_single_function *function;
	BOOL found = False;

	DEBUG(10, ("processing %s\n", client->request));

	mem_ctx = talloc_init("single_process");

	for (function = d->functions; function->name != NULL; function++) {

		if (strncmp(client->request, function->name,
			    strlen(function->name)) != 0)
			continue;

		found = True;
		result = (function->process)(d, mem_ctx, client,
					     client->request +
					     strlen(function->name)+1);
		break;
	}

	if (!found) {

		if (strcmp(client->request, "pid") != 0) {
			client->response = strdup("ERR        \n");
			goto done;
		}

		/* Generic probe request: Return pid */
		asprintf(&client->response, "%d\n", getpid());
		result = NT_STATUS_OK;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL) &&
	    (d->cli != NULL) && (d->cli->fd == -1)) {
		/* Disconnected */
		exit(1);
	}

	if (NT_STATUS_IS_OK(result)) {
		char *response = client->response;
		asprintf(&client->response, "OK %08d\n%s",
			 strlen(response), response);
		free(response);
	} else {
		client->response = strdup("ERR        \n");
	}

 done:
	talloc_destroy(mem_ctx);
}

static void winbind_single_read_line(struct winbindd_single_client *client)
{
	int n;

	n = sys_read(client->sock, client->request + client->bytes_read,
		     sizeof(client->request) - client->bytes_read);

	DEBUG(10, ("Read %d bytes. Need %d more for a full request.\n",
		   n, sizeof(client->request) - n - client->bytes_read));

	if (n <= 0) {
		DEBUG(5, ("Read failed on socket %d: %s\n",
			  client->sock,
			  (n == -1) ? strerror(errno) : "EOF"));
		client->finished = True;
		return;
	}

	client->bytes_read += n;

	if (client->bytes_read == sizeof(client->request)) {
		DEBUG(5, ("Request overflow\n"));
		client->finished = True;
	}

	return;
}

static void winbind_single_write_line(struct winbindd_single_client *client)
{
	int to_write = strlen(client->response) - client->bytes_written;
	int n;

	n = sys_write(client->sock, client->response + client->bytes_written,
		      to_write);

	if (n <= 0) {
		DEBUG(5, ("Write failed on socket %d: %s\n",
			  client->sock,
			  (n == -1) ? strerror(errno) : "EOF"));
		client->finished = True;
		return;
	}

	client->bytes_written += n;

	if (n != to_write)
		return;

	/* Wrote everything, prepare for the next request */

	client->reading = True;
	client->bytes_read = 0;
	SAFE_FREE(client->response);
}

static int open_single_socket(struct winbindd_single_daemon *d)
{
	if (d->socket == -1) {
		d->socket = create_pipe_sock(WINBINDD_SOCKET_DIR,
					     d->conn.socket_name, 0755);
		DEBUG(10, ("open_winbindd_socket: opened socket fd %d\n",
			   d->socket));
	}

	return d->socket;
}

static BOOL do_sigterm = False;

static void single_termination_handler(int signum)
{
	do_sigterm = True;
	sys_select_signal();
}

static void process_single_loop(struct winbindd_single_daemon *d)
{
	struct winbindd_single_client *client;
	fd_set r_fds, w_fds;
	int maxfd, listen_sock, selret;
	struct timeval timeout;

	/* Free up temporary memory */

	lp_talloc_free();
	main_loop_talloc_free();

	if (do_sigterm)
		exit(0);

	/* Initialise fd lists for select() */

	listen_sock = open_single_socket(d);

	if (listen_sock == -1) {
		perror("open_single_socket");
		exit(1);
	}

	maxfd = listen_sock;

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);
	FD_SET(listen_sock, &r_fds);

	timeout.tv_sec = WINBINDD_ESTABLISH_LOOP;
	timeout.tv_usec = 0;

	/* Set up client readers and writers */
	
	client = winbindd_single_client_list(d);

	while (client != NULL) {

		if (client->finished) {
			struct winbindd_single_client *next = client->next;
			winbindd_remove_single_client(d, client);
			close(client->sock);
			SAFE_FREE(client->response);
			SAFE_FREE(client);
			client = next;
			continue;
		}

		if (client->sock > maxfd)
			maxfd = client->sock;

		if (client->reading)
			FD_SET(client->sock, &r_fds);
		else
			FD_SET(client->sock, &w_fds);

		client = client->next;
	}

	selret = sys_select(maxfd + 1, &r_fds, &w_fds, NULL, &timeout);

	if (selret == 0)
		return;

	if (selret == -1 && errno != EINTR) {
		perror("select");
		exit(1);
	}

	if (FD_ISSET(listen_sock, &r_fds))
		new_single_client(d, listen_sock);

	for (client = winbindd_single_client_list(d); client != NULL;
	     client = client->next) {

		if (FD_ISSET(client->sock, &r_fds))
			winbind_single_read_line(client);

		if ((client->reading) &&
		    (client->bytes_read > 0) &&
		    (client->request[client->bytes_read-1] == '\n')) {
			client->request[client->bytes_read-1] = '\0';
			winbind_single_process(d, client);
			client->reading = False;
			client->bytes_written = 0;
		}

		if (FD_ISSET(client->sock, &w_fds))
			winbind_single_write_line(client);
	}
}

static struct winbindd_single_function lsa_functions[] = {
	{ "nametosid", winbindd_lsa_nametosid },
	{ "sidtoname", winbindd_lsa_sidtoname },
	{ "enumtrust", winbindd_lsa_enumtrust },
	{ "dominfo", winbindd_lsa_dominfo },
	{ NULL, NULL }
};

static struct winbindd_single_function samr_functions[] = {
	{ "enumusers", winbindd_samr_enumusers },
	{ "groupmem", winbindd_samr_groupmem },
	{ "usergroups", winbindd_samr_usergroups },
	{ NULL, NULL }
};

static struct winbindd_single_function idmap_functions[] = {
	{ "sidtouid", winbindd_idmap_sidtouid },
	{ "sidtogid", winbindd_idmap_sidtogid },
	{ "uidtosid", winbindd_idmap_uidtosid },
	{ "gidtosid", winbindd_idmap_gidtosid },
	{ NULL, NULL }
};

static NTSTATUS prepare_lsa_pol(TALLOC_CTX *mem_ctx,
				struct winbindd_single_daemon *d)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	result = cli_full_connection(&d->cli, global_myname(), d->conn.dc_name,
				     &d->conn.dc_ip, 0, "IPC$", "IPC", "", "",
				     "", 0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("Child: Could not open IPC$: %s\n",
			  nt_errstr(result)));
		return result;
	}

	if (!cli_nt_session_open(d->cli, PI_LSARPC)) {
		DEBUG(0, ("Child: Could not open pipe: %s\n",
			  nt_errstr(result)));
		return result;
	}

	result = cli_lsa_open_policy(d->cli, mem_ctx, True,
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &d->pol);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("Child: Could not open lsa policy: %s\n",
			  nt_errstr(result)));
		return result;
	}

	return result;
}

static NTSTATUS prepare_samr_pol(TALLOC_CTX *mem_ctx,
				 struct winbindd_single_daemon *d)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol;

	result = cli_full_connection(&d->cli, global_myname(), d->conn.dc_name,
				     &d->conn.dc_ip, 0, "IPC$", "IPC", "", "",
				     "", 0, Undefined, NULL);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("Child: Could not open IPC$: %s\n",
			  nt_errstr(result)));
		return result;
	}

	if (!cli_nt_session_open(d->cli, PI_SAMR)) {
		DEBUG(0, ("Child: Could not open pipe: %s\n",
			  nt_errstr(result)));
		return result;
	}

	result = cli_samr_connect(d->cli, mem_ctx, SEC_RIGHTS_MAXIMUM_ALLOWED,
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("Child: Could not connect to SAM: %s\n",
			  nt_errstr(result)));
		return result;
	}

	result = cli_samr_open_domain(d->cli, mem_ctx, &connect_pol,
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      &d->conn.sam_sid,
				      &d->pol);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("Child: Could not open domain %s: %s\n",
			  sid_string_static(&d->conn.sam_sid),
			  nt_errstr(result)));
		return result;
	}
	return result;
}

static struct winbindd_child *children = NULL;

static BOOL check_child(TALLOC_CTX *mem_ctx, struct winbindd_child *child)
{
	pid_t pid;

	if (!wb_fetchpid(child->conn.socket_name, &pid))
		return False;

	if (pid != child->pid) {
		kill(pid, SIGTERM);
		return False;
	}

	return True;
}

static BOOL restart_child(TALLOC_CTX *mem_ctx, struct winbindd_child *child)
{
	struct winbindd_single_daemon d;
	NTSTATUS result;

	child->pid = fork();

	if (child->pid != 0) {
		if (check_child(mem_ctx, child))
			return True;
		smb_msleep(100);
		return check_child(mem_ctx, child);
	}

	winbindd_init_single_daemon(&d);
	d.conn = child->conn;

	if (open_single_socket(&d) < 0) {
		DEBUG(0, ("Could not open socket\n"));
		exit(1);
	}

	DEBUG(0, ("Child %s\n", d.conn.socket_name));

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
		_exit(0);
	}

	/* We can not share tcp connections to DCs with our parent */
	cm_close_all_connections();

	switch (child->conn.type) {
	case WB_LSA_PROXY:
		d.functions = lsa_functions;
		result = prepare_lsa_pol(mem_ctx, &d);
		break;
	case WB_SAMR_PROXY:
		d.functions = samr_functions;
		result = prepare_samr_pol(mem_ctx, &d);
		break;
	case WB_IDMAP_DAEMON:
		d.functions = idmap_functions;
		result = NT_STATUS_OK;
		break;
	default:
		smb_panic("Unknown child type\n");
		break;
	}

	if (!NT_STATUS_IS_OK(result))
		exit(1);

	CatchSignal(SIGINT, single_termination_handler);
	CatchSignal(SIGQUIT, single_termination_handler);
	CatchSignal(SIGTERM, single_termination_handler);

	while (1)
		process_single_loop(&d);
}

static BOOL new_samr_child(TALLOC_CTX *mem_ctx,
			   const char *domain_name, const DOM_SID *sid)
{
	struct winbindd_child *child;

	child = malloc(sizeof(*child));

	if (child == NULL) {
		DEBUG(0, ("Could not malloc child\n"));
		return False;
	}

	child->conn.type = WB_SAMR_PROXY;
	fstr_sprintf(child->conn.socket_name, "samr-%s",
		     sid_string_static(sid));
	fstrcpy(child->conn.domain_name, domain_name);
	sid_copy(&child->conn.sam_sid, sid);
	child->pid = -1;

	if (!get_dc_name(child->conn.domain_name, NULL, child->conn.dc_name,
			 &child->conn.dc_ip)) {
		DEBUG(0, ("Could not find DC for %s\n",
			  child->conn.domain_name));
		free(child);
		return False;
	}

	DLIST_ADD(children, child);

	return restart_child(mem_ctx, child);
}

void check_children(void)
{
	TALLOC_CTX *mem_ctx;
	struct winbindd_child *child;
	struct winbindd_child *lsa_child;
	struct wb_client_state state;

	int num_domains;
	char **domain_names = NULL;
	char **sid_strings = NULL;
	int i;

	mem_ctx = talloc_init("check_children");

	if (mem_ctx == NULL) {
		DEBUG(0, ("Could not talloc_init\n"));
		return;
	}

	lsa_child = NULL;

	wb_init_client_state(&state);

	for (child = children; child != NULL; child = child->next) {
		if (child->conn.type == WB_LSA_PROXY) {
			SMB_ASSERT(lsa_child == NULL);
			lsa_child = child;
		}

		if (!check_child(mem_ctx, child) &&
		    !restart_child(mem_ctx, child)) {
			DEBUG(1, ("Could not restart child for %d\n",
				  child->pid));
		}
	}

	/* We have to have one and only one lsa child */
	SMB_ASSERT(lsa_child != NULL);

	if (!wb_enumtrust(&state, &num_domains, &domain_names, &sid_strings)) {
		DEBUG(1, ("Could not list trusted domains\n"));
		goto done;
	}

	wb_add_ourself(&state, &num_domains, &domain_names, &sid_strings);

	for (i=0; i<num_domains; i++) {

		DOM_SID sid;
		BOOL found = False;

		if (!string_to_sid(&sid, sid_strings[i]))
			continue;

		for (child = children; child != NULL; child = child->next) {

			if (child->conn.type != WB_SAMR_PROXY)
				continue;

			if (sid_compare(&child->conn.sam_sid, &sid) != 0)
				continue;

			found = True;
		}

		if (found)
			continue;

		/* New trust */

		if (!new_samr_child(mem_ctx, domain_names[i], &sid)) {
			DEBUG(1, ("Could not start new child for %s\n",
				  domain_names[i]));
		}

		SAFE_FREE(domain_names[i]);
		SAFE_FREE(sid_strings[i]);
	}
 done:
	SAFE_FREE(domain_names);
	SAFE_FREE(sid_strings);
	wb_destroy_client_state(&state);
	return;
}

static BOOL get_tgt(time_t *expire_time)
{
	BOOL result = False;

#ifdef HAVE_KRB5

	int ret;
	char *machine_password = NULL;
	char *machine_krb5_principal = NULL;

	/* If there's more than an hour left, don't bother the DC. */
	if ((*expire_time - time(NULL)) > 3600)
		return True;

	if (!secrets_init())
		return False;

	/* Use in-memory credentials cache */
	setenv(KRB5_ENV_CCNAME, "MEMORY:cliconnect", 1);

	machine_password = secrets_fetch_machine_password(lp_workgroup(),
							  NULL, NULL);

	if (machine_password == NULL)
		goto done;

	if (asprintf(&machine_krb5_principal, "%s$@%s",
		     global_myname(), lp_realm()) == -1)
		goto done;

	ret = kerberos_kinit_password(machine_krb5_principal, machine_password,
				      0 /* no time correction for now */,
				      NULL);

	if (ret != 0) {
		DEBUG(0, ("Kinit failed: %s\n", error_message(ret)));
		goto done;
	}

	result = True;

 done:

	SAFE_FREE(machine_password);
	SAFE_FREE(machine_krb5_principal);

#endif

	return result;
}

void do_single_daemons(void)
{
	struct winbindd_child *child;

	child = malloc(sizeof(*child));

	if (child == NULL) {
		DEBUG(0, ("Could not malloc child\n"));
		return;
	}

	child->conn.type = WB_LSA_PROXY;
	fstrcpy(child->conn.socket_name, "lsa");
	fstrcpy(child->conn.domain_name, lp_workgroup());
	child->pid = -1;

	if (!get_dc_name(child->conn.domain_name, NULL, child->conn.dc_name,
			 &child->conn.dc_ip)) {
		DEBUG(0, ("Could not find our DC\n"));
		free(child);
		return;
	}

	DLIST_ADD(children, child);

	child = malloc(sizeof(*child));

	if (child == NULL) {
		DEBUG(0, ("Could not malloc child\n"));
		return;
	}

	child->conn.type = WB_IDMAP_DAEMON;
	fstrcpy(child->conn.socket_name, "idmap");
	
	DLIST_ADD(children, child);

	check_children();
}
