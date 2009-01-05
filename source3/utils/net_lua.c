/*
 *  Unix SMB/CIFS implementation.
 *  Lua experiments
 *  Copyright (C) Volker Lendecke 2006
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "utils/net.h"

#include "lua-5.1.4/src/lualib.h"
#include "lua-5.1.4/src/lauxlib.h"

#define SOCK_METATABLE "cade1208-9029-4d76-8748-426dfc1436f7"

struct sock_userdata {
	int fd;
};

static int sock_userdata_gc(lua_State *L)
{
	struct sock_userdata *p = (struct sock_userdata *)
		luaL_checkudata(L, 1, SOCK_METATABLE);
	close(p->fd);
	return 0;
}

static int sock_userdata_tostring(lua_State *L)
{
	struct sock_userdata *p = (struct sock_userdata *)
		luaL_checkudata(L, 1, SOCK_METATABLE);

	lua_pushfstring(L, "socket: %d", p->fd);
	return 1;
}

static int sock_userdata_connect(lua_State *L)
{
	struct sock_userdata *p = (struct sock_userdata *)
		luaL_checkudata(L, 1, SOCK_METATABLE);
	const char *hostname;
	int port;
	struct sockaddr_in addr;
	int res;

	if (!lua_isstring(L, 2)) {
		luaL_error(L, "connect: Expected IP-Address");
	}
	hostname = lua_tostring(L, 2);

	if (!lua_isnumber(L, 3)) {
		luaL_error(L, "connect: Expected port");
	}
	port = lua_tointeger(L, 3);

	if (lua_gettop(L) == 4) {
		/*
		 * Here we expect an event context in the last argument to
		 * make connect() asynchronous.
		 */
	}

	addr.sin_family = AF_INET;
	inet_aton(hostname, &addr.sin_addr);
	addr.sin_port = htons(port);

	res = connect(p->fd, (struct sockaddr *)&addr, sizeof(addr));
	if (res == -1) {
		int err = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "connect failed: %s", strerror(err));
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static const struct luaL_Reg sock_methods[] = {
	{"__gc",	sock_userdata_gc},
	{"__tostring",	sock_userdata_tostring},
	{"connect",	sock_userdata_connect},
	{NULL, NULL}
};

static const struct {
	const char *name;
	int domain;
} socket_domains[] = {
	{"PF_UNIX", PF_UNIX},
	{"PF_INET", PF_INET},
	{NULL, 0},
};

static const struct {
	const char *name;
	int type;
} socket_types[] = {
	{"SOCK_STREAM", SOCK_STREAM},
	{"SOCK_DGRAM", SOCK_DGRAM},
	{NULL, 0},
};

static int sock_userdata_new(lua_State *L)
{
	struct sock_userdata *result;
	const char *domain_str = luaL_checkstring(L, 1);
	const char *type_str = luaL_checkstring(L, 2);
	int i, domain, type;

	i = 0;
	while (socket_domains[i].name != NULL) {
		if (strcmp(domain_str, socket_domains[i].name) == 0) {
			break;
		}
		i += 1;
	}
	if (socket_domains[i].name == NULL) {
		return luaL_error(L, "socket domain %s unknown", domain_str);
	}
	domain = socket_domains[i].domain;

	i = 0;
	while (socket_types[i].name != NULL) {
		if (strcmp(type_str, socket_types[i].name) == 0) {
			break;
		}
		i += 1;
	}
	if (socket_types[i].name == NULL) {
		return luaL_error(L, "socket type %s unknown", type_str);
	}
	type = socket_types[i].type;

	result = (struct sock_userdata *)lua_newuserdata(L, sizeof(*result));
	ZERO_STRUCTP(result);

	result->fd = socket(domain, type, 0);
	if (result->fd == -1) {
		int err = errno;
		lua_pushnil(L);
		lua_pushfstring(L, "socket() failed: %s", strerror(errno));
		lua_pushinteger(L, err);
		return 3;
	}

	luaL_getmetatable(L, SOCK_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static const struct luaL_Reg sock_funcs[] = {
	{"new",		sock_userdata_new},
	{NULL, NULL}
};

static int sock_lua_init(lua_State *L, const char *libname) {
	luaL_newmetatable(L, SOCK_METATABLE);

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	luaL_register(L, NULL, sock_methods);
	luaL_register(L, libname, sock_funcs);
	return 1;
}

#define EVT_METATABLE "c42e0642-b24a-40f0-8483-d8eb4aee9ea3"

/*
 * The userdata we allocate from lua when a new event context is created
 */
struct evt_userdata {
	struct event_context *ev;
};

static bool evt_is_main_thread(lua_State *L) {
	int ret;

	ret = lua_pushthread(L);
	lua_pop(L, 1);
	return (ret != 0);
}

/*
 * Per event we allocate a struct thread_reference to keep the coroutine from
 * being garbage-collected. This is also the hook to find the right thread to
 * be resumed.
 */

struct thread_reference {
	struct lua_State *L;
	/*
	 * Reference to the Thread (i.e. lua_State) this event is hanging on
	 */
	int thread_ref;
};

static int thread_reference_destructor(struct thread_reference *ref)
{
	luaL_unref(ref->L, LUA_REGISTRYINDEX, ref->thread_ref);
	return 0;
}

static struct thread_reference *evt_reference_thread(TALLOC_CTX *mem_ctx,
						     lua_State *L)
{
	struct thread_reference *result;

	result = talloc(mem_ctx, struct thread_reference);
	if (result == NULL) {
		return NULL;
	}

	lua_pushthread(L);
	result->thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	result->L = L;
	talloc_set_destructor(result, thread_reference_destructor);

	return result;
}

static int evt_userdata_gc(lua_State *L)
{
	struct evt_userdata *p = (struct evt_userdata *)
		luaL_checkudata(L, 1, EVT_METATABLE);
	TALLOC_FREE(p->ev);
	return 0;
}

static int evt_userdata_tostring(lua_State *L) {
	lua_pushstring(L, "event context");
	return 1;
}

static void evt_userdata_sleep_done(struct event_context *event_ctx,
				   struct timed_event *te,
				   struct timeval now,
				   void *priv)
{
	struct thread_reference *ref = talloc_get_type_abort(
		priv, struct thread_reference);
	lua_resume(ref->L, 0);
	TALLOC_FREE(ref);
}

static int evt_userdata_sleep(lua_State *L)
{
	struct evt_userdata *p = (struct evt_userdata *)
		luaL_checkudata(L, 1, EVT_METATABLE);
	lua_Integer usecs = luaL_checkint(L, 2);
	struct thread_reference *ref;
	struct timed_event *te;

	if (evt_is_main_thread(L)) {
		/*
		 * Block in the main thread
		 */
		smb_msleep(usecs/1000);
		return 0;
	}

	ref = evt_reference_thread(p->ev, L);
	if (ref == NULL) {
		return luaL_error(L, "evt_reference_thread failed\n");
	}

	te = event_add_timed(p->ev, ref, timeval_current_ofs(0, usecs),
			     evt_userdata_sleep_done,
			     ref);

	if (te == NULL) {
		TALLOC_FREE(ref);
		return luaL_error(L, "event_add_timed failed");
	}

	return lua_yield(L, 0);
}

static int evt_userdata_once(lua_State *L)
{
	struct evt_userdata *p = (struct evt_userdata *)
		luaL_checkudata(L, 1, EVT_METATABLE);

	if (!evt_is_main_thread(L)) {
		return luaL_error(L, "event_once called from non-base thread");
	}

	lua_pushinteger(L, event_loop_once(p->ev));
	return 1;
}

static const struct luaL_Reg evt_methods[] = {
	{"__gc",	evt_userdata_gc},
	{"__tostring",	evt_userdata_tostring},
	{"sleep",	evt_userdata_sleep},
	{"once",	evt_userdata_once},
	{NULL, NULL}
};

static int evt_userdata_new(lua_State *L) {
	struct evt_userdata *result;

	result = (struct evt_userdata *)lua_newuserdata(L, sizeof(*result));
	ZERO_STRUCTP(result);

	result->ev = event_context_init(NULL);
	if (result->ev == NULL) {
		return luaL_error(L, "event_context_init failed");
	}

	luaL_getmetatable(L, EVT_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static const struct luaL_Reg evt_funcs[] = {
	{"new",		evt_userdata_new},
	{NULL, NULL}
};

static int evt_lua_init(lua_State *L, const char *libname) {
	luaL_newmetatable(L, EVT_METATABLE);

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	luaL_register(L, NULL, evt_methods);
	luaL_register(L, libname, evt_funcs);
	return 1;
}

int net_lua(struct net_context *c, int argc, const char **argv)
{
	lua_State *state;

	state = lua_open();
	if (state == NULL) {
		d_fprintf(stderr, "lua_newstate failed\n");
		return -1;
	}

	luaL_openlibs(state);
	evt_lua_init(state, "event");
	sock_lua_init(state, "socket");

	while (1) {
		char *line = NULL;

		line = smb_readline("lua> ", NULL, NULL);
		if (line == NULL) {
			break;
		}

		if (line[0] == ':') {
			if (luaL_dofile(state, &line[1])) {
				d_printf("luaL_dofile returned an error\n");
				continue;
			}
		} else if (line[0] != '\n') {
			if (luaL_dostring(state, line) != 0) {
				d_printf("luaL_dostring returned an error\n");
			}
		}

		SAFE_FREE(line);
	}

	lua_close(state);
	return -1;
}
