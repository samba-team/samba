/*
  add to build farm
  add masktest and locktest too
  add -W flag
  convert to popt_common
*/

/* 
   Unix SMB/CIFS implementation.
   generic testing tool
   Copyright (C) Andrew Tridgell 2003
   
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
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/raw/request.h"
#include "libcli/libcli.h"
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/security.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

#define NSERVERS 2
#define NINSTANCES 2

/* global options */
static struct gentest_options {
	BOOL showall;
	BOOL analyze;
	BOOL analyze_always;
	BOOL analyze_continuous;
	uint_t max_open_handles;
	uint_t seed;
	uint_t numops;
	BOOL use_oplocks;
	char **ignore_patterns;
	const char *seeds_file;
	BOOL use_preset_seeds;
	BOOL fast_reconnect;
} options;

/* mapping between open handles on the server and local handles */
static struct {
	BOOL active;
	uint_t instance;
	uint_t server_fnum[NSERVERS];
	const char *name;
} *open_handles;
static uint_t num_open_handles;

/* state information for the servers. We open NINSTANCES connections to
   each server */
static struct {
	struct smbcli_state *cli[NINSTANCES];
	char *server_name;
	char *share_name;
	struct cli_credentials *credentials;
} servers[NSERVERS];

/* the seeds and flags for each operation */
static struct {
	uint_t seed;
	BOOL disabled;
} *op_parms;


/* oplock break info */
static struct {
	BOOL got_break;
	uint16_t fnum;
	uint16_t handle;
	uint8_t level;
	BOOL do_close;
} oplocks[NSERVERS][NINSTANCES];

/* change notify reply info */
static struct {
	int notify_count;
	NTSTATUS status;
	union smb_notify notify;
} notifies[NSERVERS][NINSTANCES];

/* info relevant to the current operation */
static struct {
	const char *name;
	uint_t seed;
	NTSTATUS status;
	uint_t opnum;
	TALLOC_CTX *mem_ctx;
} current_op;



#define BAD_HANDLE 0xFFFE

static BOOL oplock_handler(struct smbcli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *private);
static void idle_func(struct smbcli_transport *transport, void *private);

/*
  check if a string should be ignored. This is used as the basis
  for all error ignore settings
*/
static BOOL ignore_pattern(const char *str)
{
	int i;
	if (!options.ignore_patterns) return False;

	for (i=0;options.ignore_patterns[i];i++) {
		if (strcmp(options.ignore_patterns[i], str) == 0 ||
		    gen_fnmatch(options.ignore_patterns[i], str) == 0) {
			DEBUG(2,("Ignoring '%s'\n", str));
			return True;
		}
	}
	return False;
}

/***************************************************** 
connect to the servers
*******************************************************/
static BOOL connect_servers_fast(void)
{
	int h, i;

	/* close all open files */
	for (h=0;h<options.max_open_handles;h++) {
		if (!open_handles[h].active) continue;
		for (i=0;i<NSERVERS;i++) {
			if (NT_STATUS_IS_ERR((smbcli_close(servers[i].cli[open_handles[h].instance]->tree,
				       open_handles[h].server_fnum[i])))) {
				return False;
			}
			open_handles[h].active = False;
		}
	}

	return True;
}




/***************************************************** 
connect to the servers
*******************************************************/
static BOOL connect_servers(void)
{
	int i, j;

	if (options.fast_reconnect && servers[0].cli[0]) {
		if (connect_servers_fast()) {
			return True;
		}
	}

	/* close any existing connections */
	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (servers[i].cli[j]) {
				smbcli_tdis(servers[i].cli[j]);
				talloc_free(servers[i].cli[j]);
				servers[i].cli[j] = NULL;
			}
		}
	}

	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			NTSTATUS status;
			printf("Connecting to \\\\%s\\%s as %s - instance %d\n",
			       servers[i].server_name, servers[i].share_name, 
			       servers[i].credentials->username, j);

			cli_credentials_set_workstation(servers[i].credentials, 
							"gentest", CRED_SPECIFIED);

			status = smbcli_full_connection(NULL, &servers[i].cli[j],
							servers[i].server_name, 
							servers[i].share_name, NULL, 
							servers[i].credentials, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Failed to connect to \\\\%s\\%s - %s\n",
				       servers[i].server_name, servers[i].share_name,
				       nt_errstr(status));
				return False;
			}

			smbcli_oplock_handler(servers[i].cli[j]->transport, oplock_handler, NULL);
			smbcli_transport_idle_handler(servers[i].cli[j]->transport, idle_func, 50000, NULL);
		}
	}

	return True;
}

/*
  work out the time skew between the servers - be conservative
*/
static uint_t time_skew(void)
{
	uint_t ret;
	ret = labs(servers[0].cli[0]->transport->negotiate.server_time -
		  servers[1].cli[0]->transport->negotiate.server_time);
	return ret + 300;
}

/*
  turn an fnum for an instance into a handle
*/
static uint_t fnum_to_handle(int server, int instance, uint16_t fnum)
{
	uint_t i;
	for (i=0;i<options.max_open_handles;i++) {
		if (!open_handles[i].active ||
		    instance != open_handles[i].instance) continue;
		if (open_handles[i].server_fnum[server] == fnum) {
			return i;
		}
	}
	printf("Invalid fnum %d in fnum_to_handle on server %d instance %d\n", 
	       fnum, server, instance);
	return BAD_HANDLE;
}

/*
  add some newly opened handles
*/
static void gen_add_handle(int instance, const char *name, uint16_t fnums[NSERVERS])
{
	int i, h;
	for (h=0;h<options.max_open_handles;h++) {
		if (!open_handles[h].active) break;
	}
	if (h == options.max_open_handles) {
		/* we have to force close a random handle */
		h = random() % options.max_open_handles;
		for (i=0;i<NSERVERS;i++) {
			if (NT_STATUS_IS_ERR((smbcli_close(servers[i].cli[open_handles[h].instance]->tree, 
				       open_handles[h].server_fnum[i])))) {
				printf("INTERNAL ERROR: Close failed when recovering handle! - %s\n",
				       smbcli_errstr(servers[i].cli[open_handles[h].instance]->tree));
			}
		}
		printf("Recovered handle %d\n", h);
		num_open_handles--;
	}
	for (i=0;i<NSERVERS;i++) {
		open_handles[h].server_fnum[i] = fnums[i];
		open_handles[h].instance = instance;
		open_handles[h].active = True;
		open_handles[h].name = name;
	}
	num_open_handles++;

	printf("OPEN num_open_handles=%d h=%d s1=0x%x s2=0x%x (%s)\n", 
	       num_open_handles, h, 
	       open_handles[h].server_fnum[0], open_handles[h].server_fnum[1],
	       name);
}

/*
  remove a closed handle
*/
static void gen_remove_handle(int instance, uint16_t fnums[NSERVERS])
{
	int h;
	for (h=0;h<options.max_open_handles;h++) {
		if (instance == open_handles[h].instance &&
		    open_handles[h].server_fnum[0] == fnums[0]) {
			open_handles[h].active = False;			
			num_open_handles--;
			printf("CLOSE num_open_handles=%d h=%d s1=0x%x s2=0x%x (%s)\n", 
			       num_open_handles, h, 
			       open_handles[h].server_fnum[0], open_handles[h].server_fnum[1],
			       open_handles[h].name);
			return;
		}
	}
	printf("Removing invalid handle!?\n");
	exit(1);
}

/*
  return True with 'chance' probability as a percentage
*/
static BOOL gen_chance(uint_t chance)
{
	return ((random() % 100) <= chance);
}

/*
  map an internal handle number to a server fnum
*/
static uint16_t gen_lookup_fnum(int server, uint16_t handle)
{
	if (handle == BAD_HANDLE) return handle;
	return open_handles[handle].server_fnum[server];
}

/*
  return a file handle
*/
static uint16_t gen_fnum(int instance)
{
	uint16_t h;
	int count = 0;

	if (gen_chance(20)) return BAD_HANDLE;

	while (num_open_handles > 0 && count++ < 10*options.max_open_handles) {
		h = random() % options.max_open_handles;
		if (open_handles[h].active && 
		    open_handles[h].instance == instance) {
			return h;
		}
	}
	return BAD_HANDLE;
}

/*
  return a file handle, but skewed so we don't close the last
  couple of handles too readily
*/
static uint16_t gen_fnum_close(int instance)
{
	if (num_open_handles < 3) {
		if (gen_chance(80)) return BAD_HANDLE;
	}

	return gen_fnum(instance);
}

/*
  generate an integer in a specified range
*/
static int gen_int_range(uint_t min, uint_t max)
{
	uint_t r = random();
	return min + (r % (1+max-min));
}

/*
  return a fnum for use as a root fid
  be careful to call GEN_SET_FNUM() when you use this!
*/
static uint16_t gen_root_fid(int instance)
{
	if (gen_chance(5)) return gen_fnum(instance);
	if (gen_chance(2)) return BAD_HANDLE;
	return 0;
}

/*
  generate a file offset
*/
static int gen_offset(void)
{
	if (gen_chance(20)) return 0;
	return gen_int_range(0, 1024*1024);
}

/*
  generate a io count
*/
static int gen_io_count(void)
{
	if (gen_chance(20)) return 0;
	return gen_int_range(0, 4096);
}

/*
  generate a filename
*/
static const char *gen_fname(void)
{
	const char *names[] = {"\\gentest\\gentest.dat", 
			       "\\gentest\\foo", 
			       "\\gentest\\foo2.sym", 
			       "\\gentest\\foo3.dll", 
			       "\\gentest\\foo4", 
			       "\\gentest\\foo4:teststream1", 
			       "\\gentest\\foo4:teststream2", 
			       "\\gentest\\foo5.exe", 
			       "\\gentest\\foo5.exe:teststream3", 
			       "\\gentest\\foo5.exe:teststream4", 
			       "\\gentest\\foo6.com", 
			       "\\gentest\\blah", 
			       "\\gentest\\blah\\blergh.txt", 
			       "\\gentest\\blah\\blergh2", 
			       "\\gentest\\blah\\blergh3.txt", 
			       "\\gentest\\blah\\blergh4", 
			       "\\gentest\\blah\\blergh5.txt", 
			       "\\gentest\\blah\\blergh5", 
			       "\\gentest\\blah\\.", 
#if 0
			       /* this causes problem with w2k3 */
			       "\\gentest\\blah\\..", 
#endif
			       "\\gentest\\a_very_long_name.bin", 
			       "\\gentest\\x.y", 
			       "\\gentest\\blah"};
	int i;

	do {
		i = gen_int_range(0, ARRAY_SIZE(names)-1);
	} while (ignore_pattern(names[i]));

	return names[i];
}

/*
  generate a filename with a higher chance of choosing an already 
  open file
*/
static const char *gen_fname_open(int instance)
{
	uint16_t h;
	h = gen_fnum(instance);
	if (h == BAD_HANDLE) {
		return gen_fname();
	}
	return open_handles[h].name;
}

/*
  generate a wildcard pattern
*/
static const char *gen_pattern(void)
{
	int i;
	const char *names[] = {"\\gentest\\*.dat", 
			       "\\gentest\\*", 
			       "\\gentest\\*.*", 
			       "\\gentest\\blah\\*.*", 
			       "\\gentest\\blah\\*", 
			       "\\gentest\\?"};

	if (gen_chance(50)) return gen_fname();

	do {
		i = gen_int_range(0, ARRAY_SIZE(names)-1);
	} while (ignore_pattern(names[i]));

	return names[i];
}

/*
  generate a bitmask
*/
static uint32_t gen_bits_mask(uint_t mask)
{
	uint_t ret = random();
	return ret & mask;
}

/*
  generate a bitmask with high probability of the first mask
  and low of the second
*/
static uint32_t gen_bits_mask2(uint32_t mask1, uint32_t mask2)
{
	if (gen_chance(10)) return gen_bits_mask(mask2);
	return gen_bits_mask(mask1);
}

/*
  generate a boolean
*/
static BOOL gen_bool(void)
{
	return gen_bits_mask2(0x1, 0xFF);
}

/*
  generate ntrename flags
*/
static uint16_t gen_rename_flags(void)
{
	if (gen_chance(30)) return RENAME_FLAG_RENAME;
	if (gen_chance(30)) return RENAME_FLAG_HARD_LINK;
	if (gen_chance(30)) return RENAME_FLAG_COPY;
	return gen_bits_mask(0xFFFF);
}


/*
  return a lockingx lock mode
*/
static uint16_t gen_lock_mode(void)
{
	if (gen_chance(5))  return gen_bits_mask(0xFFFF);
	if (gen_chance(20)) return gen_bits_mask(0x1F);
	return gen_bits_mask(LOCKING_ANDX_SHARED_LOCK | LOCKING_ANDX_LARGE_FILES);
}

/*
  generate a pid 
*/
static uint16_t gen_pid(void)
{
	if (gen_chance(10)) return gen_bits_mask(0xFFFF);
	return getpid();
}

/*
  generate a lock count
*/
static off_t gen_lock_count(void)
{
	return gen_int_range(0, 3);
}

/*
  generate a ntcreatex flags field
*/
static uint32_t gen_ntcreatex_flags(void)
{
	if (gen_chance(70)) return NTCREATEX_FLAGS_EXTENDED;
	return gen_bits_mask2(0x1F, 0xFFFFFFFF);
}

/*
  generate a NT access mask
*/
static uint32_t gen_access_mask(void)
{
	if (gen_chance(50)) return SEC_FLAG_MAXIMUM_ALLOWED;
	if (gen_chance(20)) return SEC_FILE_ALL;
	return gen_bits_mask(0xFFFFFFFF);
}

/*
  generate a ntcreatex create options bitfield
*/
static uint32_t gen_create_options(void)
{
	if (gen_chance(20)) return gen_bits_mask(0xFFFFFFFF);
	if (gen_chance(50)) return 0;
	return gen_bits_mask(NTCREATEX_OPTIONS_DELETE_ON_CLOSE | NTCREATEX_OPTIONS_DIRECTORY);
}

/*
  generate a ntcreatex open disposition
*/
static uint32_t gen_open_disp(void)
{
	if (gen_chance(10)) return gen_bits_mask(0xFFFFFFFF);
	return gen_int_range(0, 5);
}

/*
  generate an openx open mode
*/
static uint16_t gen_openx_mode(void)
{
	if (gen_chance(20)) return gen_bits_mask(0xFFFF);
	if (gen_chance(20)) return gen_bits_mask(0xFF);
	return OPENX_MODE_DENY_NONE | gen_bits_mask(0x3);
}

/*
  generate an openx flags field
*/
static uint16_t gen_openx_flags(void)
{
	if (gen_chance(20)) return gen_bits_mask(0xFFFF);
	return gen_bits_mask(0x7);
}

/*
  generate an openx open function
*/
static uint16_t gen_openx_func(void)
{
	if (gen_chance(20)) return gen_bits_mask(0xFFFF);
	return gen_bits_mask(0x13);
}

/*
  generate a file attrib combination
*/
static uint32_t gen_attrib(void)
{
	if (gen_chance(20)) return gen_bits_mask(0xFFFFFFFF);
	return gen_bits_mask(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_DIRECTORY);
}

/*
  generate a unix timestamp
*/
static time_t gen_timet(void)
{
	if (gen_chance(30)) return 0;
	return (time_t)random();
}

/*
  generate a unix timestamp
*/
static NTTIME gen_nttime(void)
{
	NTTIME ret;
	unix_to_nt_time(&ret, gen_timet());
	return ret;
}

/*
  generate a milliseconds protocol timeout
*/
static uint32_t gen_timeout(void)
{
	if (gen_chance(98)) return 0;
	return random() % 50;
}

/*
  generate a file allocation size
*/
static uint_t gen_alloc_size(void)
{
	uint_t ret;

	if (gen_chance(30)) return 0;

	ret = random() % 4*1024*1024;
	/* give a high chance of a round number */
	if (gen_chance(60)) {
		ret &= ~(1024*1024 - 1);
	}
	return ret;
}

/*
  generate an ea_struct
*/
static struct ea_struct gen_ea_struct(void)
{
	struct ea_struct ea;
	const char *names[] = {"EAONE", 
			       "", 
			       "FOO!", 
			       " WITH SPACES ", 
			       ".", 
			       "AVERYLONGATTRIBUTENAME"};
	const char *values[] = {"VALUE1", 
			       "", 
			       "NOT MUCH FOO", 
			       " LEADING SPACES ", 
			       ":", 
			       "ASOMEWHATLONGERATTRIBUTEVALUE"};
	int i;

	ZERO_STRUCT(ea);

	do {
		i = gen_int_range(0, ARRAY_SIZE(names)-1);
	} while (ignore_pattern(names[i]));

	ea.name.s = names[i];

	do {
		i = gen_int_range(0, ARRAY_SIZE(values)-1);
	} while (ignore_pattern(values[i]));

	ea.value = data_blob(values[i], strlen(values[i]));

	if (gen_chance(10)) ea.flags = gen_bits_mask(0xFF);
	ea.flags = 0;

	return ea;
}


/*
  this is called when a change notify reply comes in
*/
static void async_notify(struct smbcli_request *req)
{
	union smb_notify notify;
	NTSTATUS status;
	int i, j;
	uint16_t tid;
	struct smbcli_transport *transport = req->transport;

	tid = SVAL(req->in.hdr, HDR_TID);

	notify.nttrans.level = RAW_NOTIFY_NTTRANS;
	status = smb_raw_changenotify_recv(req, current_op.mem_ctx, &notify);
	if (NT_STATUS_IS_OK(status)) {
		printf("notify tid=%d num_changes=%d action=%d name=%s\n", 
		       tid, 
		       notify.nttrans.out.num_changes,
		       notify.nttrans.out.changes[0].action,
		       notify.nttrans.out.changes[0].name.s);
	}

	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (transport == servers[i].cli[j]->transport &&
			    tid == servers[i].cli[j]->tree->tid) {
				notifies[i][j].notify_count++;
				notifies[i][j].status = status;
				notifies[i][j].notify = notify;
			}
		}
	}
}

static void oplock_handler_close_recv(struct smbcli_request *req)
{
	NTSTATUS status;
	status = smbcli_request_simple_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed in oplock_handler\n");
		smb_panic("close failed in oplock_handler");
	}
}

/*
  the oplock handler will either ack the break or close the file
*/
static BOOL oplock_handler(struct smbcli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *private)
{
	union smb_close io;
	int i, j;
	BOOL do_close;
	struct smbcli_tree *tree = NULL;
	struct smbcli_request *req;

	srandom(current_op.seed);
	do_close = gen_chance(50);

	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (transport == servers[i].cli[j]->transport &&
			    tid == servers[i].cli[j]->tree->tid) {
				oplocks[i][j].got_break = True;
				oplocks[i][j].fnum = fnum;
				oplocks[i][j].handle = fnum_to_handle(i, j, fnum);
				oplocks[i][j].level = level;
				oplocks[i][j].do_close = do_close;
				tree = servers[i].cli[j]->tree;
			}
		}
	}

	if (!tree) {
		printf("Oplock break not for one of our trees!?\n");
		return False;
	}

	if (!do_close) {
		printf("oplock ack fnum=%d\n", fnum);
		return smbcli_oplock_ack(tree, fnum, level);
	}

	printf("oplock close fnum=%d\n", fnum);

	io.close.level = RAW_CLOSE_CLOSE;
	io.close.in.file.fnum = fnum;
	io.close.in.write_time = 0;
	req = smb_raw_close_send(tree, &io);

	if (req == NULL) {
		printf("WARNING: close failed in oplock_handler_close\n");
		return False;
	}

	req->async.fn = oplock_handler_close_recv;
	req->async.private = NULL;

	return True;
}


/*
  the idle function tries to cope with getting an oplock break on a connection, and
  an operation on another connection blocking until that break is acked
  we check for operations on all transports in the idle function
*/
static void idle_func(struct smbcli_transport *transport, void *private)
{
	int i, j;
	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (servers[i].cli[j] &&
			    transport != servers[i].cli[j]->transport) {
				smbcli_transport_process(servers[i].cli[j]->transport);
			}
		}
	}

}


/*
  compare NTSTATUS, using checking ignored patterns
*/
static BOOL compare_status(NTSTATUS status1, NTSTATUS status2)
{
	if (NT_STATUS_EQUAL(status1, status2)) return True;

	/* one code being an error and the other OK is always an error */
	if (NT_STATUS_IS_OK(status1) || NT_STATUS_IS_OK(status2)) return False;

	/* if we are ignoring one of the status codes then consider this a match */
	if (ignore_pattern(nt_errstr(status1)) ||
	    ignore_pattern(nt_errstr(status2))) {
		return True;
	}
	return False;
}


/*
  check for pending packets on all connections
*/
static void check_pending(void)
{
	int i, j;

	msleep(20);

	for (j=0;j<NINSTANCES;j++) {
		for (i=0;i<NSERVERS;i++) {
			smbcli_transport_process(servers[i].cli[j]->transport);
		}
	}	
}

/*
  check that the same oplock breaks have been received by all instances
*/
static BOOL check_oplocks(const char *call)
{
	int i, j;
	int tries = 0;

again:
	check_pending();

	for (j=0;j<NINSTANCES;j++) {
		for (i=1;i<NSERVERS;i++) {
			if (oplocks[0][j].got_break != oplocks[i][j].got_break ||
			    oplocks[0][j].handle != oplocks[i][j].handle ||
			    oplocks[0][j].level != oplocks[i][j].level) {
				if (tries++ < 10) goto again;
				printf("oplock break inconsistent - %d/%d/%d vs %d/%d/%d\n",
				       oplocks[0][j].got_break, 
				       oplocks[0][j].handle, 
				       oplocks[0][j].level, 
				       oplocks[i][j].got_break, 
				       oplocks[i][j].handle, 
				       oplocks[i][j].level);
				return False;
			}
		}
	}

	/* if we got a break and closed then remove the handle */
	for (j=0;j<NINSTANCES;j++) {
		if (oplocks[0][j].got_break &&
		    oplocks[0][j].do_close) {
			uint16_t fnums[NSERVERS];
			for (i=0;i<NSERVERS;i++) {
				fnums[i] = oplocks[i][j].fnum;
			}
			gen_remove_handle(j, fnums);
			break;
		}
	}	
	return True;
}


/*
  check that the same change notify info has been received by all instances
*/
static BOOL check_notifies(const char *call)
{
	int i, j;
	int tries = 0;

again:
	check_pending();

	for (j=0;j<NINSTANCES;j++) {
		for (i=1;i<NSERVERS;i++) {
			int n;
			union smb_notify not1, not2;

			if (notifies[0][j].notify_count != notifies[i][j].notify_count) {
				if (tries++ < 10) goto again;
				printf("Notify count inconsistent %d %d\n",
				       notifies[0][j].notify_count,
				       notifies[i][j].notify_count);
				return False;
			}

			if (notifies[0][j].notify_count == 0) continue;

			if (!NT_STATUS_EQUAL(notifies[0][j].status,
					     notifies[i][j].status)) {
				printf("Notify status mismatch - %s - %s\n",
				       nt_errstr(notifies[0][j].status),
				       nt_errstr(notifies[i][j].status));
				return False;
			}

			if (!NT_STATUS_IS_OK(notifies[0][j].status)) {
				continue;
			}

			not1 = notifies[0][j].notify;
			not2 = notifies[i][j].notify;

			for (n=0;n<not1.nttrans.out.num_changes;n++) {
				if (not1.nttrans.out.changes[n].action != 
				    not2.nttrans.out.changes[n].action) {
					printf("Notify action %d inconsistent %d %d\n", n,
					       not1.nttrans.out.changes[n].action,
					       not2.nttrans.out.changes[n].action);
					return False;
				}
				if (strcmp(not1.nttrans.out.changes[n].name.s,
					   not2.nttrans.out.changes[n].name.s)) {
					printf("Notify name %d inconsistent %s %s\n", n,
					       not1.nttrans.out.changes[n].name.s,
					       not2.nttrans.out.changes[n].name.s);
					return False;
				}
				if (not1.nttrans.out.changes[n].name.private_length !=
				    not2.nttrans.out.changes[n].name.private_length) {
					printf("Notify name length %d inconsistent %d %d\n", n,
					       not1.nttrans.out.changes[n].name.private_length,
					       not2.nttrans.out.changes[n].name.private_length);
					return False;
				}
			}
		}
	}

	ZERO_STRUCT(notifies);

	return True;
}


#define GEN_COPY_PARM do { \
	int i; \
	for (i=1;i<NSERVERS;i++) { \
		parm[i] = parm[0]; \
	} \
} while (0)

#define GEN_CALL(call) do { \
	int i; \
	ZERO_STRUCT(oplocks); \
	ZERO_STRUCT(notifies); \
	for (i=0;i<NSERVERS;i++) { \
		struct smbcli_tree *tree = servers[i].cli[instance]->tree; \
		status[i] = call; \
	} \
	current_op.status = status[0]; \
	for (i=1;i<NSERVERS;i++) { \
		if (!compare_status(status[i], status[0])) { \
			printf("status different in %s - %s %s\n", #call, \
			       nt_errstr(status[0]), nt_errstr(status[i])); \
			return False; \
		} \
	} \
	if (!check_oplocks(#call)) return False; \
	if (!check_notifies(#call)) return False; \
	if (!NT_STATUS_IS_OK(status[0])) { \
		return True; \
	} \
} while(0)

#define ADD_HANDLE(name, field) do { \
	uint16_t fnums[NSERVERS]; \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		fnums[i] = parm[i].field; \
	} \
	gen_add_handle(instance, name, fnums); \
} while(0)

#define REMOVE_HANDLE(field) do { \
	uint16_t fnums[NSERVERS]; \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		fnums[i] = parm[i].field; \
	} \
	gen_remove_handle(instance, fnums); \
} while(0)

#define GEN_SET_FNUM(field) do { \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		parm[i].field = gen_lookup_fnum(i, parm[i].field); \
	} \
} while(0)

#define CHECK_EQUAL(field) do { \
	if (parm[0].field != parm[1].field && !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%x 0x%x\n", #field, \
		       (int)parm[0].field, (int)parm[1].field); \
		return False; \
	} \
} while(0)

#define CHECK_WSTR_EQUAL(field) do { \
	if ((!parm[0].field.s && parm[1].field.s) || (parm[0].field.s && !parm[1].field.s)) { \
		printf("%s is NULL!\n", #field); \
		return False; \
	} \
	if (parm[0].field.s && strcmp(parm[0].field.s, parm[1].field.s) != 0 && !ignore_pattern(#field)) { \
		printf("Mismatch in %s - %s %s\n", #field, \
		       parm[0].field.s, parm[1].field.s); \
		return False; \
	} \
	CHECK_EQUAL(field.private_length); \
} while(0)

#define CHECK_BLOB_EQUAL(field) do { \
	if (memcmp(parm[0].field.data, parm[1].field.data, parm[0].field.length) != 0 && !ignore_pattern(#field)) { \
		printf("Mismatch in %s\n", #field); \
		return False; \
	} \
	CHECK_EQUAL(field.length); \
} while(0)

#define CHECK_TIMES_EQUAL(field) do { \
	if (labs(parm[0].field - parm[1].field) > time_skew() && \
	    !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%x 0x%x\n", #field, \
		       (int)parm[0].field, (int)parm[1].field); \
		return False; \
	} \
} while(0)

#define CHECK_NTTIMES_EQUAL(field) do { \
	if (labs(nt_time_to_unix(parm[0].field) - \
		nt_time_to_unix(parm[1].field)) > time_skew() && \
	    !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%x 0x%x\n", #field, \
		       (int)nt_time_to_unix(parm[0].field), \
		       (int)nt_time_to_unix(parm[1].field)); \
		return False; \
	} \
} while(0)

/*
  generate openx operations
*/
static BOOL handler_openx(int instance)
{
	union smb_open parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].openx.level = RAW_OPEN_OPENX;
	parm[0].openx.in.flags = gen_openx_flags();
	parm[0].openx.in.open_mode = gen_openx_mode();
	parm[0].openx.in.search_attrs = gen_attrib();
	parm[0].openx.in.file_attrs = gen_attrib();
	parm[0].openx.in.write_time = gen_timet();
	parm[0].openx.in.open_func = gen_openx_func();
	parm[0].openx.in.size = gen_io_count();
	parm[0].openx.in.timeout = gen_timeout();
	parm[0].openx.in.fname = gen_fname_open(instance);

	if (!options.use_oplocks) {
		/* mask out oplocks */
		parm[0].openx.in.flags &= ~(OPENX_FLAGS_REQUEST_OPLOCK|
					    OPENX_FLAGS_REQUEST_BATCH_OPLOCK);
	}
	
	GEN_COPY_PARM;
	GEN_CALL(smb_raw_open(tree, current_op.mem_ctx, &parm[i]));

	CHECK_EQUAL(openx.out.attrib);
	CHECK_EQUAL(openx.out.size);
	CHECK_EQUAL(openx.out.access);
	CHECK_EQUAL(openx.out.ftype);
	CHECK_EQUAL(openx.out.devstate);
	CHECK_EQUAL(openx.out.action);
	CHECK_EQUAL(openx.out.access_mask);
	CHECK_EQUAL(openx.out.unknown);
	CHECK_TIMES_EQUAL(openx.out.write_time);

	/* open creates a new file handle */
	ADD_HANDLE(parm[0].openx.in.fname, openx.out.file.fnum);

	return True;
}


/*
  generate open operations
*/
static BOOL handler_open(int instance)
{
	union smb_open parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].openold.level = RAW_OPEN_OPEN;
	parm[0].openold.in.open_mode = gen_bits_mask2(0xF, 0xFFFF);
	parm[0].openold.in.search_attrs = gen_attrib();
	parm[0].openold.in.fname = gen_fname_open(instance);

	if (!options.use_oplocks) {
		/* mask out oplocks */
		parm[0].openold.in.open_mode &= ~(OPENX_FLAGS_REQUEST_OPLOCK|
						  OPENX_FLAGS_REQUEST_BATCH_OPLOCK);
	}
	
	GEN_COPY_PARM;
	GEN_CALL(smb_raw_open(tree, current_op.mem_ctx, &parm[i]));

	CHECK_EQUAL(openold.out.attrib);
	CHECK_TIMES_EQUAL(openold.out.write_time);
	CHECK_EQUAL(openold.out.size);
	CHECK_EQUAL(openold.out.rmode);

	/* open creates a new file handle */
	ADD_HANDLE(parm[0].openold.in.fname, openold.out.file.fnum);

	return True;
}


/*
  generate ntcreatex operations
*/
static BOOL handler_ntcreatex(int instance)
{
	union smb_open parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].ntcreatex.level = RAW_OPEN_NTCREATEX;
	parm[0].ntcreatex.in.flags = gen_ntcreatex_flags();
	parm[0].ntcreatex.in.root_fid = gen_root_fid(instance);
	parm[0].ntcreatex.in.access_mask = gen_access_mask();
	parm[0].ntcreatex.in.alloc_size = gen_alloc_size();
	parm[0].ntcreatex.in.file_attr = gen_attrib();
	parm[0].ntcreatex.in.share_access = gen_bits_mask2(0x7, 0xFFFFFFFF);
	parm[0].ntcreatex.in.open_disposition = gen_open_disp();
	parm[0].ntcreatex.in.create_options = gen_create_options();
	parm[0].ntcreatex.in.impersonation = gen_bits_mask2(0, 0xFFFFFFFF);
	parm[0].ntcreatex.in.security_flags = gen_bits_mask2(0, 0xFF);
	parm[0].ntcreatex.in.fname = gen_fname_open(instance);

	if (!options.use_oplocks) {
		/* mask out oplocks */
		parm[0].ntcreatex.in.flags &= ~(NTCREATEX_FLAGS_REQUEST_OPLOCK|
						NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK);
	}
	
	GEN_COPY_PARM;
	if (parm[0].ntcreatex.in.root_fid != 0) {
		GEN_SET_FNUM(ntcreatex.in.root_fid);
	}
	GEN_CALL(smb_raw_open(tree, current_op.mem_ctx, &parm[i]));

	CHECK_EQUAL(ntcreatex.out.oplock_level);
	CHECK_EQUAL(ntcreatex.out.create_action);
	CHECK_NTTIMES_EQUAL(ntcreatex.out.create_time);
	CHECK_NTTIMES_EQUAL(ntcreatex.out.access_time);
	CHECK_NTTIMES_EQUAL(ntcreatex.out.write_time);
	CHECK_NTTIMES_EQUAL(ntcreatex.out.change_time);
	CHECK_EQUAL(ntcreatex.out.attrib);
	CHECK_EQUAL(ntcreatex.out.alloc_size);
	CHECK_EQUAL(ntcreatex.out.size);
	CHECK_EQUAL(ntcreatex.out.file_type);
	CHECK_EQUAL(ntcreatex.out.ipc_state);
	CHECK_EQUAL(ntcreatex.out.is_directory);

	/* ntcreatex creates a new file handle */
	ADD_HANDLE(parm[0].ntcreatex.in.fname, ntcreatex.out.file.fnum);

	return True;
}

/*
  generate close operations
*/
static BOOL handler_close(int instance)
{
	union smb_close parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].close.level = RAW_CLOSE_CLOSE;
	parm[0].close.in.file.fnum = gen_fnum_close(instance);
	parm[0].close.in.write_time = gen_timet();

	GEN_COPY_PARM;
	GEN_SET_FNUM(close.in.file.fnum);
	GEN_CALL(smb_raw_close(tree, &parm[i]));

	REMOVE_HANDLE(close.in.file.fnum);

	return True;
}

/*
  generate unlink operations
*/
static BOOL handler_unlink(int instance)
{
	union smb_unlink parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].unlink.in.pattern = gen_pattern();
	parm[0].unlink.in.attrib = gen_attrib();

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_unlink(tree, &parm[i]));

	return True;
}

/*
  generate chkpath operations
*/
static BOOL handler_chkpath(int instance)
{
	union smb_chkpath parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].chkpath.in.path = gen_fname_open(instance);

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_chkpath(tree, &parm[i]));

	return True;
}

/*
  generate mkdir operations
*/
static BOOL handler_mkdir(int instance)
{
	union smb_mkdir parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].mkdir.level = RAW_MKDIR_MKDIR;
	parm[0].mkdir.in.path = gen_fname_open(instance);

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_mkdir(tree, &parm[i]));

	return True;
}

/*
  generate rmdir operations
*/
static BOOL handler_rmdir(int instance)
{
	struct smb_rmdir parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].in.path = gen_fname_open(instance);

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_rmdir(tree, &parm[i]));

	return True;
}

/*
  generate rename operations
*/
static BOOL handler_rename(int instance)
{
	union smb_rename parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.level = RAW_RENAME_RENAME;
	parm[0].rename.in.pattern1 = gen_pattern();
	parm[0].rename.in.pattern2 = gen_pattern();
	parm[0].rename.in.attrib = gen_attrib();

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_rename(tree, &parm[i]));

	return True;
}

/*
  generate ntrename operations
*/
static BOOL handler_ntrename(int instance)
{
	union smb_rename parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.level = RAW_RENAME_NTRENAME;
	parm[0].ntrename.in.old_name = gen_fname();
	parm[0].ntrename.in.new_name = gen_fname();
	parm[0].ntrename.in.attrib = gen_attrib();
	parm[0].ntrename.in.cluster_size = gen_bits_mask2(0, 0xFFFFFFF);
	parm[0].ntrename.in.flags = gen_rename_flags();

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_rename(tree, &parm[i]));

	return True;
}


/*
  generate seek operations
*/
static BOOL handler_seek(int instance)
{
	union smb_seek parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].lseek.in.file.fnum = gen_fnum(instance);
	parm[0].lseek.in.mode = gen_bits_mask2(0x3, 0xFFFF);
	parm[0].lseek.in.offset = gen_offset();

	GEN_COPY_PARM;
	GEN_SET_FNUM(lseek.in.file.fnum);
	GEN_CALL(smb_raw_seek(tree, &parm[i]));

	CHECK_EQUAL(lseek.out.offset);

	return True;
}


/*
  generate readx operations
*/
static BOOL handler_readx(int instance)
{
	union smb_read parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].readx.level = RAW_READ_READX;
	parm[0].readx.in.file.fnum = gen_fnum(instance);
	parm[0].readx.in.offset = gen_offset();
	parm[0].readx.in.mincnt = gen_io_count();
	parm[0].readx.in.maxcnt = gen_io_count();
	parm[0].readx.in.remaining = gen_io_count();
	parm[0].readx.in.read_for_execute = gen_bool();
	parm[0].readx.out.data = talloc_size(current_op.mem_ctx,
					     MAX(parm[0].readx.in.mincnt, parm[0].readx.in.maxcnt));

	GEN_COPY_PARM;
	GEN_SET_FNUM(readx.in.file.fnum);
	GEN_CALL(smb_raw_read(tree, &parm[i]));

	CHECK_EQUAL(readx.out.remaining);
	CHECK_EQUAL(readx.out.compaction_mode);
	CHECK_EQUAL(readx.out.nread);

	return True;
}

/*
  generate writex operations
*/
static BOOL handler_writex(int instance)
{
	union smb_write parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].writex.level = RAW_WRITE_WRITEX;
	parm[0].writex.in.file.fnum = gen_fnum(instance);
	parm[0].writex.in.offset = gen_offset();
	parm[0].writex.in.wmode = gen_bits_mask(0xFFFF);
	parm[0].writex.in.remaining = gen_io_count();
	parm[0].writex.in.count = gen_io_count();
	parm[0].writex.in.data = talloc_zero_size(current_op.mem_ctx, parm[0].writex.in.count);

	GEN_COPY_PARM;
	GEN_SET_FNUM(writex.in.file.fnum);
	GEN_CALL(smb_raw_write(tree, &parm[i]));

	CHECK_EQUAL(writex.out.nwritten);
	CHECK_EQUAL(writex.out.remaining);

	return True;
}

/*
  generate lockingx operations
*/
static BOOL handler_lockingx(int instance)
{
	union smb_lock parm[NSERVERS];
	NTSTATUS status[NSERVERS];
	int n, nlocks;

	parm[0].lockx.level = RAW_LOCK_LOCKX;
	parm[0].lockx.in.file.fnum = gen_fnum(instance);
	parm[0].lockx.in.mode = gen_lock_mode();
	parm[0].lockx.in.timeout = gen_timeout();
	do {
		/* make sure we don't accidentially generate an oplock
		   break ack - otherwise the server can just block forever */
		parm[0].lockx.in.ulock_cnt = gen_lock_count();
		parm[0].lockx.in.lock_cnt = gen_lock_count();
		nlocks = parm[0].lockx.in.ulock_cnt + parm[0].lockx.in.lock_cnt;
	} while (nlocks == 0);

	if (nlocks > 0) {
		parm[0].lockx.in.locks = talloc_array(current_op.mem_ctx,
							struct smb_lock_entry,
							nlocks);
		for (n=0;n<nlocks;n++) {
			parm[0].lockx.in.locks[n].pid = gen_pid();
			parm[0].lockx.in.locks[n].offset = gen_offset();
			parm[0].lockx.in.locks[n].count = gen_io_count();
		}
	}

	GEN_COPY_PARM;
	GEN_SET_FNUM(lockx.in.file.fnum);
	GEN_CALL(smb_raw_lock(tree, &parm[i]));

	return True;
}

/*
  generate a fileinfo query structure
*/
static void gen_fileinfo(int instance, union smb_fileinfo *info)
{
	int i;
	#define LVL(v) {RAW_FILEINFO_ ## v, "RAW_FILEINFO_" #v}
	struct {
		enum smb_fileinfo_level level;
		const char *name;
	}  levels[] = {
		LVL(GETATTR), LVL(GETATTRE), LVL(STANDARD),
		LVL(EA_SIZE), LVL(ALL_EAS), LVL(IS_NAME_VALID),
		LVL(BASIC_INFO), LVL(STANDARD_INFO), LVL(EA_INFO),
		LVL(NAME_INFO), LVL(ALL_INFO), LVL(ALT_NAME_INFO),
		LVL(STREAM_INFO), LVL(COMPRESSION_INFO), LVL(BASIC_INFORMATION),
		LVL(STANDARD_INFORMATION), LVL(INTERNAL_INFORMATION), LVL(EA_INFORMATION),
		LVL(ACCESS_INFORMATION), LVL(NAME_INFORMATION), LVL(POSITION_INFORMATION),
		LVL(MODE_INFORMATION), LVL(ALIGNMENT_INFORMATION), LVL(ALL_INFORMATION),
		LVL(ALT_NAME_INFORMATION), LVL(STREAM_INFORMATION), LVL(COMPRESSION_INFORMATION),
		LVL(NETWORK_OPEN_INFORMATION), LVL(ATTRIBUTE_TAG_INFORMATION)
	};
	do {
		i = gen_int_range(0, ARRAY_SIZE(levels)-1);
	} while (ignore_pattern(levels[i].name));

	info->generic.level = levels[i].level;
}

/*
  compare returned fileinfo structures
*/
static BOOL cmp_fileinfo(int instance, 
			 union smb_fileinfo parm[NSERVERS],
			 NTSTATUS status[NSERVERS])
{
	int i;

	switch (parm[0].generic.level) {
	case RAW_FILEINFO_GENERIC:
		return False;

	case RAW_FILEINFO_GETATTR:
		CHECK_EQUAL(getattr.out.attrib);
		CHECK_EQUAL(getattr.out.size);
		CHECK_TIMES_EQUAL(getattr.out.write_time);
		break;

	case RAW_FILEINFO_GETATTRE:
		CHECK_TIMES_EQUAL(getattre.out.create_time);
		CHECK_TIMES_EQUAL(getattre.out.access_time);
		CHECK_TIMES_EQUAL(getattre.out.write_time);
		CHECK_EQUAL(getattre.out.size);
		CHECK_EQUAL(getattre.out.alloc_size);
		CHECK_EQUAL(getattre.out.attrib);
		break;

	case RAW_FILEINFO_STANDARD:
		CHECK_TIMES_EQUAL(standard.out.create_time);
		CHECK_TIMES_EQUAL(standard.out.access_time);
		CHECK_TIMES_EQUAL(standard.out.write_time);
		CHECK_EQUAL(standard.out.size);
		CHECK_EQUAL(standard.out.alloc_size);
		CHECK_EQUAL(standard.out.attrib);
		break;

	case RAW_FILEINFO_EA_SIZE:
		CHECK_TIMES_EQUAL(ea_size.out.create_time);
		CHECK_TIMES_EQUAL(ea_size.out.access_time);
		CHECK_TIMES_EQUAL(ea_size.out.write_time);
		CHECK_EQUAL(ea_size.out.size);
		CHECK_EQUAL(ea_size.out.alloc_size);
		CHECK_EQUAL(ea_size.out.attrib);
		CHECK_EQUAL(ea_size.out.ea_size);
		break;

	case RAW_FILEINFO_ALL_EAS:
		CHECK_EQUAL(all_eas.out.num_eas);
		for (i=0;i<parm[0].all_eas.out.num_eas;i++) {
			CHECK_EQUAL(all_eas.out.eas[i].flags);
			CHECK_WSTR_EQUAL(all_eas.out.eas[i].name);
			CHECK_BLOB_EQUAL(all_eas.out.eas[i].value);
		}
		break;

	case RAW_FILEINFO_IS_NAME_VALID:
		break;
		
	case RAW_FILEINFO_BASIC_INFO:
	case RAW_FILEINFO_BASIC_INFORMATION:
		CHECK_NTTIMES_EQUAL(basic_info.out.create_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.access_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.write_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.change_time);
		CHECK_EQUAL(basic_info.out.attrib);
		break;

	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_STANDARD_INFORMATION:
		CHECK_EQUAL(standard_info.out.alloc_size);
		CHECK_EQUAL(standard_info.out.size);
		CHECK_EQUAL(standard_info.out.nlink);
		CHECK_EQUAL(standard_info.out.delete_pending);
		CHECK_EQUAL(standard_info.out.directory);
		break;

	case RAW_FILEINFO_EA_INFO:
	case RAW_FILEINFO_EA_INFORMATION:
		CHECK_EQUAL(ea_info.out.ea_size);
		break;

	case RAW_FILEINFO_NAME_INFO:
	case RAW_FILEINFO_NAME_INFORMATION:
		CHECK_WSTR_EQUAL(name_info.out.fname);
		break;

	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALL_INFORMATION:
		CHECK_NTTIMES_EQUAL(all_info.out.create_time);
		CHECK_NTTIMES_EQUAL(all_info.out.access_time);
		CHECK_NTTIMES_EQUAL(all_info.out.write_time);
		CHECK_NTTIMES_EQUAL(all_info.out.change_time);
		CHECK_EQUAL(all_info.out.attrib);
		CHECK_EQUAL(all_info.out.alloc_size);
		CHECK_EQUAL(all_info.out.size);
		CHECK_EQUAL(all_info.out.nlink);
		CHECK_EQUAL(all_info.out.delete_pending);
		CHECK_EQUAL(all_info.out.directory);
		CHECK_EQUAL(all_info.out.ea_size);
		CHECK_WSTR_EQUAL(all_info.out.fname);
		break;

	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_ALT_NAME_INFORMATION:
		CHECK_WSTR_EQUAL(alt_name_info.out.fname);
		break;

	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_STREAM_INFORMATION:
		CHECK_EQUAL(stream_info.out.num_streams);
		for (i=0;i<parm[0].stream_info.out.num_streams;i++) {
			CHECK_EQUAL(stream_info.out.streams[i].size);
			CHECK_EQUAL(stream_info.out.streams[i].alloc_size);
			CHECK_WSTR_EQUAL(stream_info.out.streams[i].stream_name);
		}
		break;

	case RAW_FILEINFO_COMPRESSION_INFO:
	case RAW_FILEINFO_COMPRESSION_INFORMATION:
		CHECK_EQUAL(compression_info.out.compressed_size);
		CHECK_EQUAL(compression_info.out.format);
		CHECK_EQUAL(compression_info.out.unit_shift);
		CHECK_EQUAL(compression_info.out.chunk_shift);
		CHECK_EQUAL(compression_info.out.cluster_shift);
		break;

	case RAW_FILEINFO_INTERNAL_INFORMATION:
		CHECK_EQUAL(internal_information.out.file_id);
		break;

	case RAW_FILEINFO_ACCESS_INFORMATION:
		CHECK_EQUAL(access_information.out.access_flags);
		break;

	case RAW_FILEINFO_POSITION_INFORMATION:
		CHECK_EQUAL(position_information.out.position);
		break;

	case RAW_FILEINFO_MODE_INFORMATION:
		CHECK_EQUAL(mode_information.out.mode);
		break;

	case RAW_FILEINFO_ALIGNMENT_INFORMATION:
		CHECK_EQUAL(alignment_information.out.alignment_requirement);
		break;

	case RAW_FILEINFO_NETWORK_OPEN_INFORMATION:
		CHECK_NTTIMES_EQUAL(network_open_information.out.create_time);
		CHECK_NTTIMES_EQUAL(network_open_information.out.access_time);
		CHECK_NTTIMES_EQUAL(network_open_information.out.write_time);
		CHECK_NTTIMES_EQUAL(network_open_information.out.change_time);
		CHECK_EQUAL(network_open_information.out.alloc_size);
		CHECK_EQUAL(network_open_information.out.size);
		CHECK_EQUAL(network_open_information.out.attrib);
		break;

	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		CHECK_EQUAL(attribute_tag_information.out.attrib);
		CHECK_EQUAL(attribute_tag_information.out.reparse_tag);
		break;

		/* Unhandled levels */

	case RAW_FILEINFO_SEC_DESC:
	case RAW_FILEINFO_EA_LIST:
	case RAW_FILEINFO_UNIX_BASIC:
	case RAW_FILEINFO_UNIX_LINK:
	case RAW_FILEINFO_SMB2_ALL_EAS:
	case RAW_FILEINFO_SMB2_ALL_INFORMATION:	
		break;
	}

	return True;
}

/*
  generate qpathinfo operations
*/
static BOOL handler_qpathinfo(int instance)
{
	union smb_fileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.path = gen_fname_open(instance);

	gen_fileinfo(instance, &parm[0]);

	GEN_COPY_PARM;
	GEN_CALL(smb_raw_pathinfo(tree, current_op.mem_ctx, &parm[i]));

	return cmp_fileinfo(instance, parm, status);
}

/*
  generate qfileinfo operations
*/
static BOOL handler_qfileinfo(int instance)
{
	union smb_fileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.fnum = gen_fnum(instance);

	gen_fileinfo(instance, &parm[0]);

	GEN_COPY_PARM;
	GEN_SET_FNUM(generic.in.file.fnum);
	GEN_CALL(smb_raw_fileinfo(tree, current_op.mem_ctx, &parm[i]));

	return cmp_fileinfo(instance, parm, status);
}


/*
  generate a fileinfo query structure
*/
static void gen_setfileinfo(int instance, union smb_setfileinfo *info)
{
	int i;
	#undef LVL
	#define LVL(v) {RAW_SFILEINFO_ ## v, "RAW_SFILEINFO_" #v}
	struct {
		enum smb_setfileinfo_level level;
		const char *name;
	}  levels[] = {
#if 0
		/* disabled until win2003 can handle them ... */
		LVL(EA_SET), LVL(BASIC_INFO), LVL(DISPOSITION_INFO), 
		LVL(STANDARD), LVL(ALLOCATION_INFO), LVL(END_OF_FILE_INFO), 
#endif
		LVL(SETATTR), LVL(SETATTRE), LVL(BASIC_INFORMATION),
		LVL(RENAME_INFORMATION), LVL(DISPOSITION_INFORMATION), 
		LVL(POSITION_INFORMATION), LVL(MODE_INFORMATION),
		LVL(ALLOCATION_INFORMATION), LVL(END_OF_FILE_INFORMATION), 
		LVL(1023), LVL(1025), LVL(1029), LVL(1032), LVL(1039), LVL(1040)
	};
	do {
		i = gen_int_range(0, ARRAY_SIZE(levels)-1);
	} while (ignore_pattern(levels[i].name));

	info->generic.level = levels[i].level;

	switch (info->generic.level) {
	case RAW_SFILEINFO_SETATTR:
		info->setattr.in.attrib = gen_attrib();
		info->setattr.in.write_time = gen_timet();
		break;
	case RAW_SFILEINFO_SETATTRE:
		info->setattre.in.create_time = gen_timet();
		info->setattre.in.access_time = gen_timet();
		info->setattre.in.write_time = gen_timet();
		break;
	case RAW_SFILEINFO_STANDARD:
		info->standard.in.create_time = gen_timet();
		info->standard.in.access_time = gen_timet();
		info->standard.in.write_time = gen_timet();
		break;
	case RAW_SFILEINFO_EA_SET: {
		static struct ea_struct ea;
		info->ea_set.in.num_eas = 1;
		info->ea_set.in.eas = &ea;
		info->ea_set.in.eas[0] = gen_ea_struct();
	}
		break;
	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_BASIC_INFORMATION:
		info->basic_info.in.create_time = gen_nttime();
		info->basic_info.in.access_time = gen_nttime();
		info->basic_info.in.write_time = gen_nttime();
		info->basic_info.in.change_time = gen_nttime();
		info->basic_info.in.attrib = gen_attrib();
		break;
	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
		info->disposition_info.in.delete_on_close = gen_bool();
		break;
	case RAW_SFILEINFO_ALLOCATION_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		info->allocation_info.in.alloc_size = gen_alloc_size();
		break;
	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		info->end_of_file_info.in.size = gen_offset();
		break;
	case RAW_SFILEINFO_RENAME_INFORMATION:
		info->rename_information.in.overwrite = gen_bool();
		info->rename_information.in.root_fid = gen_root_fid(instance);
		info->rename_information.in.new_name = gen_fname_open(instance);
		break;
	case RAW_SFILEINFO_POSITION_INFORMATION:
		info->position_information.in.position = gen_offset();
		break;
	case RAW_SFILEINFO_MODE_INFORMATION:
		info->mode_information.in.mode = gen_bits_mask(0xFFFFFFFF);
		break;
	case RAW_SFILEINFO_GENERIC:
	case RAW_SFILEINFO_SEC_DESC:
	case RAW_SFILEINFO_UNIX_BASIC:
	case RAW_SFILEINFO_UNIX_LINK:
	case RAW_SFILEINFO_UNIX_HLINK:
	case RAW_SFILEINFO_1023:
	case RAW_SFILEINFO_1025:
	case RAW_SFILEINFO_1029:
	case RAW_SFILEINFO_1032:
	case RAW_SFILEINFO_1039:
	case RAW_SFILEINFO_1040:
		/* Untested */
		break;
	}
}

/*
  generate setpathinfo operations
*/
static BOOL handler_spathinfo(int instance)
{
	union smb_setfileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.path = gen_fname_open(instance);

	gen_setfileinfo(instance, &parm[0]);

	GEN_COPY_PARM;

	/* a special case for the fid in a RENAME */
	if (parm[0].generic.level == RAW_SFILEINFO_RENAME_INFORMATION &&
	    parm[0].rename_information.in.root_fid != 0) {
		GEN_SET_FNUM(rename_information.in.root_fid);
	}

	GEN_CALL(smb_raw_setpathinfo(tree, &parm[i]));

	return True;
}


/*
  generate setfileinfo operations
*/
static BOOL handler_sfileinfo(int instance)
{
	union smb_setfileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.fnum = gen_fnum(instance);

	gen_setfileinfo(instance, &parm[0]);

	GEN_COPY_PARM;
	GEN_SET_FNUM(generic.in.file.fnum);
	GEN_CALL(smb_raw_setfileinfo(tree, &parm[i]));

	return True;
}


/*
  generate change notify operations
*/
static BOOL handler_notify(int instance)
{
	union smb_notify parm[NSERVERS];
	int n;

	ZERO_STRUCT(parm[0]);
	parm[0].nttrans.level			= RAW_NOTIFY_NTTRANS;
	parm[0].nttrans.in.buffer_size		= gen_io_count();
	parm[0].nttrans.in.completion_filter	= gen_bits_mask(0xFF);
	parm[0].nttrans.in.file.fnum		= gen_fnum(instance);
	parm[0].nttrans.in.recursive		= gen_bool();

	GEN_COPY_PARM;
	GEN_SET_FNUM(nttrans.in.file.fnum);

	for (n=0;n<NSERVERS;n++) {
		struct smbcli_request *req;
		req = smb_raw_changenotify_send(servers[n].cli[instance]->tree, &parm[n]);
		req->async.fn = async_notify;
	}

	return True;
}

/*
  wipe any relevant files
*/
static void wipe_files(void)
{
	int i;
	for (i=0;i<NSERVERS;i++) {
		int n = smbcli_deltree(servers[i].cli[0]->tree, "\\gentest");
		if (n == -1) {
			printf("Failed to wipe tree on server %d\n", i);
			exit(1);
		}
		if (NT_STATUS_IS_ERR(smbcli_mkdir(servers[i].cli[0]->tree, "\\gentest"))) {
			printf("Failed to create \\gentest - %s\n",
			       smbcli_errstr(servers[i].cli[0]->tree));
			exit(1);
		}
		if (n > 0) {
			printf("Deleted %d files on server %d\n", n, i);
		}
	}
}

/*
  dump the current seeds - useful for continuing a backtrack
*/
static void dump_seeds(void)
{
	int i;
	FILE *f;

	if (!options.seeds_file) {
		return;
	}
	f = fopen("seeds.tmp", "w");
	if (!f) return;

	for (i=0;i<options.numops;i++) {
		fprintf(f, "%u\n", op_parms[i].seed);
	}
	fclose(f);
	rename("seeds.tmp", options.seeds_file);
}



/*
  the list of top-level operations that we will generate
*/
static struct {
	const char *name;
	BOOL (*handler)(int instance);
	int count, success_count;
} gen_ops[] = {
	{"OPEN",       handler_open},
	{"OPENX",      handler_openx},
	{"NTCREATEX",  handler_ntcreatex},
	{"CLOSE",      handler_close},
	{"UNLINK",     handler_unlink},
	{"MKDIR",      handler_mkdir},
	{"RMDIR",      handler_rmdir},
	{"RENAME",     handler_rename},
	{"NTRENAME",   handler_ntrename},
	{"READX",      handler_readx},
	{"WRITEX",     handler_writex},
	{"CHKPATH",    handler_chkpath},
	{"LOCKINGX",   handler_lockingx},
	{"QPATHINFO",  handler_qpathinfo},
	{"QFILEINFO",  handler_qfileinfo},
	{"SPATHINFO",  handler_spathinfo},
	{"SFILEINFO",  handler_sfileinfo},
	{"NOTIFY",     handler_notify},
	{"SEEK",       handler_seek},
};


/*
  run the test with the current set of op_parms parameters
  return the number of operations that completed successfully
*/
static int run_test(void)
{
	int op, i;

	if (!connect_servers()) {
		printf("Failed to connect to servers\n");
		exit(1);
	}

	dump_seeds();

	/* wipe any leftover files from old runs */
	wipe_files();

	/* reset the open handles array */
	memset(open_handles, 0, options.max_open_handles * sizeof(open_handles[0]));
	num_open_handles = 0;

	for (i=0;i<ARRAY_SIZE(gen_ops);i++) {
		gen_ops[i].count = 0;
		gen_ops[i].success_count = 0;
	}

	for (op=0; op<options.numops; op++) {
		int instance, which_op;
		BOOL ret;

		if (op_parms[op].disabled) continue;

		srandom(op_parms[op].seed);

		instance = gen_int_range(0, NINSTANCES-1);

		/* generate a non-ignored operation */
		do {
			which_op = gen_int_range(0, ARRAY_SIZE(gen_ops)-1);
		} while (ignore_pattern(gen_ops[which_op].name));

		DEBUG(3,("Generating op %s on instance %d\n",
			 gen_ops[which_op].name, instance));

		current_op.seed = op_parms[op].seed;
		current_op.opnum = op;
		current_op.name = gen_ops[which_op].name;
		current_op.status = NT_STATUS_OK;
		current_op.mem_ctx = talloc_named(NULL, 0, "%s", current_op.name);

		ret = gen_ops[which_op].handler(instance);

		talloc_free(current_op.mem_ctx);

		gen_ops[which_op].count++;
		if (NT_STATUS_IS_OK(current_op.status)) {
			gen_ops[which_op].success_count++;			
		}

		if (!ret) {
			printf("Failed at operation %d - %s\n",
			       op, gen_ops[which_op].name);
			return op;
		}

		if (op % 100 == 0) {
			printf("%d\n", op);
		}
	}

	for (i=0;i<ARRAY_SIZE(gen_ops);i++) {
		printf("Op %-10s got %d/%d success\n", 
		       gen_ops[i].name,
		       gen_ops[i].success_count,
		       gen_ops[i].count);
	}

	return op;
}

/* 
   perform a backtracking analysis of the minimal set of operations
   to generate an error
*/
static void backtrack_analyze(void)
{
	int chunk, ret;

	chunk = options.numops / 2;

	do {
		int base;
		for (base=0; 
		     chunk > 0 && base+chunk < options.numops && options.numops > 1; ) {
			int i, max;

			chunk = MIN(chunk, options.numops / 2);

			/* mark this range as disabled */
			max = MIN(options.numops, base+chunk);
			for (i=base;i<max; i++) {
				op_parms[i].disabled = True;
			}
			printf("Testing %d ops with %d-%d disabled\n", 
			       options.numops, base, max-1);
			ret = run_test();
			printf("Completed %d of %d ops\n", ret, options.numops);
			for (i=base;i<max; i++) {
				op_parms[i].disabled = False;
			}
			if (ret == options.numops) {
				/* this chunk is needed */
				base += chunk;
			} else if (ret < base) {
				printf("damn - inconsistent errors! found early error\n");
				options.numops = ret+1;
				base = 0;
			} else {
				/* it failed - this chunk isn't needed for a failure */
				memmove(&op_parms[base], &op_parms[max], 
					sizeof(op_parms[0]) * (options.numops - max));
				options.numops = (ret+1) - (max - base);
			}
		}

		if (chunk == 2) {
			chunk = 1;
		} else {
			chunk *= 0.4;
		}

		if (options.analyze_continuous && chunk == 0 && options.numops != 1) {
			chunk = 1;
		}
	} while (chunk > 0);

	printf("Reduced to %d ops\n", options.numops);
	ret = run_test();
	if (ret != options.numops - 1) {
		printf("Inconsistent result? ret=%d numops=%d\n", ret, options.numops);
	}
}

/* 
   start the main gentest process
*/
static BOOL start_gentest(void)
{
	int op;
	int ret;

	/* allocate the open_handles array */
	open_handles = calloc(options.max_open_handles, sizeof(open_handles[0]));

	srandom(options.seed);
	op_parms = calloc(options.numops, sizeof(op_parms[0]));

	/* generate the seeds - after this everything is deterministic */
	if (options.use_preset_seeds) {
		int numops;
		char **preset = file_lines_load(options.seeds_file, &numops, NULL);
		if (!preset) {
			printf("Failed to load %s - %s\n", options.seeds_file, strerror(errno));
			exit(1);
		}
		if (numops < options.numops) {
			options.numops = numops;
		}
		for (op=0;op<options.numops;op++) {
			if (!preset[op]) {
				printf("Not enough seeds in %s\n", options.seeds_file);
				exit(1);
			}
			op_parms[op].seed = atoi(preset[op]);
		}
		printf("Loaded %d seeds from %s\n", options.numops, options.seeds_file);
	} else {
		for (op=0; op<options.numops; op++) {
			op_parms[op].seed = random();
		}
	}

	ret = run_test();

	if (ret != options.numops && options.analyze) {
		options.numops = ret+1;
		backtrack_analyze();
	} else if (options.analyze_always) {
		backtrack_analyze();
	} else if (options.analyze_continuous) {
		while (run_test() == options.numops) ;
	}

	return ret == options.numops;
}


static void usage(void)
{
	printf(
"Usage:\n\
  gentest2 //server1/share1 //server2/share2 [options..]\n\
  options:\n\
        -U user%%pass        (can be specified twice)\n\
        -s seed\n\
        -o numops\n\
        -a            (show all ops)\n\
        -A            backtrack to find minimal ops\n\
        -i FILE       add a list of wildcard exclusions\n\
        -O            enable oplocks\n\
        -S FILE       set preset seeds file\n\
        -L            use preset seeds\n\
        -F            fast reconnect (just close files)\n\
        -C            continuous analysis mode\n\
        -X            analyse even when test OK\n\
");
}

/**
  split a UNC name into server and share names
*/
static BOOL split_unc_name(const char *unc, char **server, char **share)
{
	char *p = strdup(unc);
	if (!p) return False;
	all_string_sub(p, "\\", "/", 0);
	if (strncmp(p, "//", 2) != 0) return False;

	(*server) = p+2;
	p = strchr(*server, '/');
	if (!p) return False;

	*p = 0;
	(*share) = p+1;
	
	return True;
}



/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, char *argv[])
{
	int opt;
	int i, username_count=0;
	BOOL ret;

	setlinebuf(stdout);

	setup_logging("gentest", DEBUG_STDOUT);

	if (argc < 3 || argv[1][0] == '-') {
		usage();
		exit(1);
	}

	setup_logging(argv[0], DEBUG_STDOUT);

	for (i=0;i<NSERVERS;i++) {
		const char *share = argv[1+i];
		servers[i].credentials = cli_credentials_init(NULL);
		if (!split_unc_name(share, &servers[i].server_name, &servers[i].share_name)) {
			printf("Invalid share name '%s'\n", share);
			return -1;
		}
	}

	argc -= NSERVERS;
	argv += NSERVERS;

	lp_load();

	servers[0].credentials = cli_credentials_init(talloc_autofree_context());
	servers[1].credentials = cli_credentials_init(talloc_autofree_context());
	cli_credentials_guess(servers[0].credentials);
	cli_credentials_guess(servers[1].credentials);

	options.seed = time(NULL);
	options.numops = 1000;
	options.max_open_handles = 20;
	options.seeds_file = "gentest_seeds.dat";

	while ((opt = getopt(argc, argv, "U:s:o:ad:i:AOhS:LFXC")) != EOF) {
		switch (opt) {
		case 'U':
			if (username_count == 2) {
				usage();
				exit(1);
			}
			cli_credentials_parse_string(servers[username_count].credentials, 
						     optarg, CRED_SPECIFIED);
			username_count++;
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			setup_logging(NULL, DEBUG_STDOUT);
			break;
		case 's':
			options.seed = atoi(optarg);
			break;
		case 'S':
			options.seeds_file = optarg;
			break;
		case 'L':
			options.use_preset_seeds = True;
			break;
		case 'F':
			options.fast_reconnect = True;
			break;
		case 'o':
			options.numops = atoi(optarg);
			break;
		case 'O':
			options.use_oplocks = True;
			break;
		case 'a':
			options.showall = True;
			break;
		case 'A':
			options.analyze = True;
			break;
		case 'X':
			options.analyze_always = True;
			break;
		case 'C':
			options.analyze_continuous = True;
			break;
		case 'i':
			options.ignore_patterns = file_lines_load(optarg, NULL, NULL);
			break;
		case 'h':
			usage();
			exit(1);
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	gensec_init();

	if (username_count == 0) {
		usage();
		return -1;
	}
	if (username_count == 1) {
		servers[1].credentials = servers[0].credentials;
	}

	printf("seed=%u\n", options.seed);

	ret = start_gentest();

	if (ret) {
		printf("gentest completed - no errors\n");
	} else {
		printf("gentest failed\n");
	}

	return ret?0:-1;
}
