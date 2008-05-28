/* 
   Unix SMB/CIFS implementation.

   generic testing tool - version with SMB2 support

   Copyright (C) Andrew Tridgell 2003-2008
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/raw/request.h"
#include "libcli/libcli.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "auth/credentials/credentials.h"
#include "libcli/resolve/resolve.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"
#include "dynconfig/dynconfig.h"
#include "libcli/security/security.h"

#define NSERVERS 2
#define NINSTANCES 2

/* global options */
static struct gentest_options {
	int showall;
	int analyze;
	int analyze_always;
	int analyze_continuous;
	uint_t max_open_handles;
	uint_t seed;
	uint_t numops;
	int use_oplocks;
	char **ignore_patterns;
	const char *seeds_file;
	int use_preset_seeds;
	int fast_reconnect;
	int mask_indexing;
	int no_eas;
	int skip_cleanup;
	int valid;
} options;

/* mapping between open handles on the server and local handles */
static struct {
	bool active;
	uint_t instance;
	struct smb2_handle server_handle[NSERVERS];
	const char *name;
} *open_handles;
static uint_t num_open_handles;

/* state information for the servers. We open NINSTANCES connections to
   each server */
static struct {
	struct smb2_tree *tree[NINSTANCES];
	char *server_name;
	char *share_name;
	struct cli_credentials *credentials;
} servers[NSERVERS];

/* the seeds and flags for each operation */
static struct {
	uint_t seed;
	bool disabled;
} *op_parms;


/* oplock break info */
static struct {
	bool got_break;
	struct smb2_handle server_handle;
	uint16_t handle;
	uint8_t level;
	bool do_close;
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

static struct smb2_handle bad_smb2_handle;


#define BAD_HANDLE 0xFFFE

static bool oplock_handler(struct smb2_transport *transport, const struct smb2_handle *handle,
			   uint8_t level, void *private_data);
static void idle_func(struct smb2_transport *transport, void *private);

/*
  check if a string should be ignored. This is used as the basis
  for all error ignore settings
*/
static bool ignore_pattern(const char *str)
{
	int i;
	if (!options.ignore_patterns) return false;

	for (i=0;options.ignore_patterns[i];i++) {
		if (strcmp(options.ignore_patterns[i], str) == 0 ||
		    gen_fnmatch(options.ignore_patterns[i], str) == 0) {
			DEBUG(2,("Ignoring '%s'\n", str));
			return true;
		}
	}
	return false;
}

/***************************************************** 
connect to the servers
*******************************************************/
static bool connect_servers_fast(void)
{
	int h, i;

	/* close all open files */
	for (h=0;h<options.max_open_handles;h++) {
		if (!open_handles[h].active) continue;
		for (i=0;i<NSERVERS;i++) {
			NTSTATUS status = smb2_util_close(servers[i].tree[open_handles[h].instance],
							  open_handles[h].server_handle[i]);
			if (NT_STATUS_IS_ERR(status)) {
				return false;
			}
			open_handles[h].active = false;
		}
	}

	return true;
}




/***************************************************** 
connect to the servers
*******************************************************/
static bool connect_servers(struct event_context *ev,
			    struct loadparm_context *lp_ctx)
{
	int i, j;

	if (options.fast_reconnect && servers[0].tree[0]) {
		if (connect_servers_fast()) {
			return true;
		}
	}

	/* close any existing connections */
	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (servers[i].tree[j]) {
				smb2_tdis(servers[i].tree[j]);
				talloc_free(servers[i].tree[j]);
				servers[i].tree[j] = NULL;
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

			status = smb2_connect(NULL, servers[i].server_name, 
					      servers[i].share_name,
					      lp_resolve_context(lp_ctx),
					      servers[i].credentials,
					      &servers[i].tree[j],
					      ev);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Failed to connect to \\\\%s\\%s - %s\n",
				       servers[i].server_name, servers[i].share_name,
				       nt_errstr(status));
				return false;
			}

			servers[i].tree[j]->session->transport->oplock.handler = oplock_handler;
			servers[i].tree[j]->session->transport->oplock.private_data = (void *)(uintptr_t)((i<<8)|j);
			smb2_transport_idle_handler(servers[i].tree[j]->session->transport, idle_func, 50000, NULL);
		}
	}

	return true;
}

/*
  work out the time skew between the servers - be conservative
*/
static uint_t time_skew(void)
{
	uint_t ret;
	ret = labs(servers[0].tree[0]->session->transport->negotiate.system_time -
		  servers[1].tree[0]->session->transport->negotiate.system_time);
	return ret + 300;
}


static bool smb2_handle_equal(const struct smb2_handle *h1, const struct smb2_handle *h2)
{
	return memcmp(h1, h2, sizeof(struct smb2_handle)) == 0;
}

/*
  turn a server handle into a local handle
*/
static uint_t fnum_to_handle(int server, int instance, struct smb2_handle server_handle)
{
	uint_t i;
	for (i=0;i<options.max_open_handles;i++) {
		if (!open_handles[i].active ||
		    instance != open_handles[i].instance) continue;
		if (smb2_handle_equal(&open_handles[i].server_handle[server], &server_handle)) {
			return i;
		}
	}
	printf("Invalid server handle in fnum_to_handle on server %d instance %d\n", 
	       server, instance);
	return BAD_HANDLE;
}

/*
  add some newly opened handles
*/
static void gen_add_handle(int instance, const char *name, struct smb2_handle handles[NSERVERS])
{
	int i, h;
	for (h=0;h<options.max_open_handles;h++) {
		if (!open_handles[h].active) break;
	}
	if (h == options.max_open_handles) {
		/* we have to force close a random handle */
		h = random() % options.max_open_handles;
		for (i=0;i<NSERVERS;i++) {
			NTSTATUS status;
			status = smb2_util_close(servers[i].tree[open_handles[h].instance], 
						 open_handles[h].server_handle[i]);
			if (NT_STATUS_IS_ERR(status)) {
				printf("INTERNAL ERROR: Close failed when recovering handle! - %s\n",
				       nt_errstr(status));
			}
		}
		printf("Recovered handle %d\n", h);
		num_open_handles--;
	}
	for (i=0;i<NSERVERS;i++) {
		open_handles[h].server_handle[i] = handles[i];
		open_handles[h].instance = instance;
		open_handles[h].active = true;
		open_handles[h].name = name;
	}
	num_open_handles++;

	printf("OPEN num_open_handles=%d h=%d (%s)\n", 
	       num_open_handles, h, name);
}

/*
  remove a closed handle
*/
static void gen_remove_handle(int instance, struct smb2_handle handles[NSERVERS])
{
	int h;
	for (h=0;h<options.max_open_handles;h++) {
		if (instance == open_handles[h].instance &&
		    smb2_handle_equal(&open_handles[h].server_handle[0], &handles[0])) {
			open_handles[h].active = false;			
			num_open_handles--;
			printf("CLOSE num_open_handles=%d h=%d (%s)\n", 
			       num_open_handles, h, 
			       open_handles[h].name);
			return;
		}
	}
	printf("Removing invalid handle!?\n");
	exit(1);
}

/*
  return true with 'chance' probability as a percentage
*/
static bool gen_chance(uint_t chance)
{
	return ((random() % 100) <= chance);
}

/*
  map an internal handle number to a server handle
*/
static struct smb2_handle gen_lookup_handle(int server, uint16_t handle)
{
	if (handle == BAD_HANDLE) return bad_smb2_handle;
	return open_handles[handle].server_handle[server];
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
	if (num_open_handles < 5) {
		if (gen_chance(90)) return BAD_HANDLE;
	}

	return gen_fnum(instance);
}

/*
  generate an integer in a specified range
*/
static int gen_int_range(uint64_t min, uint64_t max)
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
	return 0;
}

/*
  generate a file offset
*/
static int gen_offset(void)
{
	if (gen_chance(20)) return 0;
//	if (gen_chance(5)) return gen_int_range(0, 0xFFFFFFFF);
	return gen_int_range(0, 1024*1024);
}

/*
  generate a io count
*/
static int gen_io_count(void)
{
	if (gen_chance(20)) return 0;
//	if (gen_chance(5)) return gen_int_range(0, 0xFFFFFFFF);
	return gen_int_range(0, 4096);
}

/*
  generate a filename
*/
static const char *gen_fname(void)
{
	const char *names[] = {"gentest\\gentest.dat", 
			       "gentest\\foo", 
			       "gentest\\foo2.sym", 
			       "gentest\\foo3.dll", 
			       "gentest\\foo4", 
			       "gentest\\foo4:teststream1", 
			       "gentest\\foo4:teststream2", 
			       "gentest\\foo5.exe", 
			       "gentest\\foo5.exe:teststream3", 
			       "gentest\\foo5.exe:teststream4", 
			       "gentest\\foo6.com", 
			       "gentest\\blah", 
			       "gentest\\blah\\blergh.txt", 
			       "gentest\\blah\\blergh2", 
			       "gentest\\blah\\blergh3.txt", 
			       "gentest\\blah\\blergh4", 
			       "gentest\\blah\\blergh5.txt", 
			       "gentest\\blah\\blergh5", 
			       "gentest\\blah\\.", 
#if 0
			       /* this causes problem with w2k3 */
			       "gentest\\blah\\..", 
#endif
			       "gentest\\a_very_long_name.bin", 
			       "gentest\\x.y", 
			       "gentest\\blah"};
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
	const char *names[] = {"gentest\\*.dat", 
			       "gentest\\*", 
			       "gentest\\*.*", 
			       "gentest\\blah\\*.*", 
			       "gentest\\blah\\*", 
			       "gentest\\?"};

	if (gen_chance(50)) return gen_fname();

	do {
		i = gen_int_range(0, ARRAY_SIZE(names)-1);
	} while (ignore_pattern(names[i]));

	return names[i];
}

static uint32_t gen_bits_levels(int nlevels, ...)
{
	va_list ap;
	uint32_t pct;
	uint32_t mask;
	int i;
	va_start(ap, nlevels);
	for (i=0;i<nlevels;i++) {
		pct = va_arg(ap, uint32_t);
		mask = va_arg(ap, uint32_t);
		if (pct == 100 || gen_chance(pct)) {
			va_end(ap);
			return mask & random();
		}
	}
	va_end(ap);
	return 0;
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
	if (!options.valid && gen_chance(10)) return gen_bits_mask(mask2);
	return gen_bits_mask(mask1);
}

/*
  generate reserved values
 */
static uint64_t gen_reserved8(void)
{
	if (options.valid) return 0;
	return gen_bits_mask(0xFF);
}

static uint64_t gen_reserved16(void)
{
	if (options.valid) return 0;
	return gen_bits_mask(0xFFFF);
}

static uint64_t gen_reserved32(void)
{
	if (options.valid) return 0;
	return gen_bits_mask(0xFFFFFFFF);
}

static uint64_t gen_reserved64(void)
{
	if (options.valid) return 0;
	return gen_bits_mask(0xFFFFFFFF) | (((uint64_t)gen_bits_mask(0xFFFFFFFF))<<32);
}



/*
  generate a boolean
*/
static bool gen_bool(void)
{
	return gen_bits_mask2(0x1, 0xFF);
}

/*
  return a set of lock flags
*/
static uint16_t gen_lock_flags(void)
{
	if (!options.valid && gen_chance(5))  return gen_bits_mask(0xFFFF);
	if (gen_chance(20)) return gen_bits_mask(0x1F);
	if (gen_chance(50)) return SMB2_LOCK_FLAG_UNLOCK;
	return gen_bits_mask(SMB2_LOCK_FLAG_SHARED | 
			     SMB2_LOCK_FLAG_EXCLUSIVE | 
			     SMB2_LOCK_FLAG_FAIL_IMMEDIATELY);
}

/*
  generate a lock count
*/
static off_t gen_lock_count(void)
{
	return gen_int_range(0, 3);
}

/*
  generate a NT access mask
*/
static uint32_t gen_access_mask(void)
{
	uint32_t ret;
	if (gen_chance(70)) return SEC_FLAG_MAXIMUM_ALLOWED;
	if (gen_chance(70)) return SEC_FILE_ALL;
	ret = gen_bits_mask(0xFFFFFFFF);
	if (options.valid) ret &= ~SEC_MASK_INVALID;
	return ret;
}

/*
  generate a ntcreatex create options bitfield
*/
static uint32_t gen_create_options(void)
{
	if (!options.valid && gen_chance(20)) return gen_bits_mask(0xFFFFFFFF);
	if (gen_chance(50)) return 0;
	return gen_bits_mask(NTCREATEX_OPTIONS_DELETE_ON_CLOSE | NTCREATEX_OPTIONS_DIRECTORY);
}

/*
  generate a ntcreatex open disposition
*/
static uint32_t gen_open_disp(void)
{
	if (gen_chance(50)) return NTCREATEX_DISP_OPEN_IF;
	if (!options.valid && gen_chance(10)) return gen_bits_mask(0xFFFFFFFF);
	return gen_int_range(0, 5);
}

/*
  generate a file attrib combination
*/
static uint32_t gen_attrib(void)
{
	uint32_t ret;
	if (gen_chance(20)) {
		ret = gen_bits_mask(0xFFFFFFFF);
		if (options.valid) ret &= FILE_ATTRIBUTE_ALL_MASK;
		return ret;
	}
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
  generate a timestamp
*/
static NTTIME gen_nttime(void)
{
	NTTIME ret;
	unix_to_nt_time(&ret, gen_timet());
	return ret;
}

/*
  generate a timewarp value
*/
static NTTIME gen_timewarp(void)
{
	NTTIME ret = gen_nttime();
	if (gen_chance(98)) ret = 0;
	return ret;
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
  generate an ea_struct
*/
static struct smb_ea_list gen_ea_list(void)
{
	struct smb_ea_list eas;
	int i;
	if (options.no_eas) {
		ZERO_STRUCT(eas);
		return eas;
	}
	eas.num_eas = gen_int_range(0, 3);
	eas.eas = talloc_array(current_op.mem_ctx, struct ea_struct, eas.num_eas);
	for (i=0;i<eas.num_eas;i++) {
		eas.eas[i] = gen_ea_struct();
	}
	return eas;
}

/* generate a security descriptor */
static struct security_descriptor *gen_sec_desc(void)
{
	struct security_descriptor *sd;
	if (gen_chance(90)) return NULL;

	sd = security_descriptor_dacl_create(current_op.mem_ctx,
					     0, NULL, NULL,
					     NULL,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_FILE_WRITE_DATA | SEC_STD_WRITE_DAC,
					     SEC_ACE_FLAG_OBJECT_INHERIT,
					     SID_WORLD,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_FILE_ALL | SEC_STD_ALL,
					     0,
					     NULL);
	return sd;
}

static void oplock_handler_close_recv(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_close io;
	status = smb2_close_recv(req, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed in oplock_handler\n");
		smb_panic("close failed in oplock_handler");
	}
}

static void oplock_handler_ack_callback(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_break br;

	status = smb2_break_recv(req, &br);
	if (!NT_STATUS_IS_OK(status)) {
		printf("oplock break ack failed in oplock_handler\n");
		smb_panic("oplock break ack failed in oplock_handler");
	}
}

static bool send_oplock_ack(struct smb2_tree *tree, struct smb2_handle handle, 
			    uint8_t level)
{
	struct smb2_break br;
	struct smb2_request *req;

	ZERO_STRUCT(br);
	br.in.file.handle	= handle;
	br.in.oplock_level	= level;
	br.in.reserved	        = gen_reserved8();
	br.in.reserved2	        = gen_reserved32();

	req = smb2_break_send(tree, &br);
	if (req == NULL) return false;
	req->async.fn = oplock_handler_ack_callback;
	req->async.private_data = NULL;
	return true;
}

/*
  the oplock handler will either ack the break or close the file
*/
static bool oplock_handler(struct smb2_transport *transport, const struct smb2_handle *handle, 
			   uint8_t level, void *private_data)
{
	struct smb2_close io;
	unsigned i, j;
	bool do_close;
	struct smb2_tree *tree = NULL;
	struct smb2_request *req;

	srandom(current_op.seed);
	do_close = gen_chance(50);

	i = ((uintptr_t)private_data) >> 8;
	j = ((uintptr_t)private_data) & 0xFF;

	if (i >= NSERVERS || j >= NINSTANCES) {
		printf("Bad private_data in oplock_handler\n");
		return false;
	}

	oplocks[i][j].got_break = true;
	oplocks[i][j].server_handle = *handle;
	oplocks[i][j].handle = fnum_to_handle(i, j, *handle);
	oplocks[i][j].level = level;
	oplocks[i][j].do_close = do_close;
	tree = talloc_get_type(servers[i].tree[j], struct smb2_tree);

	if (!tree) {
		printf("Oplock break not for one of our trees!?\n");
		return false;
	}

	if (!do_close) {
		printf("oplock ack handle=%d\n", oplocks[i][j].handle);
		return send_oplock_ack(tree, *handle, level);
	}

	printf("oplock close fnum=%d\n", oplocks[i][j].handle);

	ZERO_STRUCT(io);
	io.in.file.handle = *handle;
	io.in.flags = 0;
	req = smb2_close_send(tree, &io);

	if (req == NULL) {
		printf("WARNING: close failed in oplock_handler_close\n");
		return false;
	}

	req->async.fn = oplock_handler_close_recv;
	req->async.private_data = NULL;

	return true;
}


/*
  the idle function tries to cope with getting an oplock break on a connection, and
  an operation on another connection blocking until that break is acked
  we check for operations on all transports in the idle function
*/
static void idle_func(struct smb2_transport *transport, void *private)
{
	int i, j;
	for (i=0;i<NSERVERS;i++) {
		for (j=0;j<NINSTANCES;j++) {
			if (servers[i].tree[j] &&
			    transport != servers[i].tree[j]->session->transport) {
				// smb2_transport_process(servers[i].tree[j]->session->transport);
			}
		}
	}

}


/*
  compare NTSTATUS, using checking ignored patterns
*/
static bool compare_status(NTSTATUS status1, NTSTATUS status2)
{
	if (NT_STATUS_EQUAL(status1, status2)) return true;

	/* one code being an error and the other OK is always an error */
	if (NT_STATUS_IS_OK(status1) || NT_STATUS_IS_OK(status2)) return false;

	/* if we are ignoring one of the status codes then consider this a match */
	if (ignore_pattern(nt_errstr(status1)) ||
	    ignore_pattern(nt_errstr(status2))) {
		return true;
	}
	return false;
}

#if 0
/*
  check for pending packets on all connections
*/
static void check_pending(void)
{
	int i, j;

	msleep(20);

	for (j=0;j<NINSTANCES;j++) {
		for (i=0;i<NSERVERS;i++) {
			// smb2_transport_process(servers[i].tree[j]->session->transport);
		}
	}	
}
#endif

/*
  check that the same oplock breaks have been received by all instances
*/
static bool check_oplocks(const char *call)
{
#if 0
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
				return false;
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
#endif
	return true;
}


/*
  check that the same change notify info has been received by all instances
*/
static bool check_notifies(const char *call)
{
#if 0
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
				return false;
			}

			if (notifies[0][j].notify_count == 0) continue;

			if (!NT_STATUS_EQUAL(notifies[0][j].status,
					     notifies[i][j].status)) {
				printf("Notify status mismatch - %s - %s\n",
				       nt_errstr(notifies[0][j].status),
				       nt_errstr(notifies[i][j].status));
				return false;
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
					return false;
				}
				if (strcmp(not1.nttrans.out.changes[n].name.s,
					   not2.nttrans.out.changes[n].name.s)) {
					printf("Notify name %d inconsistent %s %s\n", n,
					       not1.nttrans.out.changes[n].name.s,
					       not2.nttrans.out.changes[n].name.s);
					return false;
				}
				if (not1.nttrans.out.changes[n].name.private_length !=
				    not2.nttrans.out.changes[n].name.private_length) {
					printf("Notify name length %d inconsistent %d %d\n", n,
					       not1.nttrans.out.changes[n].name.private_length,
					       not2.nttrans.out.changes[n].name.private_length);
					return false;
				}
			}
		}
	}

	ZERO_STRUCT(notifies);

#endif
	return true;
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
		struct smb2_tree *tree = servers[i].tree[instance]; \
		status[i] = call; \
	} \
	current_op.status = status[0]; \
	for (i=1;i<NSERVERS;i++) { \
		if (!compare_status(status[i], status[0])) { \
			printf("status different in %s - %s %s\n", #call, \
			       nt_errstr(status[0]), nt_errstr(status[i])); \
			return false; \
		} \
	} \
	if (!check_oplocks(#call)) return false;	\
	if (!check_notifies(#call)) return false;	\
	if (!NT_STATUS_IS_OK(status[0])) { \
		return true; \
	} \
} while(0)

#define ADD_HANDLE(name, field) do { \
	struct smb2_handle handles[NSERVERS]; \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		handles[i] = parm[i].field; \
	} \
	gen_add_handle(instance, name, handles); \
} while(0)

#define REMOVE_HANDLE(field) do { \
	struct smb2_handle handles[NSERVERS]; \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		handles[i] = parm[i].field; \
	} \
	gen_remove_handle(instance, handles); \
} while(0)

#define GEN_SET_FNUM(field) do { \
	int i; \
	for (i=0;i<NSERVERS;i++) { \
		parm[i].field = gen_lookup_handle(i, parm[i].field.data[0]); \
	} \
} while(0)

#define CHECK_EQUAL(field) do { \
	if (parm[0].field != parm[1].field && !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%llx 0x%llx\n", #field, \
		       (unsigned long long)parm[0].field, (unsigned long long)parm[1].field); \
		return false; \
	} \
} while(0)

#define CHECK_SECDESC(field) do { \
	if (!security_acl_equal(parm[0].field->dacl, parm[1].field->dacl) && !ignore_pattern(#field)) { \
		printf("Mismatch in %s\n", #field); \
		return false;			    \
	} \
} while(0)

#define CHECK_ATTRIB(field) do { \
		if (!options.mask_indexing) { \
		CHECK_EQUAL(field); \
	} else if ((~FILE_ATTRIBUTE_NONINDEXED & parm[0].field) != (~FILE_ATTRIBUTE_NONINDEXED & parm[1].field) && !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%x 0x%x\n", #field, \
		       (int)parm[0].field, (int)parm[1].field); \
		return false; \
	} \
} while(0)

#define CHECK_WSTR_EQUAL(field) do { \
	if ((!parm[0].field.s && parm[1].field.s) || (parm[0].field.s && !parm[1].field.s)) { \
		printf("%s is NULL!\n", #field); \
		return false; \
	} \
	if (parm[0].field.s && strcmp(parm[0].field.s, parm[1].field.s) != 0 && !ignore_pattern(#field)) { \
		printf("Mismatch in %s - %s %s\n", #field, \
		       parm[0].field.s, parm[1].field.s); \
		return false; \
	} \
	CHECK_EQUAL(field.private_length); \
} while(0)

#define CHECK_BLOB_EQUAL(field) do { \
	if (memcmp(parm[0].field.data, parm[1].field.data, parm[0].field.length) != 0 && !ignore_pattern(#field)) { \
		printf("Mismatch in %s\n", #field); \
		return false; \
	} \
	CHECK_EQUAL(field.length); \
} while(0)

#define CHECK_NTTIMES_EQUAL(field) do { \
	if (labs(nt_time_to_unix(parm[0].field) - \
		nt_time_to_unix(parm[1].field)) > time_skew() && \
	    !ignore_pattern(#field)) { \
		printf("Mismatch in %s - 0x%x 0x%x\n", #field, \
		       (int)nt_time_to_unix(parm[0].field), \
		       (int)nt_time_to_unix(parm[1].field)); \
		return false; \
	} \
} while(0)

/*
  generate ntcreatex operations
*/
static bool handler_create(int instance)
{
	struct smb2_create parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	ZERO_STRUCT(parm[0]);
	parm[0].in.security_flags             = gen_bits_levels(3, 90, 0x0, 70, 0x3, 100, 0xFF);
	parm[0].in.oplock_level               = gen_bits_levels(3, 90, 0x0, 70, 0x9, 100, 0xFF);
	parm[0].in.impersonation_level        = gen_bits_levels(3, 90, 0x0, 70, 0x3, 100, 0xFFFFFFFF);
	parm[0].in.create_flags               = gen_reserved64();
	parm[0].in.reserved                   = gen_reserved64();
	parm[0].in.desired_access             = gen_access_mask();
	parm[0].in.file_attributes            = gen_attrib();
	parm[0].in.share_access               = gen_bits_mask2(0x7, 0xFFFFFFFF);
	parm[0].in.create_disposition         = gen_open_disp();
	parm[0].in.create_options             = gen_create_options();
	parm[0].in.fname                      = gen_fname_open(instance);
	parm[0].in.eas			      = gen_ea_list();
	parm[0].in.alloc_size		      = gen_alloc_size();
	parm[0].in.durable_open		      = gen_bool();
	parm[0].in.query_maximal_access	      = gen_bool();
	parm[0].in.timewarp		      = gen_timewarp();
	parm[0].in.query_on_disk_id	      = gen_bool();
	parm[0].in.sec_desc		      = gen_sec_desc();

	if (!options.use_oplocks) {
		/* mask out oplocks */
		parm[0].in.oplock_level = 0;
	}

	if (options.valid) {
		parm[0].in.security_flags   &= 3;
		parm[0].in.oplock_level     &= 9;
		parm[0].in.impersonation_level &= 3;
	}

	GEN_COPY_PARM;
	GEN_CALL(smb2_create(tree, current_op.mem_ctx, &parm[i]));

	CHECK_EQUAL(out.oplock_level);
	CHECK_EQUAL(out.reserved);
	CHECK_EQUAL(out.create_action);
	CHECK_NTTIMES_EQUAL(out.create_time);
	CHECK_NTTIMES_EQUAL(out.access_time);
	CHECK_NTTIMES_EQUAL(out.write_time);
	CHECK_NTTIMES_EQUAL(out.change_time);
	CHECK_EQUAL(out.alloc_size);
	CHECK_EQUAL(out.size);
	CHECK_ATTRIB(out.file_attr);
	CHECK_EQUAL(out.reserved2);
	CHECK_EQUAL(out.maximal_access);

	/* ntcreatex creates a new file handle */
	ADD_HANDLE(parm[0].in.fname, out.file.handle);

	return true;
}

/*
  generate close operations
*/
static bool handler_close(int instance)
{
	struct smb2_close parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	ZERO_STRUCT(parm[0]);
	parm[0].in.file.handle.data[0] = gen_fnum_close(instance);
	parm[0].in.flags               = gen_bits_mask2(0x1, 0xFFFF);

	GEN_COPY_PARM;
	GEN_SET_FNUM(in.file.handle);
	GEN_CALL(smb2_close(tree, &parm[i]));

	CHECK_EQUAL(out.flags);
	CHECK_EQUAL(out._pad);
	CHECK_NTTIMES_EQUAL(out.create_time);
	CHECK_NTTIMES_EQUAL(out.access_time);
	CHECK_NTTIMES_EQUAL(out.write_time);
	CHECK_NTTIMES_EQUAL(out.change_time);
	CHECK_EQUAL(out.alloc_size);
	CHECK_EQUAL(out.size);
	CHECK_ATTRIB(out.file_attr);

	REMOVE_HANDLE(in.file.handle);

	return true;
}

/*
  generate read operations
*/
static bool handler_read(int instance)
{
	struct smb2_read parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].in.file.handle.data[0] = gen_fnum(instance);
	parm[0].in.reserved    = gen_reserved8();
	parm[0].in.length      = gen_io_count();
	parm[0].in.offset      = gen_offset();
	parm[0].in.min_count   = gen_io_count();
	parm[0].in.channel     = gen_bits_mask2(0x0, 0xFFFFFFFF);
	parm[0].in.remaining   = gen_bits_mask2(0x0, 0xFFFFFFFF);
	parm[0].in.channel_offset = gen_bits_mask2(0x0, 0xFFFF);
	parm[0].in.channel_length = gen_bits_mask2(0x0, 0xFFFF);

	GEN_COPY_PARM;
	GEN_SET_FNUM(in.file.handle);
	GEN_CALL(smb2_read(tree, current_op.mem_ctx, &parm[i]));

	CHECK_EQUAL(out.remaining);
	CHECK_EQUAL(out.reserved);
	CHECK_EQUAL(out.data.length);

	return true;
}

/*
  generate write operations
*/
static bool handler_write(int instance)
{
	struct smb2_write parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].in.file.handle.data[0] = gen_fnum(instance);
	parm[0].in.offset = gen_offset();
	parm[0].in.unknown1 = gen_bits_mask2(0, 0xFFFFFFFF);
	parm[0].in.unknown2 = gen_bits_mask2(0, 0xFFFFFFFF);
	parm[0].in.data = data_blob_talloc(current_op.mem_ctx, NULL,
					    gen_io_count());

	GEN_COPY_PARM;
	GEN_SET_FNUM(in.file.handle);
	GEN_CALL(smb2_write(tree, &parm[i]));

	CHECK_EQUAL(out._pad);
	CHECK_EQUAL(out.nwritten);
	CHECK_EQUAL(out.unknown1);

	return true;
}

/*
  generate lockingx operations
*/
static bool handler_lock(int instance)
{
	struct smb2_lock parm[NSERVERS];
	NTSTATUS status[NSERVERS];
	int n;

	parm[0].level = RAW_LOCK_LOCKX;
	parm[0].in.file.handle.data[0] = gen_fnum(instance);
	parm[0].in.lock_count = gen_lock_count();
	parm[0].in.reserved = gen_reserved32();
	
	parm[0].in.locks = talloc_array(current_op.mem_ctx,
					struct smb2_lock_element,
					parm[0].in.lock_count);
	for (n=0;n<parm[0].in.lock_count;n++) {
		parm[0].in.locks[n].offset = gen_offset();
		parm[0].in.locks[n].length = gen_io_count();
		/* don't yet cope with async replies */
		parm[0].in.locks[n].flags  = gen_lock_flags() | 
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
		parm[0].in.locks[n].reserved = gen_bits_mask2(0x0, 0xFFFFFFFF);
	}

	GEN_COPY_PARM;
	GEN_SET_FNUM(in.file.handle);
	GEN_CALL(smb2_lock(tree, &parm[i]));

	return true;
}

/*
  generate flush operations
*/
static bool handler_flush(int instance)
{
	struct smb2_flush parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	ZERO_STRUCT(parm[0]);
	parm[0].in.file.handle.data[0] = gen_fnum(instance);
	parm[0].in.reserved1  = gen_reserved16();
	parm[0].in.reserved2  = gen_reserved32();

	GEN_COPY_PARM;
	GEN_SET_FNUM(in.file.handle);
	GEN_CALL(smb2_flush(tree, &parm[i]));

	CHECK_EQUAL(out.reserved);

	return true;
}

/*
  generate echo operations
*/
static bool handler_echo(int instance)
{
	NTSTATUS status[NSERVERS];

	GEN_CALL(smb2_keepalive(tree->session->transport));

	return true;
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
		LVL(BASIC_INFORMATION),
		LVL(STANDARD_INFORMATION), LVL(INTERNAL_INFORMATION), LVL(EA_INFORMATION),
		LVL(ACCESS_INFORMATION), LVL(NAME_INFORMATION), LVL(POSITION_INFORMATION),
		LVL(MODE_INFORMATION), LVL(ALIGNMENT_INFORMATION), LVL(SMB2_ALL_INFORMATION),
		LVL(ALT_NAME_INFORMATION), LVL(STREAM_INFORMATION), LVL(COMPRESSION_INFORMATION),
		LVL(NETWORK_OPEN_INFORMATION), LVL(ATTRIBUTE_TAG_INFORMATION),
		LVL(SMB2_ALL_EAS), LVL(SMB2_ALL_INFORMATION), LVL(SEC_DESC),
	};
	do {
		i = gen_int_range(0, ARRAY_SIZE(levels)-1);
	} while (ignore_pattern(levels[i].name));

	info->generic.level = levels[i].level;
}

/*
  compare returned fileinfo structures
*/
static bool cmp_fileinfo(int instance, 
			 union smb_fileinfo parm[NSERVERS],
			 NTSTATUS status[NSERVERS])
{
	int i;

	switch (parm[0].generic.level) {
	case RAW_FILEINFO_GENERIC:
		return false;

		/* SMB1 specific values */
	case RAW_FILEINFO_GETATTR:
	case RAW_FILEINFO_GETATTRE:
	case RAW_FILEINFO_STANDARD:
	case RAW_FILEINFO_EA_SIZE:
	case RAW_FILEINFO_ALL_EAS:
	case RAW_FILEINFO_IS_NAME_VALID:
	case RAW_FILEINFO_BASIC_INFO:
	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_EA_INFO:
	case RAW_FILEINFO_NAME_INFO:
	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_COMPRESSION_INFO:
		return false;

	case RAW_FILEINFO_BASIC_INFORMATION:
		CHECK_NTTIMES_EQUAL(basic_info.out.create_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.access_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.write_time);
		CHECK_NTTIMES_EQUAL(basic_info.out.change_time);
		CHECK_ATTRIB(basic_info.out.attrib);
		break;

	case RAW_FILEINFO_STANDARD_INFORMATION:
		CHECK_EQUAL(standard_info.out.alloc_size);
		CHECK_EQUAL(standard_info.out.size);
		CHECK_EQUAL(standard_info.out.nlink);
		CHECK_EQUAL(standard_info.out.delete_pending);
		CHECK_EQUAL(standard_info.out.directory);
		break;

	case RAW_FILEINFO_EA_INFORMATION:
		CHECK_EQUAL(ea_info.out.ea_size);
		break;

	case RAW_FILEINFO_NAME_INFORMATION:
		CHECK_WSTR_EQUAL(name_info.out.fname);
		break;

	case RAW_FILEINFO_ALT_NAME_INFORMATION:
		CHECK_WSTR_EQUAL(alt_name_info.out.fname);
		break;

	case RAW_FILEINFO_STREAM_INFORMATION:
		CHECK_EQUAL(stream_info.out.num_streams);
		for (i=0;i<parm[0].stream_info.out.num_streams;i++) {
			CHECK_EQUAL(stream_info.out.streams[i].size);
			CHECK_EQUAL(stream_info.out.streams[i].alloc_size);
			CHECK_WSTR_EQUAL(stream_info.out.streams[i].stream_name);
		}
		break;

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
		CHECK_ATTRIB(network_open_information.out.attrib);
		break;

	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		CHECK_ATTRIB(attribute_tag_information.out.attrib);
		CHECK_EQUAL(attribute_tag_information.out.reparse_tag);
		break;

	case RAW_FILEINFO_ALL_INFORMATION:
	case RAW_FILEINFO_SMB2_ALL_INFORMATION:
		CHECK_NTTIMES_EQUAL(all_info2.out.create_time);
		CHECK_NTTIMES_EQUAL(all_info2.out.access_time);
		CHECK_NTTIMES_EQUAL(all_info2.out.write_time);
		CHECK_NTTIMES_EQUAL(all_info2.out.change_time);
		CHECK_ATTRIB(all_info2.out.attrib);
		CHECK_EQUAL(all_info2.out.unknown1);
		CHECK_EQUAL(all_info2.out.alloc_size);
		CHECK_EQUAL(all_info2.out.size);
		CHECK_EQUAL(all_info2.out.nlink);
		CHECK_EQUAL(all_info2.out.delete_pending);
		CHECK_EQUAL(all_info2.out.directory);
		CHECK_EQUAL(all_info2.out.file_id);
		CHECK_EQUAL(all_info2.out.ea_size);
		CHECK_EQUAL(all_info2.out.access_mask);
		CHECK_EQUAL(all_info2.out.position);
		CHECK_EQUAL(all_info2.out.mode);
		CHECK_EQUAL(all_info2.out.alignment_requirement);
		CHECK_WSTR_EQUAL(all_info2.out.fname);
		break;

	case RAW_FILEINFO_SMB2_ALL_EAS:
		CHECK_EQUAL(all_eas.out.num_eas);
		for (i=0;i<parm[0].all_eas.out.num_eas;i++) {
			CHECK_EQUAL(all_eas.out.eas[i].flags);
			CHECK_WSTR_EQUAL(all_eas.out.eas[i].name);
			CHECK_BLOB_EQUAL(all_eas.out.eas[i].value);
		}
		break;

	case RAW_FILEINFO_SEC_DESC:
		CHECK_SECDESC(query_secdesc.out.sd);
		break;

		/* Unhandled levels */
	case RAW_FILEINFO_EA_LIST:
	case RAW_FILEINFO_UNIX_BASIC:
	case RAW_FILEINFO_UNIX_LINK:
	case RAW_FILEINFO_UNIX_INFO2:
		break;
	}

	return true;
}

/*
  generate qfileinfo operations
*/
static bool handler_qfileinfo(int instance)
{
	union smb_fileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.handle.data[0] = gen_fnum(instance);

	gen_fileinfo(instance, &parm[0]);

	GEN_COPY_PARM;
	GEN_SET_FNUM(generic.in.file.handle);
	GEN_CALL(smb2_getinfo_file(tree, current_op.mem_ctx, &parm[i]));

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
		LVL(BASIC_INFORMATION),
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
	case RAW_SFILEINFO_SETATTRE:
	case RAW_SFILEINFO_STANDARD:
	case RAW_SFILEINFO_EA_SET:
	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFO:
		break;

	case RAW_SFILEINFO_BASIC_INFORMATION:
		info->basic_info.in.create_time = gen_nttime();
		info->basic_info.in.access_time = gen_nttime();
		info->basic_info.in.write_time = gen_nttime();
		info->basic_info.in.change_time = gen_nttime();
		info->basic_info.in.attrib = gen_attrib();
		break;
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
		info->disposition_info.in.delete_on_close = gen_bool();
		break;
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		info->allocation_info.in.alloc_size = gen_alloc_size();
		break;
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		info->end_of_file_info.in.size = gen_offset();
		break;
	case RAW_SFILEINFO_RENAME_INFORMATION:
	case RAW_SFILEINFO_RENAME_INFORMATION_SMB2:
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
	case RAW_SFILEINFO_1023:
	case RAW_SFILEINFO_1025:
	case RAW_SFILEINFO_1029:
	case RAW_SFILEINFO_1032:
	case RAW_SFILEINFO_1039:
	case RAW_SFILEINFO_1040:
	case RAW_SFILEINFO_UNIX_BASIC:
	case RAW_SFILEINFO_UNIX_INFO2:
	case RAW_SFILEINFO_UNIX_LINK:
	case RAW_SFILEINFO_UNIX_HLINK:
		/* Untested */
		break;
	}
}

/*
  generate setfileinfo operations
*/
static bool handler_sfileinfo(int instance)
{
	union smb_setfileinfo parm[NSERVERS];
	NTSTATUS status[NSERVERS];

	parm[0].generic.in.file.fnum = gen_fnum(instance);

	gen_setfileinfo(instance, &parm[0]);

	GEN_COPY_PARM;
	GEN_SET_FNUM(generic.in.file.handle);
	GEN_CALL(smb2_setinfo_file(tree, &parm[i]));

	return true;
}

/*
  wipe any relevant files
*/
static void wipe_files(void)
{
	int i;
	NTSTATUS status;

	if (options.skip_cleanup) {
		return;
	}

	for (i=0;i<NSERVERS;i++) {
		int n = smb2_deltree(servers[i].tree[0], "gentest");
		if (n == -1) {
			printf("Failed to wipe tree on server %d\n", i);
			exit(1);
		}
		status = smb2_util_mkdir(servers[i].tree[0], "gentest");
		if (NT_STATUS_IS_ERR(status)) {
			printf("Failed to create gentest on server %d - %s\n", i, nt_errstr(status));
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
	bool (*handler)(int instance);
	int count, success_count;
} gen_ops[] = {
	{"CREATE",     handler_create},
	{"CLOSE",      handler_close},
	{"READ",       handler_read},
	{"WRITE",      handler_write},
	{"LOCK",       handler_lock},
	{"FLUSH",      handler_flush},
	{"ECHO",       handler_echo},
	{"QFILEINFO",  handler_qfileinfo},
	{"SFILEINFO",  handler_sfileinfo},
};


/*
  run the test with the current set of op_parms parameters
  return the number of operations that completed successfully
*/
static int run_test(struct event_context *ev, struct loadparm_context *lp_ctx)
{
	int op, i;

	if (!connect_servers(ev, lp_ctx)) {
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
		bool ret;

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
static void backtrack_analyze(struct event_context *ev,
			      struct loadparm_context *lp_ctx)
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
				op_parms[i].disabled = true;
			}
			printf("Testing %d ops with %d-%d disabled\n", 
			       options.numops, base, max-1);
			ret = run_test(ev, lp_ctx);
			printf("Completed %d of %d ops\n", ret, options.numops);
			for (i=base;i<max; i++) {
				op_parms[i].disabled = false;
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
	ret = run_test(ev, lp_ctx);
	if (ret != options.numops - 1) {
		printf("Inconsistent result? ret=%d numops=%d\n", ret, options.numops);
	}
}

/* 
   start the main gentest process
*/
static bool start_gentest(struct event_context *ev,
			  struct loadparm_context *lp_ctx)
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

	ret = run_test(ev, lp_ctx);

	if (ret != options.numops && options.analyze) {
		options.numops = ret+1;
		backtrack_analyze(ev, lp_ctx);
	} else if (options.analyze_always) {
		backtrack_analyze(ev, lp_ctx);
	} else if (options.analyze_continuous) {
		while (run_test(ev, lp_ctx) == options.numops) ;
	}

	return ret == options.numops;
}


static void usage(poptContext pc)
{
	printf(
"Usage:\n\
  gentest //server1/share1 //server2/share2 [options..]\n\
");
	poptPrintUsage(pc, stdout, 0);
}

/**
  split a UNC name into server and share names
*/
static bool split_unc_name(const char *unc, char **server, char **share)
{
	char *p = strdup(unc);
	if (!p) return false;
	all_string_sub(p, "\\", "/", 0);
	if (strncmp(p, "//", 2) != 0) return false;

	(*server) = p+2;
	p = strchr(*server, '/');
	if (!p) return false;

	*p = 0;
	(*share) = p+1;
	
	return true;
}



/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, char *argv[])
{
	int opt;
	int i, username_count=0;
	bool ret;
	char *ignore_file=NULL;
	struct event_context *ev;
	struct loadparm_context *lp_ctx;
	poptContext pc;
	int argc_new;
	char **argv_new;
	enum {OPT_UNCLIST=1000};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"seed",	  0, POPT_ARG_INT,  &options.seed, 	0,	"Seed to use for randomizer", 	NULL},
		{"num-ops",	  0, POPT_ARG_INT,  &options.numops, 	0, 	"num ops",	NULL},
		{"oplocks",       0, POPT_ARG_NONE, &options.use_oplocks,0,      "use oplocks", NULL},
		{"showall",       0, POPT_ARG_NONE, &options.showall,    0,      "display all operations", NULL},
		{"analyse",       0, POPT_ARG_NONE, &options.analyze,    0,      "do backtrack analysis", NULL},
		{"analysealways", 0, POPT_ARG_NONE, &options.analyze_always,    0,      "analysis always", NULL},
		{"analysecontinuous", 0, POPT_ARG_NONE, &options.analyze_continuous,    0,      "analysis continuous", NULL},
		{"ignore",        0, POPT_ARG_STRING, &ignore_file,    0,      "ignore from file", NULL},
		{"preset",        0, POPT_ARG_NONE, &options.use_preset_seeds,    0,      "use preset seeds", NULL},
		{"fast",          0, POPT_ARG_NONE, &options.fast_reconnect,    0,      "use fast reconnect", NULL},
		{"unclist",	  0, POPT_ARG_STRING,	NULL, 	OPT_UNCLIST,	"unclist", 	NULL},
		{"seedsfile",	  0, POPT_ARG_STRING,  &options.seeds_file, 0,	"seed file", 	NULL},
		{ "user", 'U',       POPT_ARG_STRING, NULL, 'U', "Set the network username", "[DOMAIN/]USERNAME[%PASSWORD]" },
		{"maskindexing",  0, POPT_ARG_NONE,  &options.mask_indexing, 0,	"mask out the indexed file attrib", 	NULL},
		{"noeas",  0, POPT_ARG_NONE,  &options.no_eas, 0,	"don't use extended attributes", 	NULL},
		{"skip-cleanup",  0, POPT_ARG_NONE,  &options.skip_cleanup, 0,	"don't delete files at start", 	NULL},
		{"valid",  0, POPT_ARG_NONE,  &options.valid, 0,	"generate only valid fields", 	NULL},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		{ NULL }
	};

	memset(&bad_smb2_handle, 0xFF, sizeof(bad_smb2_handle));

	setlinebuf(stdout);
	options.seed = time(NULL);
	options.numops = 1000;
	options.max_open_handles = 20;
	options.seeds_file = "gentest_seeds.dat";

	pc = poptGetContext("gentest", argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	poptSetOtherOptionHelp(pc, "<unc1> <unc2>");

	lp_ctx = cmdline_lp_ctx;
	servers[0].credentials = cli_credentials_init(talloc_autofree_context());
	servers[1].credentials = cli_credentials_init(talloc_autofree_context());
	cli_credentials_guess(servers[0].credentials, lp_ctx);
	cli_credentials_guess(servers[1].credentials, lp_ctx);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_UNCLIST:
			lp_set_cmdline(cmdline_lp_ctx, "torture:unclist", poptGetOptArg(pc));
			break;
		case 'U':
			if (username_count == 2) {
				usage(pc);
				exit(1);
			}
			cli_credentials_parse_string(servers[username_count].credentials, poptGetOptArg(pc), CRED_SPECIFIED);
			username_count++;
			break;
		}
	}

	if (ignore_file) {
		options.ignore_patterns = file_lines_load(ignore_file, NULL, NULL);
	}

	argv_new = discard_const_p(char *, poptGetArgs(pc));
	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (!(argc_new >= 3)) {
		usage(pc);
		exit(1);
	}

	setlinebuf(stdout);

	setup_logging("gentest", DEBUG_STDOUT);

	if (argc < 3 || argv[1][0] == '-') {
		usage(pc);
		exit(1);
	}

	setup_logging(argv[0], DEBUG_STDOUT);

	for (i=0;i<NSERVERS;i++) {
		const char *share = argv[1+i];
		if (!split_unc_name(share, &servers[i].server_name, &servers[i].share_name)) {
			printf("Invalid share name '%s'\n", share);
			return -1;
		}
	}

	if (username_count == 0) {
		usage(pc);
		return -1;
	}
	if (username_count == 1) {
		servers[1].credentials = servers[0].credentials;
	}

	printf("seed=%u\n", options.seed);

	ev = event_context_init(talloc_autofree_context());

	gensec_init(lp_ctx);

	ret = start_gentest(ev, lp_ctx);

	if (ret) {
		printf("gentest completed - no errors\n");
	} else {
		printf("gentest failed\n");
	}

	return ret?0:-1;
}
