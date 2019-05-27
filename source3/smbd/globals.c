/*
   Unix SMB/Netbios implementation.
   smbd globals
   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../lib/util/memcache.h"
#include "messages.h"
#include <tdb.h>

#ifdef USE_DMAPI
struct smbd_dmapi_context *dmapi_ctx = NULL;
#endif

const struct mangle_fns *mangle_fns = NULL;

unsigned char *chartest = NULL;
TDB_CONTEXT *tdb_mangled_cache = NULL;

/*
  this determines how many characters are used from the original filename
  in the 8.3 mangled name. A larger value leads to a weaker hash and more collisions.
  The largest possible value is 6.
*/
unsigned mangle_prefix = 0;

bool logged_ioctl_message = false;

time_t last_smb_conf_reload_time = 0;
pid_t background_lpq_updater_pid = -1;

/****************************************************************************
 structure to hold a linked list of queued messages.
 for processing.
****************************************************************************/
uint32_t common_flags2 = FLAGS2_LONG_PATH_COMPONENTS|FLAGS2_32_BIT_ERROR_CODES|FLAGS2_EXTENDED_ATTRIBUTES;

struct smb_trans_enc_state *partial_srv_trans_enc_ctx = NULL;
struct smb_trans_enc_state *srv_trans_enc_ctx = NULL;

/* A stack of security contexts.  We include the current context as being
   the first one, so there is room for another MAX_SEC_CTX_DEPTH more. */
struct sec_ctx sec_ctx_stack[MAX_SEC_CTX_DEPTH + 1];
int sec_ctx_stack_ndx = 0;
bool become_uid_done = false;
bool become_gid_done = false;

connection_struct *last_conn = NULL;
uint16_t last_flags = 0;

uint32_t global_client_caps = 0;

uint16_t fnf_handle = 257;

/* A stack of current_user connection contexts. */
struct conn_ctx conn_ctx_stack[MAX_SEC_CTX_DEPTH];
int conn_ctx_stack_ndx = 0;

struct vfs_init_function_entry *backends = NULL;
char *sparse_buf = NULL;
char *LastDir = NULL;

struct smbd_parent_context *am_parent = NULL;
struct memcache *smbd_memcache_ctx = NULL;
bool exit_firsttime = true;

struct smbXsrv_client *global_smbXsrv_client = NULL;

struct memcache *smbd_memcache(void)
{
	if (!smbd_memcache_ctx) {
		/*
		 * Note we MUST use the NULL context here, not the
		 * autofree context, to avoid side effects in forked
		 * children exiting.
		 */
		smbd_memcache_ctx = memcache_init(NULL,
						  lp_max_stat_cache_size()*1024);
	}
	if (!smbd_memcache_ctx) {
		smb_panic("Could not init smbd memcache");
	}

	return smbd_memcache_ctx;
}

void smbd_init_globals(void)
{
	ZERO_STRUCT(conn_ctx_stack);

	ZERO_STRUCT(sec_ctx_stack);
}

struct GUID smbd_request_guid(struct smb_request *smb1req, uint16_t idx)
{
	struct GUID v = {
		.time_low = (uint32_t)smb1req->mid,
		.time_hi_and_version = idx,
	};

	if (smb1req->smb2req != NULL) {
		v.time_mid = (uint16_t)smb1req->smb2req->current_idx;
	} else {
		v.time_mid = (uint16_t)(uintptr_t)smb1req->vwv;
	}

	SBVAL((uint8_t *)&v, 8, (uintptr_t)smb1req->xconn);

	return v;
}
