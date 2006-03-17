/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "lib/cmdline/popt_common.h"
#include "libcli/raw/libcliraw.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/filesys.h"
#include "libcli/raw/ioctl.h"
#include "libcli/libcli.h"
#include "lib/ldb/include/ldb.h"
#include "lib/events/events.h"
#include "libcli/resolve/resolve.h"
#include "auth/credentials/credentials.h"
#include "libcli/ldap/ldap_client.h"
#include "librpc/gen_ndr/ndr_nbt.h"

#include "torture/raw/proto.h"
#include "torture/smb2/proto.h"
#include "torture/rap/proto.h"
#include "torture/auth/proto.h"
#include "torture/local/proto.h"
#include "torture/nbench/proto.h"
#include "torture/ldap/proto.h"
#include "torture/com/proto.h"
#include "torture/nbt/proto.h"
#include "torture/libnet/proto.h"
#include "torture/torture.h"
#include "build.h"
#include "dlinklist.h"

int torture_nprocs=4;
_PUBLIC_ int torture_numops=10;
_PUBLIC_ int torture_entries=1000;
_PUBLIC_ int torture_failures=1;
_PUBLIC_ int torture_seed=0;
static int procnum; /* records process count number when forking */
static struct smbcli_state *current_cli;
static BOOL use_oplocks;
static BOOL use_level_II_oplocks;
#define MAX_COLS 80 /* FIXME: Determine this at run-time */

_PUBLIC_ BOOL torture_showall = False;

BOOL torture_open_connection_share(TALLOC_CTX *mem_ctx,
				   struct smbcli_state **c, 
				   const char *hostname, 
				   const char *sharename,
				   struct event_context *ev)
{
	NTSTATUS status;

	status = smbcli_full_connection(mem_ctx, c, hostname, 
					sharename, NULL,
					cmdline_credentials, ev);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open connection - %s\n", nt_errstr(status));
		return False;
	}

	(*c)->transport->options.use_oplocks = use_oplocks;
	(*c)->transport->options.use_level2_oplocks = use_level_II_oplocks;

	return True;
}

_PUBLIC_ BOOL torture_open_connection(struct smbcli_state **c)
{
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");

	return torture_open_connection_share(NULL, c, host, share, NULL);
}



_PUBLIC_ BOOL torture_close_connection(struct smbcli_state *c)
{
	BOOL ret = True;
	if (!c) return True;
	if (NT_STATUS_IS_ERR(smbcli_tdis(c))) {
		printf("tdis failed (%s)\n", smbcli_errstr(c->tree));
		ret = False;
	}
	talloc_free(c);
	return ret;
}


/* check if the server produced the expected error code */
_PUBLIC_ BOOL check_error(const char *location, struct smbcli_state *c, 
		 uint8_t eclass, uint32_t ecode, NTSTATUS nterr)
{
	NTSTATUS status;
	
	status = smbcli_nt_error(c->tree);
	if (NT_STATUS_IS_DOS(status)) {
		int class, num;
		class = NT_STATUS_DOS_CLASS(status);
		num = NT_STATUS_DOS_CODE(status);
                if (eclass != class || ecode != num) {
                        printf("unexpected error code %s\n", nt_errstr(status));
                        printf(" expected %s or %s (at %s)\n", 
			       nt_errstr(NT_STATUS_DOS(eclass, ecode)), 
                               nt_errstr(nterr), location);
                        return False;
                }
        } else {
                if (!NT_STATUS_EQUAL(nterr, status)) {
                        printf("unexpected error code %s\n", nt_errstr(status));
                        printf(" expected %s (at %s)\n", nt_errstr(nterr), location);
                        return False;
                }
        }

	return True;
}


static BOOL wait_lock(struct smbcli_state *c, int fnum, uint32_t offset, uint32_t len)
{
	while (NT_STATUS_IS_ERR(smbcli_lock(c->tree, fnum, offset, len, -1, WRITE_LOCK))) {
		if (!check_error(__location__, c, ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) return False;
	}
	return True;
}


static BOOL rw_torture(struct smbcli_state *c)
{
	const char *lockfname = "\\torture.lck";
	char *fname;
	int fnum;
	int fnum2;
	pid_t pid2, pid = getpid();
	int i, j;
	uint8_t buf[1024];
	BOOL correct = True;

	fnum2 = smbcli_open(c->tree, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE);
	if (fnum2 == -1)
		fnum2 = smbcli_open(c->tree, lockfname, O_RDWR, DENY_NONE);
	if (fnum2 == -1) {
		printf("open of %s failed (%s)\n", lockfname, smbcli_errstr(c->tree));
		return False;
	}


	for (i=0;i<torture_numops;i++) {
		uint_t n = (uint_t)random()%10;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		asprintf(&fname, "\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		fnum = smbcli_open(c->tree, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_ALL);
		if (fnum == -1) {
			printf("open failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
			break;
		}

		if (smbcli_write(c->tree, fnum, 0, &pid, 0, sizeof(pid)) != sizeof(pid)) {
			printf("write failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		for (j=0;j<50;j++) {
			if (smbcli_write(c->tree, fnum, 0, buf, 
				      sizeof(pid)+(j*sizeof(buf)), 
				      sizeof(buf)) != sizeof(buf)) {
				printf("write failed (%s)\n", smbcli_errstr(c->tree));
				correct = False;
			}
		}

		pid2 = 0;

		if (smbcli_read(c->tree, fnum, &pid2, 0, sizeof(pid)) != sizeof(pid)) {
			printf("read failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_close(c->tree, fnum))) {
			printf("close failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_unlink(c->tree, fname))) {
			printf("unlink failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}

		if (NT_STATUS_IS_ERR(smbcli_unlock(c->tree, fnum2, n*sizeof(int), sizeof(int)))) {
			printf("unlock failed (%s)\n", smbcli_errstr(c->tree));
			correct = False;
		}
		free(fname);
	}

	smbcli_close(c->tree, fnum2);
	smbcli_unlink(c->tree, lockfname);

	printf("%d\n", i);

	return correct;
}

static BOOL run_torture(struct smbcli_state *cli, int dummy)
{
        BOOL ret;

	ret = rw_torture(cli);
	
	if (!torture_close_connection(cli)) {
		ret = False;
	}

	return ret;
}


/*
  see how many RPC pipes we can open at once
*/
static BOOL run_pipe_number(void)
{
	struct smbcli_state *cli1;
	const char *pipe_name = "\\WKSSVC";
	int fnum;
	int num_pipes = 0;

	printf("starting pipenumber test\n");
	if (!torture_open_connection(&cli1)) {
		return False;
	}

	while(1) {
		fnum = smbcli_nt_create_full(cli1->tree, pipe_name, 0, SEC_FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, NTCREATEX_DISP_OPEN_IF, 0, 0);

		if (fnum == -1) {
			printf("Open of pipe %s failed with error (%s)\n", pipe_name, smbcli_errstr(cli1->tree));
			break;
		}
		num_pipes++;
		printf("%d\r", num_pipes);
		fflush(stdout);
	}

	printf("pipe_number test - we can open %d %s pipes.\n", num_pipes, pipe_name );
	torture_close_connection(cli1);
	return True;
}




/*
  open N connections to the server and just hold them open
  used for testing performance when there are N idle users
  already connected
 */
 static BOOL torture_holdcon(void)
{
	int i;
	struct smbcli_state **cli;
	int num_dead = 0;

	printf("Opening %d connections\n", torture_numops);
	
	cli = malloc_array_p(struct smbcli_state *, torture_numops);

	for (i=0;i<torture_numops;i++) {
		if (!torture_open_connection(&cli[i])) {
			return False;
		}
		printf("opened %d connections\r", i);
		fflush(stdout);
	}

	printf("\nStarting pings\n");

	while (1) {
		for (i=0;i<torture_numops;i++) {
			NTSTATUS status;
			if (cli[i]) {
				status = smbcli_chkpath(cli[i]->tree, "\\");
				if (!NT_STATUS_IS_OK(status)) {
					printf("Connection %d is dead\n", i);
					cli[i] = NULL;
					num_dead++;
				}
				usleep(100);
			}
		}

		if (num_dead == torture_numops) {
			printf("All connections dead - finishing\n");
			break;
		}

		printf(".");
		fflush(stdout);
	}

	return True;
}

/*
test how many open files this server supports on the one socket
*/
static BOOL run_maxfidtest(struct smbcli_state *cli, int dummy)
{
#define MAXFID_TEMPLATE "\\maxfid\\fid%d\\maxfid.%d.%d"
	char *fname;
	int fnums[0x11000], i;
	int retries=4, maxfid;
	BOOL correct = True;

	if (retries <= 0) {
		printf("failed to connect\n");
		return False;
	}

	if (smbcli_deltree(cli->tree, "\\maxfid") == -1) {
		printf("Failed to deltree \\maxfid - %s\n",
		       smbcli_errstr(cli->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, "\\maxfid"))) {
		printf("Failed to mkdir \\maxfid, error=%s\n", 
		       smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing maximum number of open files\n");

	for (i=0; i<0x11000; i++) {
		if (i % 1000 == 0) {
			asprintf(&fname, "\\maxfid\\fid%d", i/1000);
			if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, fname))) {
				printf("Failed to mkdir %s, error=%s\n", 
				       fname, smbcli_errstr(cli->tree));
				return False;
			}
			free(fname);
		}
		asprintf(&fname, MAXFID_TEMPLATE, i/1000, i,(int)getpid());
		if ((fnums[i] = smbcli_open(cli->tree, fname, 
					O_RDWR|O_CREAT|O_TRUNC, DENY_NONE)) ==
		    -1) {
			printf("open of %s failed (%s)\n", 
			       fname, smbcli_errstr(cli->tree));
			printf("maximum fnum is %d\n", i);
			break;
		}
		free(fname);
		printf("%6d\r", i);
	}
	printf("%6d\n", i);
	i--;

	maxfid = i;

	printf("cleaning up\n");
	for (i=0;i<maxfid/2;i++) {
		asprintf(&fname, MAXFID_TEMPLATE, i/1000, i,(int)getpid());
		if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnums[i]))) {
			printf("Close of fnum %d failed - %s\n", fnums[i], smbcli_errstr(cli->tree));
		}
		if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, fname))) {
			printf("unlink of %s failed (%s)\n", 
			       fname, smbcli_errstr(cli->tree));
			correct = False;
		}
		free(fname);

		asprintf(&fname, MAXFID_TEMPLATE, (maxfid-i)/1000, maxfid-i,(int)getpid());
		if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnums[maxfid-i]))) {
			printf("Close of fnum %d failed - %s\n", fnums[maxfid-i], smbcli_errstr(cli->tree));
		}
		if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, fname))) {
			printf("unlink of %s failed (%s)\n", 
			       fname, smbcli_errstr(cli->tree));
			correct = False;
		}
		free(fname);

		printf("%6d %6d\r", i, maxfid-i);
	}
	printf("%6d\n", 0);

	if (smbcli_deltree(cli->tree, "\\maxfid") == -1) {
		printf("Failed to deltree \\maxfid - %s\n",
		       smbcli_errstr(cli->tree));
		return False;
	}

	printf("maxfid test finished\n");
	if (!torture_close_connection(cli)) {
		correct = False;
	}
	return correct;
#undef MAXFID_TEMPLATE
}



/*
  sees what IOCTLs are supported
 */
BOOL torture_ioctl_test(void)
{
	struct smbcli_state *cli;
	uint16_t device, function;
	int fnum;
	const char *fname = "\\ioctl.dat";
	NTSTATUS status;
	union smb_ioctl parms;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("ioctl_test");

	printf("starting ioctl test\n");

	smbcli_unlink(cli->tree, fname);

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	parms.ioctl.level = RAW_IOCTL_IOCTL;
	parms.ioctl.in.file.fnum = fnum;
	parms.ioctl.in.request = IOCTL_QUERY_JOB_INFO;
	status = smb_raw_ioctl(cli->tree, mem_ctx, &parms);
	printf("ioctl job info: %s\n", smbcli_errstr(cli->tree));

	for (device=0;device<0x100;device++) {
		printf("testing device=0x%x\n", device);
		for (function=0;function<0x100;function++) {
			parms.ioctl.in.request = (device << 16) | function;
			status = smb_raw_ioctl(cli->tree, mem_ctx, &parms);

			if (NT_STATUS_IS_OK(status)) {
				printf("ioctl device=0x%x function=0x%x OK : %d bytes\n", 
					device, function, (int)parms.ioctl.out.blob.length);
			}
		}
	}

	if (!torture_close_connection(cli)) {
		return False;
	}

	return True;
}


static void sigcont(int sig)
{
}

double torture_create_procs(BOOL (*fn)(struct smbcli_state *, int), BOOL *result)
{
	int i, status;
	volatile pid_t *child_status;
	volatile BOOL *child_status_out;
	int synccount;
	int tries = 8;
	double start_time_limit = 10 + (torture_nprocs * 1.5);
	char **unc_list = NULL;
	const char *p;
	int num_unc_names = 0;
	struct timeval tv;

	*result = True;

	synccount = 0;

	signal(SIGCONT, sigcont);

	child_status = (volatile pid_t *)shm_setup(sizeof(pid_t)*torture_nprocs);
	if (!child_status) {
		printf("Failed to setup shared memory\n");
		return -1;
	}

	child_status_out = (volatile BOOL *)shm_setup(sizeof(BOOL)*torture_nprocs);
	if (!child_status_out) {
		printf("Failed to setup result status shared memory\n");
		return -1;
	}

	p = lp_parm_string(-1, "torture", "unclist");
	if (p) {
		unc_list = file_lines_load(p, &num_unc_names, NULL);
		if (!unc_list || num_unc_names <= 0) {
			printf("Failed to load unc names list from '%s'\n", p);
			exit(1);
		}
	}

	for (i = 0; i < torture_nprocs; i++) {
		child_status[i] = 0;
		child_status_out[i] = True;
	}

	tv = timeval_current();

	for (i=0;i<torture_nprocs;i++) {
		procnum = i;
		if (fork() == 0) {
			char *myname;
			char *hostname=NULL, *sharename;

			pid_t mypid = getpid();
			srandom(((int)mypid) ^ ((int)time(NULL)));

			asprintf(&myname, "CLIENT%d", i);
			lp_set_cmdline("netbios name", myname);
			free(myname);


			if (unc_list) {
				if (!smbcli_parse_unc(unc_list[i % num_unc_names],
						      NULL, &hostname, &sharename)) {
					printf("Failed to parse UNC name %s\n",
					       unc_list[i % num_unc_names]);
					exit(1);
				}
			}

			while (1) {
				if (hostname) {
					if (torture_open_connection_share(NULL,
									  &current_cli,
									  hostname, 
									  sharename,
									  NULL)) {
						break;
					}
				} else if (torture_open_connection(&current_cli)) {
						break;
				}
				if (tries-- == 0) {
					printf("pid %d failed to start\n", (int)getpid());
					_exit(1);
				}
				msleep(100);	
			}

			child_status[i] = getpid();

			pause();

			if (child_status[i]) {
				printf("Child %d failed to start!\n", i);
				child_status_out[i] = 1;
				_exit(1);
			}

			child_status_out[i] = fn(current_cli, i);
			_exit(0);
		}
	}

	do {
		synccount = 0;
		for (i=0;i<torture_nprocs;i++) {
			if (child_status[i]) synccount++;
		}
		if (synccount == torture_nprocs) break;
		msleep(100);
	} while (timeval_elapsed(&tv) < start_time_limit);

	if (synccount != torture_nprocs) {
		printf("FAILED TO START %d CLIENTS (started %d)\n", torture_nprocs, synccount);
		*result = False;
		return timeval_elapsed(&tv);
	}

	printf("Starting %d clients\n", torture_nprocs);

	/* start the client load */
	tv = timeval_current();
	for (i=0;i<torture_nprocs;i++) {
		child_status[i] = 0;
	}

	printf("%d clients started\n", torture_nprocs);

	kill(0, SIGCONT);

	for (i=0;i<torture_nprocs;i++) {
		int ret;
		while ((ret=waitpid(0, &status, 0)) == -1 && errno == EINTR) /* noop */ ;
		if (ret == -1 || WEXITSTATUS(status) != 0) {
			*result = False;
		}
	}

	printf("\n");
	
	for (i=0;i<torture_nprocs;i++) {
		if (!child_status_out[i]) {
			*result = False;
		}
	}
	return timeval_elapsed(&tv);
}

#define FLAG_MULTIPROC 1

static struct {
	const char *name;
	BOOL (*fn)(void);
	BOOL (*multi_fn)(struct smbcli_state *, int );
} builtin_torture_ops[] = {
	/* benchmarking tests */
	{"BENCH-HOLDCON",  torture_holdcon, 0},
	{"BENCH-NBENCH",  torture_nbench, 0},
	{"BENCH-TORTURE", NULL, run_torture},
	{"BENCH-NBT",     torture_bench_nbt, 0},
	{"BENCH-WINS",    torture_bench_wins, 0},
	{"BENCH-CLDAP",   torture_bench_cldap, 0},

	/* RAW smb tests */
	{"RAW-QFSINFO", torture_raw_qfsinfo, 0},
	{"RAW-QFILEINFO", torture_raw_qfileinfo, 0},
	{"RAW-SFILEINFO", torture_raw_sfileinfo, 0},
	{"RAW-SFILEINFO-BUG", torture_raw_sfileinfo_bug, 0},
	{"RAW-SEARCH", torture_raw_search, 0},
	{"RAW-CLOSE", torture_raw_close, 0},
	{"RAW-OPEN", torture_raw_open, 0},
	{"RAW-MKDIR", torture_raw_mkdir, 0},
	{"RAW-OPLOCK", torture_raw_oplock, 0},
	{"RAW-NOTIFY", torture_raw_notify, 0},
	{"RAW-MUX", torture_raw_mux, 0},
	{"RAW-IOCTL", torture_raw_ioctl, 0},
	{"RAW-CHKPATH", torture_raw_chkpath, 0},
	{"RAW-UNLINK", torture_raw_unlink, 0},
	{"RAW-READ", torture_raw_read, 0},
	{"RAW-WRITE", torture_raw_write, 0},
	{"RAW-LOCK", torture_raw_lock, 0},
	{"RAW-CONTEXT", torture_raw_context, 0},
	{"RAW-RENAME", torture_raw_rename, 0},
	{"RAW-SEEK", torture_raw_seek, 0},
	{"RAW-EAS", torture_raw_eas, 0},
	{"RAW-EAMAX", torture_max_eas, 0},
	{"RAW-STREAMS", torture_raw_streams, 0},
	{"RAW-ACLS", torture_raw_acls, 0},
	{"RAW-RAP", torture_raw_rap, 0},
	{"RAW-COMPOSITE", torture_raw_composite, 0},

	/* SMB2 tests */
	{"SMB2-CONNECT", torture_smb2_connect, 0},
	{"SMB2-SCAN", torture_smb2_scan, 0},
	{"SMB2-SCANGETINFO", torture_smb2_getinfo_scan, 0},
	{"SMB2-SCANSETINFO", torture_smb2_setinfo_scan, 0},
	{"SMB2-SCANFIND", torture_smb2_find_scan, 0},
	{"SMB2-GETINFO", torture_smb2_getinfo, 0},
	{"SMB2-SETINFO", torture_smb2_setinfo, 0},
	{"SMB2-FIND", torture_smb2_find, 0},

	/* protocol scanners */
	{"SCAN-MAXFID", NULL, run_maxfidtest},
	{"SCAN-PIPE_NUMBER", run_pipe_number, 0},
	{"SCAN-IOCTL",  torture_ioctl_test, 0},
	{"SCAN-RAP",  torture_rap_scan, 0},

	/* local (no server) testers */
	{"LOCAL-NTLMSSP", torture_ntlmssp_self_check, 0},
	{"LOCAL-ICONV", torture_local_iconv, 0},
	{"LOCAL-TALLOC", torture_local_talloc, 0},
	{"LOCAL-MESSAGING", torture_local_messaging, 0},
	{"LOCAL-IRPC",  torture_local_irpc, 0},
	{"LOCAL-BINDING", torture_local_binding_string, 0},
	{"LOCAL-STRLIST", torture_local_util_strlist, 0},
	{"LOCAL-FILE", torture_local_util_file, 0},
	{"LOCAL-IDTREE", torture_local_idtree, 0},
	{"LOCAL-SOCKET", torture_local_socket, 0},
	{"LOCAL-PAC", torture_pac, 0},
	{"LOCAL-REGISTRY", torture_registry, 0},
	{"LOCAL-RESOLVE", torture_local_resolve, 0},
	{"LOCAL-SDDL", torture_local_sddl, 0},
	{"LOCAL-NDR", torture_local_ndr, 0},

	/* ldap testers */
	{"LDAP-BASIC", torture_ldap_basic, 0},
	{"LDAP-CLDAP", torture_cldap, 0},

	/* nbt tests */
	{"NBT-REGISTER", torture_nbt_register, 0},
	{"NBT-WINS", torture_nbt_wins, 0},
	{"NBT-DGRAM", torture_nbt_dgram, 0},
	{"NBT-BROWSE", torture_nbt_browse, 0},
	{"NBT-WINSREPLICATION-SIMPLE", torture_nbt_winsreplication_simple, 0},
	{"NBT-WINSREPLICATION-REPLICA", torture_nbt_winsreplication_replica, 0},
	{"NBT-WINSREPLICATION-OWNED", torture_nbt_winsreplication_owned, 0},
	
	/* libnet tests */
	{"NET-USERINFO", torture_userinfo, 0},
	{"NET-USERADD", torture_useradd, 0},
	{"NET-USERDEL", torture_userdel, 0},
	{"NET-USERMOD", torture_usermod, 0},
	{"NET-DOMOPEN", torture_domainopen, 0},
	{"NET-API-LOOKUP", torture_lookup, 0},
	{"NET-API-LOOKUPHOST", torture_lookup_host, 0},
	{"NET-API-LOOKUPPDC", torture_lookup_pdc, 0},
	{"NET-API-CREATEUSER", torture_createuser, 0},
	{"NET-API-RPCCONNECT", torture_rpc_connect, 0},
	{"NET-API-LISTSHARES", torture_listshares, 0},
	{"NET-API-DELSHARE", torture_delshare, 0},

	{NULL, NULL, 0}};

static void register_builtin_ops(void)
{
	int i;
	for (i = 0; builtin_torture_ops[i].name; i++) {
		register_torture_op(builtin_torture_ops[i].name, 
							builtin_torture_ops[i].fn, 
							builtin_torture_ops[i].multi_fn);
	}
}


static struct torture_op {
	const char *name;
	BOOL (*fn)(void);
	BOOL (*multi_fn)(struct smbcli_state *, int );
	struct torture_op *prev, *next;
}* torture_ops = NULL;;

static struct torture_op *find_torture_op(const char *name)
{
	struct torture_op *o;
	for (o = torture_ops; o; o = o->next) {
		if (strcmp(name, o->name) == 0)
			return o;
	}

	return NULL;
}

_PUBLIC_ NTSTATUS register_torture_op(const char *name, BOOL (*fn)(void), BOOL (*multi_fn)(struct smbcli_state *, int ))
{
	struct torture_op *op;
	
	/* Check for duplicates */
	if (find_torture_op(name) != NULL) {
		DEBUG(0,("There already is a torture op registered with the name %s!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	op = talloc(talloc_autofree_context(), struct torture_op);

	op->name = talloc_strdup(op, name);
	op->fn = fn;
	op->multi_fn = multi_fn;

	DLIST_ADD(torture_ops, op);
	
	return NT_STATUS_OK;
}

/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
static BOOL run_test(const char *name)
{
	BOOL ret = True;
	struct torture_op *o;
	BOOL matched = False;

	if (strequal(name,"ALL")) {
		for (o = torture_ops; o; o = o->next) {
			if (!run_test(o->name)) {
				ret = False;
			}
		}
		return ret;
	}

	for (o = torture_ops; o; o = o->next) {
		if (gen_fnmatch(name, o->name) == 0) {
			double t;
			matched = True;
			init_iconv();
			printf("Running %s\n", o->name);
			if (o->multi_fn) {
				BOOL result = False;
				t = torture_create_procs(o->multi_fn, 
							 &result);
				if (!result) { 
					ret = False;
					printf("TEST %s FAILED!\n", o->name);
				}
					 
			} else {
				struct timeval tv = timeval_current();
				if (!o->fn()) {
					ret = False;
					printf("TEST %s FAILED!\n", o->name);
				}
				t = timeval_elapsed(&tv);
			}
			printf("%s took %g secs\n\n", o->name, t);
		}
	}

	if (!matched) {
		printf("Unknown torture operation '%s'\n", name);
	}

	return ret;
}


static void parse_dns(const char *dns)
{
	char *userdn, *basedn, *secret;
	char *p, *d;

	/* retrievieng the userdn */
	p = strchr_m(dns, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_userdn", "");
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	userdn = strndup(dns, p - dns);
	lp_set_cmdline("torture:ldap_userdn", userdn);

	/* retrieve the basedn */
	d = p + 1;
	p = strchr_m(d, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	basedn = strndup(d, p - d);
	lp_set_cmdline("torture:ldap_basedn", basedn);

	/* retrieve the secret */
	p = p + 1;
	if (!p) {
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	secret = strdup(p);
	lp_set_cmdline("torture:ldap_secret", secret);

	printf ("%s - %s - %s\n", userdn, basedn, secret);

}

static void usage(poptContext pc)
{
	struct torture_op *o;
	int i;

	poptPrintUsage(pc, stdout, 0);
	printf("\n");

	printf("The binding format is:\n\n");

	printf("  TRANSPORT:host[flags]\n\n");

	printf("  where TRANSPORT is either ncacn_np for SMB or ncacn_ip_tcp for RPC/TCP\n\n");

	printf("  'host' is an IP or hostname or netbios name. If the binding string\n");
	printf("  identifies the server side of an endpoint, 'host' may be an empty\n");
	printf("  string.\n\n");

	printf("  'flags' can include a SMB pipe name if using the ncacn_np transport or\n");
	printf("  a TCP port number if using the ncacn_ip_tcp transport, otherwise they\n");
	printf("  will be auto-determined.\n\n");

	printf("  other recognised flags are:\n\n");

	printf("    sign : enable ntlmssp signing\n");
	printf("    seal : enable ntlmssp sealing\n");
	printf("    connect : enable rpc connect level auth (auth, but no sign or seal)\n");
	printf("    validate: enable the NDR validator\n");
	printf("    print: enable debugging of the packets\n");
	printf("    bigendian: use bigendian RPC\n");
	printf("    padcheck: check reply data for non-zero pad bytes\n\n");

	printf("  For example, these all connect to the samr pipe:\n\n");

	printf("    ncacn_np:myserver\n");
	printf("    ncacn_np:myserver[samr]\n");
	printf("    ncacn_np:myserver[\\pipe\\samr]\n");
	printf("    ncacn_np:myserver[/pipe/samr]\n");
	printf("    ncacn_np:myserver[samr,sign,print]\n");
	printf("    ncacn_np:myserver[\\pipe\\samr,sign,seal,bigendian]\n");
	printf("    ncacn_np:myserver[/pipe/samr,seal,validate]\n");
	printf("    ncacn_np:\n");
	printf("    ncacn_np:[/pipe/samr]\n\n");

	printf("    ncacn_ip_tcp:myserver\n");
	printf("    ncacn_ip_tcp:myserver[1024]\n");
	printf("    ncacn_ip_tcp:myserver[1024,sign,seal]\n\n");

	printf("The unc format is:\n\n");

	printf("    //server/share\n\n");

	printf("tests are:\n");

	i = 0;
	for (o = torture_ops; o; o = o->next) {
		if (i + strlen(o->name) >= MAX_COLS) {
			printf("\n");
			i = 0;
		}
		i+=printf("%s ", o->name);
	}
	printf("\n\n");

	printf("default test is ALL\n");

	exit(1);
}

static BOOL is_binding_string(const char *binding_string)
{
	TALLOC_CTX *mem_ctx = talloc_init("is_binding_string");
	struct dcerpc_binding *binding_struct;
	NTSTATUS status;
	
	status = dcerpc_parse_binding(mem_ctx, binding_string, &binding_struct);

	talloc_free(mem_ctx);
	return NT_STATUS_IS_OK(status);
}

static void max_runtime_handler(int sig)
{
	DEBUG(0,("maximum runtime exceeded for smbtorture - terminating\n"));
	exit(1);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	int opt, i;
	char *p;
	BOOL correct = True;
	int max_runtime=0;
	int argc_new;
	char **argv_new;
	poptContext pc;
	enum {OPT_LOADFILE=1000,OPT_UNCLIST,OPT_TIMELIMIT,OPT_DNS,
	    OPT_DANGEROUS,OPT_SMB_PORTS};
	init_module_fn static_init[] = STATIC_smbtorture_MODULES;
	init_module_fn *shared_init = load_samba_modules(NULL, "torture");
	
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"smb-ports",	'p', POPT_ARG_STRING, NULL,     OPT_SMB_PORTS,	"SMB ports", 	NULL},
		{"seed",	  0, POPT_ARG_INT,  &torture_seed, 	0,	"seed", 	NULL},
		{"num-progs",	  0, POPT_ARG_INT,  &torture_nprocs, 	0,	"num progs",	NULL},
		{"num-ops",	  0, POPT_ARG_INT,  &torture_numops, 	0, 	"num ops",	NULL},
		{"entries",	  0, POPT_ARG_INT,  &torture_entries, 	0,	"entries",	NULL},
		{"use-oplocks",	'L', POPT_ARG_NONE, &use_oplocks, 	0,	"use oplocks", 	NULL},
		{"show-all",	  0, POPT_ARG_NONE, &torture_showall, 	0,	"show all", 	NULL},
		{"loadfile",	  0, POPT_ARG_STRING,	NULL, 	OPT_LOADFILE,	"loadfile", 	NULL},
		{"unclist",	  0, POPT_ARG_STRING,	NULL, 	OPT_UNCLIST,	"unclist", 	NULL},
		{"timelimit",	't', POPT_ARG_STRING,	NULL, 	OPT_TIMELIMIT,	"timelimit", 	NULL},
		{"failures",	'f', POPT_ARG_INT,  &torture_failures, 	0,	"failures", 	NULL},
		{"parse-dns",	'D', POPT_ARG_STRING,	NULL, 	OPT_DNS,	"parse-dns", 	NULL},
		{"dangerous",	'X', POPT_ARG_NONE,	NULL,   OPT_DANGEROUS,	"dangerous", 	NULL},
		{"maximum-runtime", 0, POPT_ARG_INT, &max_runtime, 0, 
		 "set maximum time for smbtorture to live", "seconds"},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

#ifdef HAVE_SETBUFFER
	setbuffer(stdout, NULL, 0);
#endif

	register_builtin_ops();

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

	pc = poptGetContext("smbtorture", argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	poptSetOtherOptionHelp(pc, "<binding>|<unc> TEST1 TEST2 ...");

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_LOADFILE:
			lp_set_cmdline("torture:loadfile", poptGetOptArg(pc));
			break;
		case OPT_UNCLIST:
			lp_set_cmdline("torture:unclist", poptGetOptArg(pc));
			break;
		case OPT_TIMELIMIT:
			lp_set_cmdline("torture:timelimit", poptGetOptArg(pc));
			break;
		case OPT_DNS:
			parse_dns(poptGetOptArg(pc));
			break;
		case OPT_DANGEROUS:
			lp_set_cmdline("torture:dangerous", "Yes");
			break;
		case OPT_SMB_PORTS:
			lp_set_cmdline("smb ports", poptGetOptArg(pc));
			break;
		default:
			d_printf("Invalid option %s: %s\n", 
				 poptBadOption(pc, 0), poptStrerror(opt));
			usage(pc);
			exit(1);
		}
	}

	if (max_runtime) {
		/* this will only work if nobody else uses alarm(),
		   which means it won't work for some tests, but we
		   can't use the event context method we use for smbd
		   as so many tests create their own event
		   context. This will at least catch most cases. */
		signal(SIGALRM, max_runtime_handler);
		alarm(max_runtime);
	}

	ldb_global_init();

	if (torture_seed == 0) {
		torture_seed = time(NULL);
	} 
	printf("Using seed %d\n", torture_seed);
	srandom(torture_seed);

	argv_new = discard_const_p(char *, poptGetArgs(pc));

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (argc_new < 3) {
		usage(pc);
		exit(1);
	}

        for(p = argv_new[1]; *p; p++) {
		if(*p == '\\')
			*p = '/';
	}

	/* see if its a RPC transport specifier */
	if (is_binding_string(argv_new[1])) {
		lp_set_cmdline("torture:binding", argv_new[1]);
	} else {
		char *binding = NULL;
		char *host = NULL, *share = NULL;

		if (!smbcli_parse_unc(argv_new[1], NULL, &host, &share)) {
			d_printf("Invalid option: %s is not a valid torture target (share or binding string)\n\n", argv_new[1]);
			usage(pc);
		}

		lp_set_cmdline("torture:host", host);
		lp_set_cmdline("torture:share", share);
		asprintf(&binding, "ncacn_np:%s", host);
		lp_set_cmdline("torture:binding", binding);
	}

	if (argc_new == 0) {
		printf("You must specify a test to run, or 'ALL'\n");
	} else {
		for (i=2;i<argc_new;i++) {
			if (!run_test(argv_new[i])) {
				correct = False;
			}
		}
	}

	if (correct) {
		return(0);
	} else {
		return(1);
	}
}
