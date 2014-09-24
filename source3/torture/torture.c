/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-1998
   Copyright (C) Jeremy Allison 2009

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
#include "system/shmem.h"
#include "wbc_async.h"
#include "torture/proto.h"
#include "libcli/security/security.h"
#include "tldap.h"
#include "tldap_util.h"
#include "../librpc/gen_ndr/svcctl.h"
#include "../lib/util/memcache.h"
#include "nsswitch/winbind_client.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_rbt.h"
#include "talloc_dict.h"
#include "async_smb.h"
#include "libsmb/libsmb.h"
#include "libsmb/clirap.h"
#include "trans2.h"
#include "libsmb/nmblib.h"
#include "../lib/util/tevent_ntstatus.h"
#include "util_tdb.h"
#include "../libcli/smb/read_smb.h"
#include "../libcli/smb/smbXcli_base.h"

extern char *optarg;
extern int optind;

fstring host, workgroup, share, password, username, myname;
static const char *sockops="TCP_NODELAY";
int torture_nprocs=1;
static int port_to_use=0;
int torture_numops=100;
int torture_blocksize=1024*1024;
static int procnum; /* records process count number when forking */
static struct cli_state *current_cli;
static fstring randomfname;
static bool use_oplocks;
static bool use_level_II_oplocks;
static const char *client_txt = "client_oplocks.txt";
static bool disable_spnego;
static bool use_kerberos;
static bool force_dos_errors;
static fstring multishare_conn_fname;
static bool use_multishare_conn = False;
static bool do_encrypt;
static const char *local_path = NULL;
static enum smb_signing_setting signing_state = SMB_SIGNING_DEFAULT;
char *test_filename;

bool torture_showall = False;

static double create_procs(bool (*fn)(int), bool *result);

/********************************************************************
 Ensure a connection is encrypted.
********************************************************************/

static bool force_cli_encryption(struct cli_state *c,
			const char *sharename)
{
	uint16 major, minor;
	uint32 caplow, caphigh;
	NTSTATUS status;

	if (!SERVER_HAS_UNIX_CIFS(c)) {
		d_printf("Encryption required and "
			"server that doesn't support "
			"UNIX extensions - failing connect\n");
			return false;
	}

	status = cli_unix_extensions_version(c, &major, &minor, &caplow,
					     &caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Encryption required and "
			"can't get UNIX CIFS extensions "
			"version from server: %s\n", nt_errstr(status));
		return false;
	}

	if (!(caplow & CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP)) {
		d_printf("Encryption required and "
			"share %s doesn't support "
			"encryption.\n", sharename);
		return false;
	}

	if (c->use_kerberos) {
		status = cli_gss_smb_encryption_start(c);
	} else {
		status = cli_raw_ntlm_smb_encryption_start(c,
						username,
						password,
						workgroup);
	}

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Encryption required and "
			"setup failed with error %s.\n",
			nt_errstr(status));
		return false;
	}

	return true;
}


static struct cli_state *open_nbt_connection(void)
{
	struct cli_state *c;
	NTSTATUS status;
	int flags = 0;

	if (disable_spnego) {
		flags |= CLI_FULL_CONNECTION_DONT_SPNEGO;
	}

	if (use_oplocks) {
		flags |= CLI_FULL_CONNECTION_OPLOCKS;
	}

	if (use_level_II_oplocks) {
		flags |= CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS;
	}

	if (use_kerberos) {
		flags |= CLI_FULL_CONNECTION_USE_KERBEROS;
	}

	if (force_dos_errors) {
		flags |= CLI_FULL_CONNECTION_FORCE_DOS_ERRORS;
	}

	status = cli_connect_nb(host, NULL, port_to_use, 0x20, myname,
				signing_state, flags, &c);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with %s. Error %s\n", host, nt_errstr(status) );
		return NULL;
	}

	cli_set_timeout(c, 120000); /* set a really long timeout (2 minutes) */

	return c;
}

/****************************************************************************
 Send a corrupt session request. See rfc1002.txt 4.3 and 4.3.2.
****************************************************************************/

static bool cli_bad_session_request(int fd,
                         struct nmb_name *calling, struct nmb_name *called)
{
	TALLOC_CTX *frame;
	uint8_t len_buf[4];
	struct iovec iov[3];
	ssize_t len;
	uint8_t *inbuf;
	int err;
	bool ret = false;
	uint8_t message_type;
	uint8_t error;
	struct tevent_context *ev;
	struct tevent_req *req;

	frame = talloc_stackframe();

	iov[0].iov_base = len_buf;
	iov[0].iov_len  = sizeof(len_buf);

	/* put in the destination name */

	iov[1].iov_base = name_mangle(talloc_tos(), called->name,
				      called->name_type);
	if (iov[1].iov_base == NULL) {
		goto fail;
	}
	iov[1].iov_len = name_len((unsigned char *)iov[1].iov_base,
				  talloc_get_size(iov[1].iov_base));

	/* and my name */

	iov[2].iov_base = name_mangle(talloc_tos(), calling->name,
				      calling->name_type);
	if (iov[2].iov_base == NULL) {
		goto fail;
	}
	iov[2].iov_len = name_len((unsigned char *)iov[2].iov_base,
				  talloc_get_size(iov[2].iov_base));

	/* Deliberately corrupt the name len (first byte) */
	*((uint8_t *)iov[2].iov_base) = 100;

	/* send a session request (RFC 1002) */
	/* setup the packet length
         * Remove four bytes from the length count, since the length
         * field in the NBT Session Service header counts the number
         * of bytes which follow.  The cli_send_smb() function knows
         * about this and accounts for those four bytes.
         * CRH.
         */

	_smb_setlen(len_buf, iov[1].iov_len + iov[2].iov_len);
	SCVAL(len_buf,0,0x81);

	len = write_data_iov(fd, iov, 3);
	if (len == -1) {
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = read_smb_send(frame, ev, fd);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		goto fail;
	}
	len = read_smb_recv(req, talloc_tos(), &inbuf, &err);
	if (len == -1) {
		errno = err;
		goto fail;
	}
	TALLOC_FREE(ev);

	message_type = CVAL(inbuf, 0);
	if (message_type != 0x83) {
		d_fprintf(stderr, "Expected msg type 0x83, got 0x%2.2x\n",
			  message_type);
		goto fail;
        }

	if (smb_len(inbuf) != 1) {
		d_fprintf(stderr, "Expected smb_len 1, got %d\n",
			  (int)smb_len(inbuf));
		goto fail;
        }

	error = CVAL(inbuf, 4);
	if (error !=  0x82) {
		d_fprintf(stderr, "Expected error 0x82, got %d\n",
			  (int)error);
		goto fail;
        }

	ret = true;
fail:
	TALLOC_FREE(frame);
        return ret;
}

/* Insert a NULL at the first separator of the given path and return a pointer
 * to the remainder of the string.
 */
static char *
terminate_path_at_separator(char * path)
{
	char * p;

	if (!path) {
		return NULL;
	}

	if ((p = strchr_m(path, '/'))) {
		*p = '\0';
		return p + 1;
	}

	if ((p = strchr_m(path, '\\'))) {
		*p = '\0';
		return p + 1;
	}

	/* No separator. */
	return NULL;
}

/*
  parse a //server/share type UNC name
*/
bool smbcli_parse_unc(const char *unc_name, TALLOC_CTX *mem_ctx,
		      char **hostname, char **sharename)
{
	char *p;

	*hostname = *sharename = NULL;

	if (strncmp(unc_name, "\\\\", 2) &&
	    strncmp(unc_name, "//", 2)) {
		return False;
	}

	*hostname = talloc_strdup(mem_ctx, &unc_name[2]);
	p = terminate_path_at_separator(*hostname);

	if (p && *p) {
		*sharename = talloc_strdup(mem_ctx, p);
		terminate_path_at_separator(*sharename);
	}

	if (*hostname && *sharename) {
		return True;
	}

	TALLOC_FREE(*hostname);
	TALLOC_FREE(*sharename);
	return False;
}

static bool torture_open_connection_share(struct cli_state **c,
				   const char *hostname, 
				   const char *sharename)
{
	int flags = 0;
	NTSTATUS status;

	if (use_kerberos)
		flags |= CLI_FULL_CONNECTION_USE_KERBEROS;
	if (use_oplocks)
		flags |= CLI_FULL_CONNECTION_OPLOCKS;
	if (use_level_II_oplocks)
		flags |= CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS;

	status = cli_full_connection(c, myname,
				     hostname, NULL, port_to_use, 
				     sharename, "?????", 
				     username, workgroup, 
				     password, flags, signing_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed to open share connection: //%s/%s port:%d - %s\n",
			hostname, sharename, port_to_use, nt_errstr(status));
		return False;
	}

	cli_set_timeout(*c, 120000); /* set a really long timeout (2 minutes) */

	if (do_encrypt) {
		return force_cli_encryption(*c,
					sharename);
	}
	return True;
}

bool torture_open_connection(struct cli_state **c, int conn_index)
{
	char **unc_list = NULL;
	int num_unc_names = 0;
	bool result;

	if (use_multishare_conn==True) {
		char *h, *s;
		unc_list = file_lines_load(multishare_conn_fname, &num_unc_names, 0, NULL);
		if (!unc_list || num_unc_names <= 0) {
			printf("Failed to load unc names list from '%s'\n", multishare_conn_fname);
			exit(1);
		}

		if (!smbcli_parse_unc(unc_list[conn_index % num_unc_names],
				      NULL, &h, &s)) {
			printf("Failed to parse UNC name %s\n",
			       unc_list[conn_index % num_unc_names]);
			TALLOC_FREE(unc_list);
			exit(1);
		}

		result = torture_open_connection_share(c, h, s);

		/* h, s were copied earlier */
		TALLOC_FREE(unc_list);
		return result;
	}

	return torture_open_connection_share(c, host, share);
}

bool torture_init_connection(struct cli_state **pcli)
{
	struct cli_state *cli;

	cli = open_nbt_connection();
	if (cli == NULL) {
		return false;
	}

	*pcli = cli;
	return true;
}

bool torture_cli_session_setup2(struct cli_state *cli, uint16 *new_vuid)
{
	uint16_t old_vuid = cli_state_get_uid(cli);
	fstring old_user_name;
	size_t passlen = strlen(password);
	NTSTATUS status;
	bool ret;

	fstrcpy(old_user_name, cli->user_name);
	cli_state_set_uid(cli, 0);
	ret = NT_STATUS_IS_OK(cli_session_setup(cli, username,
						password, passlen,
						password, passlen,
						workgroup));
	*new_vuid = cli_state_get_uid(cli);
	cli_state_set_uid(cli, old_vuid);
	status = cli_set_username(cli, old_user_name);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	return ret;
}


bool torture_close_connection(struct cli_state *c)
{
	bool ret = True;
	NTSTATUS status;

	status = cli_tdis(c);
	if (!NT_STATUS_IS_OK(status)) {
		printf("tdis failed (%s)\n", nt_errstr(status));
		ret = False;
	}

        cli_shutdown(c);

	return ret;
}


/* check if the server produced the expected dos or nt error code */
static bool check_both_error(int line, NTSTATUS status,
			     uint8 eclass, uint32 ecode, NTSTATUS nterr)
{
	if (NT_STATUS_IS_DOS(status)) {
		uint8 cclass;
		uint32 num;

		/* Check DOS error */
		cclass = NT_STATUS_DOS_CLASS(status);
		num = NT_STATUS_DOS_CODE(status);

		if (eclass != cclass || ecode != num) {
			printf("unexpected error code class=%d code=%d\n",
			       (int)cclass, (int)num);
			printf(" expected %d/%d %s (line=%d)\n",
			       (int)eclass, (int)ecode, nt_errstr(nterr), line);
			return false;
		}
	} else {
		/* Check NT error */
		if (!NT_STATUS_EQUAL(nterr, status)) {
			printf("unexpected error code %s\n",
				nt_errstr(status));
			printf(" expected %s (line=%d)\n",
				nt_errstr(nterr), line);
			return false;
		}
	}

	return true;
}


/* check if the server produced the expected error code */
static bool check_error(int line, NTSTATUS status,
			uint8 eclass, uint32 ecode, NTSTATUS nterr)
{
	if (NT_STATUS_IS_DOS(status)) {
                uint8 cclass;
                uint32 num;

                /* Check DOS error */

		cclass = NT_STATUS_DOS_CLASS(status);
		num = NT_STATUS_DOS_CODE(status);

                if (eclass != cclass || ecode != num) {
                        printf("unexpected error code class=%d code=%d\n", 
                               (int)cclass, (int)num);
                        printf(" expected %d/%d %s (line=%d)\n", 
                               (int)eclass, (int)ecode, nt_errstr(nterr),
			       line);
                        return False;
                }

        } else {
                /* Check NT error */

                if (NT_STATUS_V(nterr) != NT_STATUS_V(status)) {
                        printf("unexpected error code %s\n",
			       nt_errstr(status));
                        printf(" expected %s (line=%d)\n", nt_errstr(nterr),
			       line);
                        return False;
                }
        }

	return True;
}


static bool wait_lock(struct cli_state *c, int fnum, uint32 offset, uint32 len)
{
	NTSTATUS status;

	status = cli_lock32(c, fnum, offset, len, -1, WRITE_LOCK);

	while (!NT_STATUS_IS_OK(status)) {
		if (!check_both_error(__LINE__, status, ERRDOS,
				      ERRlock, NT_STATUS_LOCK_NOT_GRANTED)) {
			return false;
		}

		status = cli_lock32(c, fnum, offset, len, -1, WRITE_LOCK);
	}

	return true;
}


static bool rw_torture(struct cli_state *c)
{
	const char *lockfname = "\\torture.lck";
	fstring fname;
	uint16_t fnum;
	uint16_t fnum2;
	pid_t pid2, pid = getpid();
	int i, j;
	char buf[1024];
	bool correct = True;
	size_t nread = 0;
	NTSTATUS status;

	memset(buf, '\0', sizeof(buf));

	status = cli_openx(c, lockfname, O_RDWR | O_CREAT | O_EXCL, 
			 DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		status = cli_openx(c, lockfname, O_RDWR, DENY_NONE, &fnum2);
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n",
		       lockfname, nt_errstr(status));
		return False;
	}

	for (i=0;i<torture_numops;i++) {
		unsigned n = (unsigned)sys_random()%10;

		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}
		slprintf(fname, sizeof(fstring) - 1, "\\torture.%u", n);

		if (!wait_lock(c, fnum2, n*sizeof(int), sizeof(int))) {
			return False;
		}

		status = cli_openx(c, fname, O_RDWR | O_CREAT | O_TRUNC,
                                  DENY_ALL, &fnum);
		if (!NT_STATUS_IS_OK(status)) {
			printf("open failed (%s)\n", nt_errstr(status));
			correct = False;
			break;
		}

		status = cli_writeall(c, fnum, 0, (uint8_t *)&pid, 0,
				      sizeof(pid), NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("write failed (%s)\n", nt_errstr(status));
			correct = False;
		}

		for (j=0;j<50;j++) {
			status = cli_writeall(c, fnum, 0, (uint8_t *)buf,
					      sizeof(pid)+(j*sizeof(buf)),
					      sizeof(buf), NULL);
			if (!NT_STATUS_IS_OK(status)) {
				printf("write failed (%s)\n",
				       nt_errstr(status));
				correct = False;
			}
		}

		pid2 = 0;

		status = cli_read(c, fnum, (char *)&pid2, 0, sizeof(pid),
				  &nread);
		if (!NT_STATUS_IS_OK(status)) {
			printf("read failed (%s)\n", nt_errstr(status));
			correct = false;
		} else if (nread != sizeof(pid)) {
			printf("read/write compare failed: "
			       "recv %ld req %ld\n", (unsigned long)nread,
			       (unsigned long)sizeof(pid));
			correct = false;
		}

		if (pid2 != pid) {
			printf("data corruption!\n");
			correct = False;
		}

		status = cli_close(c, fnum);
		if (!NT_STATUS_IS_OK(status)) {
			printf("close failed (%s)\n", nt_errstr(status));
			correct = False;
		}

		status = cli_unlink(c, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlink failed (%s)\n", nt_errstr(status));
			correct = False;
		}

		status = cli_unlock(c, fnum2, n*sizeof(int), sizeof(int));
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlock failed (%s)\n", nt_errstr(status));
			correct = False;
		}
	}

	cli_close(c, fnum2);
	cli_unlink(c, lockfname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("%d\n", i);

	return correct;
}

static bool run_torture(int dummy)
{
	struct cli_state *cli;
        bool ret;

	cli = current_cli;

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	ret = rw_torture(cli);

	if (!torture_close_connection(cli)) {
		ret = False;
	}

	return ret;
}

static bool rw_torture3(struct cli_state *c, char *lockfname)
{
	uint16_t fnum = (uint16_t)-1;
	unsigned int i = 0;
	char buf[131072];
	char buf_rd[131072];
	unsigned count;
	unsigned countprev = 0;
	size_t sent = 0;
	bool correct = True;
	NTSTATUS status = NT_STATUS_OK;

	srandom(1);
	for (i = 0; i < sizeof(buf); i += sizeof(uint32))
	{
		SIVAL(buf, i, sys_random());
	}

	if (procnum == 0)
	{
		status = cli_unlink(
			c, lockfname,
			FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlink failed (%s) (normal, this file should "
			       "not exist)\n", nt_errstr(status));
		}

		status = cli_openx(c, lockfname, O_RDWR | O_CREAT | O_EXCL,
		                  DENY_NONE, &fnum);
		if (!NT_STATUS_IS_OK(status)) {
			printf("first open read/write of %s failed (%s)\n",
					lockfname, nt_errstr(status));
			return False;
		}
	}
	else
	{
		for (i = 0; i < 500 && fnum == (uint16_t)-1; i++)
		{
			status = cli_openx(c, lockfname, O_RDONLY, 
					 DENY_NONE, &fnum);
			if (NT_STATUS_IS_OK(status)) {
				break;
			}
			smb_msleep(10);
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("second open read-only of %s failed (%s)\n",
					lockfname, nt_errstr(status));
			return False;
		}
	}

	i = 0;
	for (count = 0; count < sizeof(buf); count += sent)
	{
		if (count >= countprev) {
			printf("%d %8d\r", i, count);
			fflush(stdout);
			i++;
			countprev += (sizeof(buf) / 20);
		}

		if (procnum == 0)
		{
			sent = ((unsigned)sys_random()%(20))+ 1;
			if (sent > sizeof(buf) - count)
			{
				sent = sizeof(buf) - count;
			}

			status = cli_writeall(c, fnum, 0, (uint8_t *)buf+count,
					      count, sent, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				printf("write failed (%s)\n",
				       nt_errstr(status));
				correct = False;
			}
		}
		else
		{
			status = cli_read(c, fnum, buf_rd+count, count,
					  sizeof(buf)-count, &sent);
			if(!NT_STATUS_IS_OK(status)) {
				printf("read failed offset:%d size:%ld (%s)\n",
				       count, (unsigned long)sizeof(buf)-count,
				       nt_errstr(status));
				correct = False;
				sent = 0;
			} else if (sent > 0) {
				if (memcmp(buf_rd+count, buf+count, sent) != 0)
				{
					printf("read/write compare failed\n");
					printf("offset: %d req %ld recvd %ld\n", count, (unsigned long)sizeof(buf)-count, (unsigned long)sent);
					correct = False;
					break;
				}
			}
		}

	}

	status = cli_close(c, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	return correct;
}

static bool rw_torture2(struct cli_state *c1, struct cli_state *c2)
{
	const char *lockfname = "\\torture2.lck";
	uint16_t fnum1;
	uint16_t fnum2;
	int i;
	char buf[131072];
	char buf_rd[131072];
	bool correct = True;
	size_t bytes_read;
	NTSTATUS status;

	status = cli_unlink(c1, lockfname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s) (normal, this file should not exist)\n", nt_errstr(status));
	}

	status = cli_openx(c1, lockfname, O_RDWR | O_CREAT | O_EXCL,
	                  DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("first open read/write of %s failed (%s)\n",
				lockfname, nt_errstr(status));
		return False;
	}

	status = cli_openx(c2, lockfname, O_RDONLY, DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("second open read-only of %s failed (%s)\n",
				lockfname, nt_errstr(status));
		cli_close(c1, fnum1);
		return False;
	}

	for (i = 0; i < torture_numops; i++)
	{
		size_t buf_size = ((unsigned)sys_random()%(sizeof(buf)-1))+ 1;
		if (i % 10 == 0) {
			printf("%d\r", i); fflush(stdout);
		}

		generate_random_buffer((unsigned char *)buf, buf_size);

		status = cli_writeall(c1, fnum1, 0, (uint8_t *)buf, 0,
				      buf_size, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("write failed (%s)\n", nt_errstr(status));
			correct = False;
			break;
		}

		status = cli_read(c2, fnum2, buf_rd, 0, buf_size, &bytes_read);
		if(!NT_STATUS_IS_OK(status)) {
			printf("read failed (%s)\n", nt_errstr(status));
			correct = false;
			break;
		} else if (bytes_read != buf_size) {
			printf("read failed\n");
			printf("read %ld, expected %ld\n",
			       (unsigned long)bytes_read,
			       (unsigned long)buf_size); 
			correct = False;
			break;
		}

		if (memcmp(buf_rd, buf, buf_size) != 0)
		{
			printf("read/write compare failed\n");
			correct = False;
			break;
		}
	}

	status = cli_close(c2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_close(c1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_unlink(c1, lockfname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	return correct;
}

static bool run_readwritetest(int dummy)
{
	struct cli_state *cli1, *cli2;
	bool test1, test2 = False;

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting readwritetest\n");

	test1 = rw_torture2(cli1, cli2);
	printf("Passed readwritetest v1: %s\n", BOOLSTR(test1));

	if (test1) {
		test2 = rw_torture2(cli1, cli1);
		printf("Passed readwritetest v2: %s\n", BOOLSTR(test2));
	}

	if (!torture_close_connection(cli1)) {
		test1 = False;
	}

	if (!torture_close_connection(cli2)) {
		test2 = False;
	}

	return (test1 && test2);
}

static bool run_readwritemulti(int dummy)
{
	struct cli_state *cli;
	bool test;

	cli = current_cli;

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("run_readwritemulti: fname %s\n", randomfname);
	test = rw_torture3(cli, randomfname);

	if (!torture_close_connection(cli)) {
		test = False;
	}

	return test;
}

static bool run_readwritelarge_internal(void)
{
	static struct cli_state *cli1;
	uint16_t fnum1;
	const char *lockfname = "\\large.dat";
	off_t fsize;
	char buf[126*1024];
	bool correct = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	memset(buf,'\0',sizeof(buf));

	printf("starting readwritelarge_internal\n");

	cli_unlink(cli1, lockfname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, lockfname, O_RDWR | O_CREAT | O_EXCL,
	                  DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open read/write of %s failed (%s)\n", lockfname, nt_errstr(status));
		return False;
	}

	cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 0, sizeof(buf), NULL);

	status = cli_qfileinfo_basic(cli1, fnum1, NULL, &fsize, NULL, NULL,
				     NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("qfileinfo failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (fsize == sizeof(buf))
		printf("readwritelarge_internal test 1 succeeded (size = %lx)\n",
		       (unsigned long)fsize);
	else {
		printf("readwritelarge_internal test 1 failed (size = %lx)\n",
		       (unsigned long)fsize);
		correct = False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_unlink(cli1, lockfname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_openx(cli1, lockfname, O_RDWR | O_CREAT | O_EXCL,
	                  DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open read/write of %s failed (%s)\n", lockfname, nt_errstr(status));
		return False;
	}

	cli_smbwrite(cli1, fnum1, buf, 0, sizeof(buf), NULL);

	status = cli_qfileinfo_basic(cli1, fnum1, NULL, &fsize, NULL, NULL,
				     NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("qfileinfo failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (fsize == sizeof(buf))
		printf("readwritelarge_internal test 2 succeeded (size = %lx)\n",
		       (unsigned long)fsize);
	else {
		printf("readwritelarge_internal test 2 failed (size = %lx)\n",
		       (unsigned long)fsize);
		correct = False;
	}

#if 0
	/* ToDo - set allocation. JRA */
	if(!cli_set_allocation_size(cli1, fnum1, 0)) {
		printf("set allocation size to zero failed (%s)\n", cli_errstr(&cli1));
		return False;
	}
	if (!cli_qfileinfo_basic(cli1, fnum1, NULL, &fsize, NULL, NULL, NULL,
				 NULL, NULL)) {
		printf("qfileinfo failed (%s)\n", cli_errstr(cli1));
		correct = False;
	}
	if (fsize != 0)
		printf("readwritelarge test 3 (truncate test) succeeded (size = %x)\n", fsize);
#endif

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	return correct;
}

static bool run_readwritelarge(int dummy)
{
	return run_readwritelarge_internal();
}

static bool run_readwritelarge_signtest(int dummy)
{
	bool ret;
	signing_state = SMB_SIGNING_REQUIRED;
	ret = run_readwritelarge_internal();
	signing_state = SMB_SIGNING_DEFAULT;
	return ret;
}

int line_count = 0;
int nbio_id;

#define ival(s) strtol(s, NULL, 0)

/* run a test that simulates an approximate netbench client load */
static bool run_netbench(int client)
{
	struct cli_state *cli;
	int i;
	char line[1024];
	char cname[20];
	FILE *f;
	const char *params[20];
	bool correct = True;

	cli = current_cli;

	nbio_id = client;

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	nb_setup(cli);

	slprintf(cname,sizeof(cname)-1, "client%d", client);

	f = fopen(client_txt, "r");

	if (!f) {
		perror(client_txt);
		return False;
	}

	while (fgets(line, sizeof(line)-1, f)) {
		char *saveptr;
		line_count++;

		line[strlen(line)-1] = 0;

		/* printf("[%d] %s\n", line_count, line); */

		all_string_sub(line,"client1", cname, sizeof(line));

		/* parse the command parameters */
		params[0] = strtok_r(line, " ", &saveptr);
		i = 0;
		while (params[i]) params[++i] = strtok_r(NULL, " ", &saveptr);

		params[i] = "";

		if (i < 2) continue;

		if (!strncmp(params[0],"SMB", 3)) {
			printf("ERROR: You are using a dbench 1 load file\n");
			exit(1);
		}

		if (!strcmp(params[0],"NTCreateX")) {
			nb_createx(params[1], ival(params[2]), ival(params[3]), 
				   ival(params[4]));
		} else if (!strcmp(params[0],"Close")) {
			nb_close(ival(params[1]));
		} else if (!strcmp(params[0],"Rename")) {
			nb_rename(params[1], params[2]);
		} else if (!strcmp(params[0],"Unlink")) {
			nb_unlink(params[1]);
		} else if (!strcmp(params[0],"Deltree")) {
			nb_deltree(params[1]);
		} else if (!strcmp(params[0],"Rmdir")) {
			nb_rmdir(params[1]);
		} else if (!strcmp(params[0],"QUERY_PATH_INFORMATION")) {
			nb_qpathinfo(params[1]);
		} else if (!strcmp(params[0],"QUERY_FILE_INFORMATION")) {
			nb_qfileinfo(ival(params[1]));
		} else if (!strcmp(params[0],"QUERY_FS_INFORMATION")) {
			nb_qfsinfo(ival(params[1]));
		} else if (!strcmp(params[0],"FIND_FIRST")) {
			nb_findfirst(params[1]);
		} else if (!strcmp(params[0],"WriteX")) {
			nb_writex(ival(params[1]), 
				  ival(params[2]), ival(params[3]), ival(params[4]));
		} else if (!strcmp(params[0],"ReadX")) {
			nb_readx(ival(params[1]), 
				  ival(params[2]), ival(params[3]), ival(params[4]));
		} else if (!strcmp(params[0],"Flush")) {
			nb_flush(ival(params[1]));
		} else {
			printf("Unknown operation %s\n", params[0]);
			exit(1);
		}
	}
	fclose(f);

	nb_cleanup();

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	return correct;
}


/* run a test that simulates an approximate netbench client load */
static bool run_nbench(int dummy)
{
	double t;
	bool correct = True;

	nbio_shmem(torture_nprocs);

	nbio_id = -1;

	signal(SIGALRM, nb_alarm);
	alarm(1);
	t = create_procs(run_netbench, &correct);
	alarm(0);

	printf("\nThroughput %g MB/sec\n", 
	       1.0e-6 * nbio_total() / t);
	return correct;
}


/*
  This test checks for two things:

  1) correct support for retaining locks over a close (ie. the server
     must not use posix semantics)
  2) support for lock timeouts
 */
static bool run_locktest1(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "\\lockt1.lck";
	uint16_t fnum1, fnum2, fnum3;
	time_t t1, t2;
	unsigned lock_timeout;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting locktest1\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
	                  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_openx(cli2, fname, O_RDWR, DENY_NONE, &fnum3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open3 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_lock32(cli1, fnum1, 0, 4, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock1 failed (%s)\n", nt_errstr(status));
		return false;
	}

	status = cli_lock32(cli2, fnum3, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("lock2 succeeded! This is a locking bug\n");
		return false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_LOCK_NOT_GRANTED)) {
			return false;
		}
	}

	lock_timeout = (1 + (random() % 20));
	printf("Testing lock timeout with timeout=%u\n", lock_timeout);
	t1 = time(NULL);
	status = cli_lock32(cli2, fnum3, 0, 4, lock_timeout * 1000, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("lock3 succeeded! This is a locking bug\n");
		return false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_FILE_LOCK_CONFLICT)) {
			return false;
		}
	}
	t2 = time(NULL);

	if (ABS(t2 - t1) < lock_timeout-1) {
		printf("error: This server appears not to support timed lock requests\n");
	}

	printf("server slept for %u seconds for a %u second timeout\n",
	       (unsigned int)(t2-t1), lock_timeout);

	status = cli_close(cli1, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_lock32(cli2, fnum3, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("lock4 succeeded! This is a locking bug\n");
		return false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_FILE_LOCK_CONFLICT)) {
			return false;
		}
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close3 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		return False;
	}


	if (!torture_close_connection(cli1)) {
		return False;
	}

	if (!torture_close_connection(cli2)) {
		return False;
	}

	printf("Passed locktest1\n");
	return True;
}

/*
  this checks to see if a secondary tconx can use open files from an
  earlier tconx
 */
static bool run_tcon_test(int dummy)
{
	static struct cli_state *cli;
	const char *fname = "\\tcontest.tmp";
	uint16 fnum1;
	uint16 cnum1, cnum2, cnum3;
	uint16 vuid1, vuid2;
	char buf[4];
	bool ret = True;
	NTSTATUS status;

	memset(buf, '\0', sizeof(buf));

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("starting tcontest\n");

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	cnum1 = cli_state_get_tid(cli);
	vuid1 = cli_state_get_uid(cli);

	status = cli_writeall(cli, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("initial write failed (%s)", nt_errstr(status));
		return False;
	}

	status = cli_tree_connect(cli, share, "?????",
				  password, strlen(password)+1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s refused 2nd tree connect (%s)\n", host,
		       nt_errstr(status));
		cli_shutdown(cli);
		return False;
	}

	cnum2 = cli_state_get_tid(cli);
	cnum3 = MAX(cnum1, cnum2) + 1; /* any invalid number */
	vuid2 = cli_state_get_uid(cli) + 1;

	/* try a write with the wrong tid */
	cli_state_set_tid(cli, cnum2);

	status = cli_writeall(cli, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("* server allows write with wrong TID\n");
		ret = False;
	} else {
		printf("server fails write with wrong TID : %s\n",
		       nt_errstr(status));
	}


	/* try a write with an invalid tid */
	cli_state_set_tid(cli, cnum3);

	status = cli_writeall(cli, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("* server allows write with invalid TID\n");
		ret = False;
	} else {
		printf("server fails write with invalid TID : %s\n",
		       nt_errstr(status));
	}

	/* try a write with an invalid vuid */
	cli_state_set_uid(cli, vuid2);
	cli_state_set_tid(cli, cnum1);

	status = cli_writeall(cli, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("* server allows write with invalid VUID\n");
		ret = False;
	} else {
		printf("server fails write with invalid VUID : %s\n",
		       nt_errstr(status));
	}

	cli_state_set_tid(cli, cnum1);
	cli_state_set_uid(cli, vuid1);

	status = cli_close(cli, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_state_set_tid(cli, cnum2);

	status = cli_tdis(cli);
	if (!NT_STATUS_IS_OK(status)) {
		printf("secondary tdis failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_state_set_tid(cli, cnum1);

	if (!torture_close_connection(cli)) {
		return False;
	}

	return ret;
}


/*
 checks for old style tcon support
 */
static bool run_tcon2_test(int dummy)
{
	static struct cli_state *cli;
	uint16 cnum, max_xmit;
	char *service;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("starting tcon2 test\n");

	if (asprintf(&service, "\\\\%s\\%s", host, share) == -1) {
		return false;
	}

	status = cli_raw_tcon(cli, service, password, "?????", &max_xmit, &cnum);

	SAFE_FREE(service);

	if (!NT_STATUS_IS_OK(status)) {
		printf("tcon2 failed : %s\n", nt_errstr(status));
	} else {
		printf("tcon OK : max_xmit=%d cnum=%d\n",
		       (int)max_xmit, (int)cnum);
	}

	if (!torture_close_connection(cli)) {
		return False;
	}

	printf("Passed tcon2 test\n");
	return True;
}

static bool tcon_devtest(struct cli_state *cli,
			 const char *myshare, const char *devtype,
			 const char *return_devtype,
			 NTSTATUS expected_error)
{
	NTSTATUS status;
	bool ret;

	status = cli_tree_connect(cli, myshare, devtype,
				  password, strlen(password)+1);

	if (NT_STATUS_IS_OK(expected_error)) {
		if (NT_STATUS_IS_OK(status)) {
			if (strcmp(cli->dev, return_devtype) == 0) {
				ret = True;
			} else { 
				printf("tconX to share %s with type %s "
				       "succeeded but returned the wrong "
				       "device type (got [%s] but should have got [%s])\n",
				       myshare, devtype, cli->dev, return_devtype);
				ret = False;
			}
		} else {
			printf("tconX to share %s with type %s "
			       "should have succeeded but failed\n",
			       myshare, devtype);
			ret = False;
		}
		cli_tdis(cli);
	} else {
		if (NT_STATUS_IS_OK(status)) {
			printf("tconx to share %s with type %s "
			       "should have failed but succeeded\n",
			       myshare, devtype);
			ret = False;
		} else {
			if (NT_STATUS_EQUAL(status, expected_error)) {
				ret = True;
			} else {
				printf("Returned unexpected error\n");
				ret = False;
			}
		}
	}
	return ret;
}

/*
 checks for correct tconX support
 */
static bool run_tcon_devtype_test(int dummy)
{
	static struct cli_state *cli1 = NULL;
	int flags = 0;
	NTSTATUS status;
	bool ret = True;

	status = cli_full_connection(&cli1, myname,
				     host, NULL, port_to_use,
				     NULL, NULL,
				     username, workgroup,
				     password, flags, signing_state);

	if (!NT_STATUS_IS_OK(status)) {
		printf("could not open connection\n");
		return False;
	}

	if (!tcon_devtest(cli1, "IPC$", "A:", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "?????", "IPC", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "LPT:", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "IPC", "IPC", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, "IPC$", "FOOBA", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, share, "A:", "A:", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, share, "?????", "A:", NT_STATUS_OK))
		ret = False;

	if (!tcon_devtest(cli1, share, "LPT:", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, share, "IPC", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	if (!tcon_devtest(cli1, share, "FOOBA", NULL, NT_STATUS_BAD_DEVICE_TYPE))
		ret = False;

	cli_shutdown(cli1);

	if (ret)
		printf("Passed tcondevtest\n");

	return ret;
}


/*
  This test checks that 

  1) the server supports multiple locking contexts on the one SMB
  connection, distinguished by PID.  

  2) the server correctly fails overlapping locks made by the same PID (this
     goes against POSIX behaviour, which is why it is tricky to implement)

  3) the server denies unlock requests by an incorrect client PID
*/
static bool run_locktest2(int dummy)
{
	static struct cli_state *cli;
	const char *fname = "\\lockt2.lck";
	uint16_t fnum1, fnum2, fnum3;
	bool correct = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("starting locktest2\n");

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	cli_setpid(cli, 1);

	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_openx(cli, fname, O_RDWR, DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	cli_setpid(cli, 2);

	status = cli_openx(cli, fname, O_RDWR, DENY_NONE, &fnum3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open3 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	cli_setpid(cli, 1);

	status = cli_lock32(cli, fnum1, 0, 4, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock1 failed (%s)\n", nt_errstr(status));
		return false;
	}

	status = cli_lock32(cli, fnum1, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("WRITE lock1 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_LOCK_NOT_GRANTED)) {
			return false;
		}
	}

	status = cli_lock32(cli, fnum2, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("WRITE lock2 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_LOCK_NOT_GRANTED)) {
			return false;
		}
	}

	status = cli_lock32(cli, fnum2, 0, 4, 0, READ_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("READ lock2 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				 NT_STATUS_FILE_LOCK_CONFLICT)) {
			return false;
		}
	}

	status = cli_lock32(cli, fnum1, 100, 4, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock at 100 failed (%s)\n", nt_errstr(status));
	}
	cli_setpid(cli, 2);
	if (NT_STATUS_IS_OK(cli_unlock(cli, fnum1, 100, 4))) {
		printf("unlock at 100 succeeded! This is a locking bug\n");
		correct = False;
	}

	status = cli_unlock(cli, fnum1, 0, 4);
	if (NT_STATUS_IS_OK(status)) {
		printf("unlock1 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_RANGE_NOT_LOCKED)) {
			return false;
		}
	}

	status = cli_unlock(cli, fnum1, 0, 8);
	if (NT_STATUS_IS_OK(status)) {
		printf("unlock2 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_RANGE_NOT_LOCKED)) {
			return false;
		}
	}

	status = cli_lock32(cli, fnum3, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		printf("lock3 succeeded! This is a locking bug\n");
		correct = false;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRlock,
				      NT_STATUS_LOCK_NOT_GRANTED)) {
			return false;
		}
	}

	cli_setpid(cli, 1);

	status = cli_close(cli, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_close(cli, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_close(cli, fnum3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close3 failed (%s)\n", nt_errstr(status));
		return False;
	}

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("locktest2 finished\n");

	return correct;
}


/*
  This test checks that 

  1) the server supports the full offset range in lock requests
*/
static bool run_locktest3(int dummy)
{
	static struct cli_state *cli1, *cli2;
	const char *fname = "\\lockt3.lck";
	uint16_t fnum1, fnum2;
	int i;
	uint32 offset;
	bool correct = True;
	NTSTATUS status;

#define NEXT_OFFSET offset += (~(uint32)0) / torture_numops

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting locktest3\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
	                 &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_openx(cli2, fname, O_RDWR, DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;

		status = cli_lock32(cli1, fnum1, offset-1, 1, 0, WRITE_LOCK);
		if (!NT_STATUS_IS_OK(status)) {
			printf("lock1 %d failed (%s)\n", 
			       i,
			       nt_errstr(status));
			return False;
		}

		status = cli_lock32(cli2, fnum2, offset-2, 1, 0, WRITE_LOCK);
		if (!NT_STATUS_IS_OK(status)) {
			printf("lock2 %d failed (%s)\n", 
			       i,
			       nt_errstr(status));
			return False;
		}
	}

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;

		status = cli_lock32(cli1, fnum1, offset-2, 1, 0, WRITE_LOCK);
		if (NT_STATUS_IS_OK(status)) {
			printf("error: lock1 %d succeeded!\n", i);
			return False;
		}

		status = cli_lock32(cli2, fnum2, offset-1, 1, 0, WRITE_LOCK);
		if (NT_STATUS_IS_OK(status)) {
			printf("error: lock2 %d succeeded!\n", i);
			return False;
		}

		status = cli_lock32(cli1, fnum1, offset-1, 1, 0, WRITE_LOCK);
		if (NT_STATUS_IS_OK(status)) {
			printf("error: lock3 %d succeeded!\n", i);
			return False;
		}

		status = cli_lock32(cli2, fnum2, offset-2, 1, 0, WRITE_LOCK);
		if (NT_STATUS_IS_OK(status)) {
			printf("error: lock4 %d succeeded!\n", i);
			return False;
		}
	}

	for (offset=i=0;i<torture_numops;i++) {
		NEXT_OFFSET;

		status = cli_unlock(cli1, fnum1, offset-1, 1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlock1 %d failed (%s)\n", 
			       i,
			       nt_errstr(status));
			return False;
		}

		status = cli_unlock(cli2, fnum2, offset-2, 1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlock2 %d failed (%s)\n", 
			       i,
			       nt_errstr(status));
			return False;
		}
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		return False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}

	if (!torture_close_connection(cli2)) {
		correct = False;
	}

	printf("finished locktest3\n");

	return correct;
}

static bool test_cli_read(struct cli_state *cli, uint16_t fnum,
                           char *buf, off_t offset, size_t size,
                           size_t *nread, size_t expect)
{
	NTSTATUS status;
	size_t l_nread;

	status = cli_read(cli, fnum, buf, offset, size, &l_nread);

	if(!NT_STATUS_IS_OK(status)) {
		return false;
	} else if (l_nread != expect) {
		return false;
	}

	if (nread) {
		*nread = l_nread;
	}

	return true;
}

#define EXPECTED(ret, v) if ((ret) != (v)) { \
        printf("** "); correct = False; \
        }

/*
  looks at overlapping locks
*/
static bool run_locktest4(int dummy)
{
	static struct cli_state *cli1, *cli2;
	const char *fname = "\\lockt4.lck";
	uint16_t fnum1, fnum2, f;
	bool ret;
	char buf[1000];
	bool correct = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting locktest4\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	cli_openx(cli2, fname, O_RDWR, DENY_NONE, &fnum2);

	memset(buf, 0, sizeof(buf));

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 0, sizeof(buf),
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create file: %s\n", nt_errstr(status));
		correct = False;
		goto fail;
	}

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 2, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s set overlapping write locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 10, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 12, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s set overlapping read locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 20, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli2, fnum2, 22, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("a different connection %s set overlapping write locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 30, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli2, fnum2, 32, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("a different connection %s set overlapping read locks\n", ret?"can":"cannot");

	ret = (cli_setpid(cli1, 1),
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 40, 4, 0, WRITE_LOCK))) &&
	      (cli_setpid(cli1, 2),
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 42, 4, 0, WRITE_LOCK)));
	EXPECTED(ret, False);
	printf("a different pid %s set overlapping write locks\n", ret?"can":"cannot");

	ret = (cli_setpid(cli1, 1),
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 50, 4, 0, READ_LOCK))) &&
	      (cli_setpid(cli1, 2),
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 52, 4, 0, READ_LOCK)));
	EXPECTED(ret, True);
	printf("a different pid %s set overlapping read locks\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 60, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 60, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s set the same read lock twice\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 70, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 70, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s set the same write lock twice\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 80, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 80, 4, 0, WRITE_LOCK));
	EXPECTED(ret, False);
	printf("the same process %s overlay a read lock with a write lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 90, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 90, 4, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = (cli_setpid(cli1, 1),
	     NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 100, 4, 0, WRITE_LOCK))) &&
	     (cli_setpid(cli1, 2),
	     NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 100, 4, 0, READ_LOCK)));
	EXPECTED(ret, False);
	printf("a different pid %s overlay a write lock with a read lock\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 110, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 112, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 110, 6));
	EXPECTED(ret, False);
	printf("the same process %s coalesce read locks\n", ret?"can":"cannot");


	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 120, 4, 0, WRITE_LOCK)) &&
	      test_cli_read(cli2, fnum2, buf, 120, 4, NULL, 4);
	EXPECTED(ret, False);
	printf("this server %s strict write locking\n", ret?"doesn't do":"does");

	status = cli_lock32(cli1, fnum1, 130, 4, 0, READ_LOCK);
	ret = NT_STATUS_IS_OK(status);
	if (ret) {
		status = cli_writeall(cli2, fnum2, 0, (uint8_t *)buf, 130, 4,
				      NULL);
		ret = NT_STATUS_IS_OK(status);
	}
	EXPECTED(ret, False);
	printf("this server %s strict read locking\n", ret?"doesn't do":"does");


	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 140, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 140, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 140, 4)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 140, 4));
	EXPECTED(ret, True);
	printf("this server %s do recursive read locking\n", ret?"does":"doesn't");


	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 150, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 150, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 150, 4)) &&
	      test_cli_read(cli2, fnum2, buf, 150, 4, NULL, 4) &&
	      !(NT_STATUS_IS_OK(cli_writeall(cli2, fnum2, 0, (uint8_t *)buf,
					     150, 4, NULL))) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 150, 4));
	EXPECTED(ret, True);
	printf("this server %s do recursive lock overlays\n", ret?"does":"doesn't");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 160, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 160, 4)) &&
	      NT_STATUS_IS_OK(cli_writeall(cli2, fnum2, 0, (uint8_t *)buf,
					   160, 4, NULL)) &&
	      test_cli_read(cli2, fnum2, buf, 160, 4, NULL, 4);
	EXPECTED(ret, True);
	printf("the same process %s remove a read lock using write locking\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 170, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 170, 4)) &&
	      NT_STATUS_IS_OK(cli_writeall(cli2, fnum2, 0, (uint8_t *)buf,
					   170, 4, NULL)) &&
	      test_cli_read(cli2, fnum2, buf, 170, 4, NULL, 4);
	EXPECTED(ret, True);
	printf("the same process %s remove a write lock using read locking\n", ret?"can":"cannot");

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 190, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 190, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 190, 4)) &&
	      !NT_STATUS_IS_OK(cli_writeall(cli2, fnum2, 0, (uint8_t *)buf,
					    190, 4, NULL)) &&
	      test_cli_read(cli2, fnum2, buf, 190, 4, NULL, 4);
	EXPECTED(ret, True);
	printf("the same process %s remove the first lock first\n", ret?"does":"doesn't");

	cli_close(cli1, fnum1);
	cli_close(cli2, fnum2);
	cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	cli_openx(cli1, fname, O_RDWR, DENY_NONE, &f);
	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 8, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, f, 0, 1, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_close(cli1, fnum1)) &&
	      NT_STATUS_IS_OK(cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 7, 1, 0, WRITE_LOCK));
        cli_close(cli1, f);
	cli_close(cli1, fnum1);
	EXPECTED(ret, True);
	printf("the server %s have the NT byte range lock bug\n", !ret?"does":"doesn't");

 fail:
	cli_close(cli1, fnum1);
	cli_close(cli2, fnum2);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	torture_close_connection(cli1);
	torture_close_connection(cli2);

	printf("finished locktest4\n");
	return correct;
}

/*
  looks at lock upgrade/downgrade.
*/
static bool run_locktest5(int dummy)
{
	static struct cli_state *cli1, *cli2;
	const char *fname = "\\lockt5.lck";
	uint16_t fnum1, fnum2, fnum3;
	bool ret;
	char buf[1000];
	bool correct = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting locktest5\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	cli_openx(cli2, fname, O_RDWR, DENY_NONE, &fnum2);
	cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum3);

	memset(buf, 0, sizeof(buf));

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 0, sizeof(buf),
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create file: %s\n", nt_errstr(status));
		correct = False;
		goto fail;
	}

	/* Check for NT bug... */
	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 8, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum3, 0, 1, 0, READ_LOCK));
	cli_close(cli1, fnum1);
	cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	status = cli_lock32(cli1, fnum1, 7, 1, 0, WRITE_LOCK);
	ret = NT_STATUS_IS_OK(status);
	EXPECTED(ret, True);
	printf("this server %s the NT locking bug\n", ret ? "doesn't have" : "has");
	cli_close(cli1, fnum1);
	cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	cli_unlock(cli1, fnum3, 0, 1);

	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 4, 0, WRITE_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 1, 1, 0, READ_LOCK));
	EXPECTED(ret, True);
	printf("the same process %s overlay a write with a read lock\n", ret?"can":"cannot");

	status = cli_lock32(cli2, fnum2, 0, 4, 0, READ_LOCK);
	ret = NT_STATUS_IS_OK(status);
	EXPECTED(ret, False);

	printf("a different processs %s get a read lock on the first process lock stack\n", ret?"can":"cannot");

	/* Unlock the process 2 lock. */
	cli_unlock(cli2, fnum2, 0, 4);

	status = cli_lock32(cli1, fnum3, 0, 4, 0, READ_LOCK);
	ret = NT_STATUS_IS_OK(status);
	EXPECTED(ret, False);

	printf("the same processs on a different fnum %s get a read lock\n", ret?"can":"cannot");

	/* Unlock the process 1 fnum3 lock. */
	cli_unlock(cli1, fnum3, 0, 4);

	/* Stack 2 more locks here. */
	ret = NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 4, 0, READ_LOCK)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli1, fnum1, 0, 4, 0, READ_LOCK));

	EXPECTED(ret, True);
	printf("the same process %s stack read locks\n", ret?"can":"cannot");

	/* Unlock the first process lock, then check this was the WRITE lock that was
		removed. */

	ret = NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 0, 4)) &&
	      NT_STATUS_IS_OK(cli_lock32(cli2, fnum2, 0, 4, 0, READ_LOCK));

	EXPECTED(ret, True);
	printf("the first unlock removes the %s lock\n", ret?"WRITE":"READ");

	/* Unlock the process 2 lock. */
	cli_unlock(cli2, fnum2, 0, 4);

	/* We should have 3 stacked locks here. Ensure we need to do 3 unlocks. */

	ret = NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 1, 1)) &&
		  NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 0, 4)) &&
		  NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 0, 4));

	EXPECTED(ret, True);
	printf("the same process %s unlock the stack of 4 locks\n", ret?"can":"cannot"); 

	/* Ensure the next unlock fails. */
	ret = NT_STATUS_IS_OK(cli_unlock(cli1, fnum1, 0, 4));
	EXPECTED(ret, False);
	printf("the same process %s count the lock stack\n", !ret?"can":"cannot"); 

	/* Ensure connection 2 can get a write lock. */
	status = cli_lock32(cli2, fnum2, 0, 4, 0, WRITE_LOCK);
	ret = NT_STATUS_IS_OK(status);
	EXPECTED(ret, True);

	printf("a different processs %s get a write lock on the unlocked stack\n", ret?"can":"cannot");


 fail:
	cli_close(cli1, fnum1);
	cli_close(cli2, fnum2);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}

	printf("finished locktest5\n");

	return correct;
}

/*
  tries the unusual lockingX locktype bits
*/
static bool run_locktest6(int dummy)
{
	static struct cli_state *cli;
	const char *fname[1] = { "\\lock6.txt" };
	int i;
	uint16_t fnum;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("starting locktest6\n");

	for (i=0;i<1;i++) {
		printf("Testing %s\n", fname[i]);

		cli_unlink(cli, fname[i], FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

		cli_openx(cli, fname[i], O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum);
		status = cli_locktype(cli, fnum, 0, 8, 0, LOCKING_ANDX_CHANGE_LOCKTYPE);
		cli_close(cli, fnum);
		printf("CHANGE_LOCKTYPE gave %s\n", nt_errstr(status));

		cli_openx(cli, fname[i], O_RDWR, DENY_NONE, &fnum);
		status = cli_locktype(cli, fnum, 0, 8, 0, LOCKING_ANDX_CANCEL_LOCK);
		cli_close(cli, fnum);
		printf("CANCEL_LOCK gave %s\n", nt_errstr(status));

		cli_unlink(cli, fname[i], FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	}

	torture_close_connection(cli);

	printf("finished locktest6\n");
	return True;
}

static bool run_locktest7(int dummy)
{
	struct cli_state *cli1;
	const char *fname = "\\lockt7.lck";
	uint16_t fnum1;
	char buf[200];
	bool correct = False;
	size_t nread;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	printf("starting locktest7\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);

	memset(buf, 0, sizeof(buf));

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 0, sizeof(buf),
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create file: %s\n", nt_errstr(status));
		goto fail;
	}

	cli_setpid(cli1, 1);

	status = cli_lock32(cli1, fnum1, 130, 4, 0, READ_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Unable to apply read lock on range 130:4, "
		       "error was %s\n", nt_errstr(status));
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for READ\n");
	}

	status = cli_read(cli1, fnum1, buf, 130, 4, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid1 unable to read the range 130:4, error was %s\n",
		      nt_errstr(status));
		goto fail;
	} else if (nread != 4) {
		printf("pid1 unable to read the range 130:4, "
		       "recv %ld req %d\n", (unsigned long)nread, 4);
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid1 unable to write to the range 130:4, error was "
		       "%s\n", nt_errstr(status));
		if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid1 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	cli_setpid(cli1, 2);

	status = cli_read(cli1, fnum1, buf, 130, 4, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid2 unable to read the range 130:4, error was %s\n",
		      nt_errstr(status));
		goto fail;
	} else if (nread != 4) {
		printf("pid2 unable to read the range 130:4, "
		       "recv %ld req %d\n", (unsigned long)nread, 4);
		goto fail;
	} else {
		printf("pid2 successfully read the range 130:4\n");
	}

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid2 unable to write to the range 130:4, error was "
		       "%s\n", nt_errstr(status));
		if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	cli_setpid(cli1, 1);
	cli_unlock(cli1, fnum1, 130, 4);

	status = cli_lock32(cli1, fnum1, 130, 4, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Unable to apply write lock on range 130:4, error was %s\n", nt_errstr(status));
		goto fail;
	} else {
		printf("pid1 successfully locked range 130:4 for WRITE\n");
	}

	status = cli_read(cli1, fnum1, buf, 130, 4, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid1 unable to read the range 130:4, error was %s\n",
		      nt_errstr(status));
		goto fail;
	} else if (nread != 4) {
		printf("pid1 unable to read the range 130:4, "
		       "recv %ld req %d\n", (unsigned long)nread, 4);
		goto fail;
	} else {
		printf("pid1 successfully read the range 130:4\n");
	}

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid1 unable to write to the range 130:4, error was "
		       "%s\n", nt_errstr(status));
		goto fail;
	} else {
		printf("pid1 successfully wrote to the range 130:4\n");
	}

	cli_setpid(cli1, 2);

	status = cli_read(cli1, fnum1, buf, 130, 4, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid2 unable to read the range 130:4, error was "
		       "%s\n", nt_errstr(status));
		if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully read the range 130:4 (should be denied) recv %ld\n",
		       (unsigned long)nread);
		goto fail;
	}

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 130, 4, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pid2 unable to write to the range 130:4, error was "
		       "%s\n", nt_errstr(status));
		if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
			printf("Incorrect error (should be NT_STATUS_FILE_LOCK_CONFLICT)\n");
			goto fail;
		}
	} else {
		printf("pid2 successfully wrote to the range 130:4 (should be denied)\n");
		goto fail;
	}

	cli_unlock(cli1, fnum1, 130, 0);
	correct = True;

fail:
	cli_close(cli1, fnum1);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	torture_close_connection(cli1);

	printf("finished locktest7\n");
	return correct;
}

/*
 * This demonstrates a problem with our use of GPFS share modes: A file
 * descriptor sitting in the pending close queue holding a GPFS share mode
 * blocks opening a file another time. Happens with Word 2007 temp files.
 * With "posix locking = yes" and "gpfs:sharemodes = yes" enabled, the third
 * open is denied with NT_STATUS_SHARING_VIOLATION.
 */

static bool run_locktest8(int dummy)
{
	struct cli_state *cli1;
	const char *fname = "\\lockt8.lck";
	uint16_t fnum1, fnum2;
	char buf[200];
	bool correct = False;
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	printf("starting locktest8\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_WRITE,
			  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_openx returned %s\n", nt_errstr(status));
		return false;
	}

	memset(buf, 0, sizeof(buf));

	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_openx second time returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = cli_lock32(cli1, fnum2, 1, 1, 0, READ_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Unable to apply read lock on range 1:1, error was "
		       "%s\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_close(fnum1) %s\n", nt_errstr(status));
		goto fail;
	}

	status = cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_openx third time returned %s\n",
                          nt_errstr(status));
                goto fail;
        }

	correct = true;

fail:
	cli_close(cli1, fnum1);
	cli_close(cli1, fnum2);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	torture_close_connection(cli1);

	printf("finished locktest8\n");
	return correct;
}

/*
 * This test is designed to be run in conjunction with
 * external NFS or POSIX locks taken in the filesystem.
 * It checks that the smbd server will block until the
 * lock is released and then acquire it. JRA.
 */

static bool got_alarm;
static struct cli_state *alarm_cli;

static void alarm_handler(int dummy)
{
        got_alarm = True;
}

static void alarm_handler_parent(int dummy)
{
	smbXcli_conn_disconnect(alarm_cli->conn, NT_STATUS_OK);
}

static void do_local_lock(int read_fd, int write_fd)
{
	int fd;
	char c = '\0';
	struct flock lock;
	const char *local_pathname = NULL;
	int ret;

	local_pathname = talloc_asprintf(talloc_tos(),
			"%s/lockt9.lck", local_path);
	if (!local_pathname) {
		printf("child: alloc fail\n");
		exit(1);
	}

	unlink(local_pathname);
	fd = open(local_pathname, O_RDWR|O_CREAT, 0666);
	if (fd == -1) {
		printf("child: open of %s failed %s.\n",
			local_pathname, strerror(errno));
		exit(1);
	}

	/* Now take a fcntl lock. */
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 4;
	lock.l_pid = getpid();

	ret = fcntl(fd,F_SETLK,&lock);
	if (ret == -1) {
		printf("child: failed to get lock 0:4 on file %s. Error %s\n",
			local_pathname, strerror(errno));
		exit(1);
	} else {
		printf("child: got lock 0:4 on file %s.\n",
			local_pathname );
		fflush(stdout);
	}

	CatchSignal(SIGALRM, alarm_handler);
	alarm(5);
	/* Signal the parent. */
	if (write(write_fd, &c, 1) != 1) {
		printf("child: start signal fail %s.\n",
			strerror(errno));
		exit(1);
	}
	alarm(0);

	alarm(10);
	/* Wait for the parent to be ready. */
	if (read(read_fd, &c, 1) != 1) {
		printf("child: reply signal fail %s.\n",
			strerror(errno));
		exit(1);
	}
	alarm(0);

	sleep(5);
	close(fd);
	printf("child: released lock 0:4 on file %s.\n",
		local_pathname );
	fflush(stdout);
	exit(0);
}

static bool run_locktest9(int dummy)
{
	struct cli_state *cli1;
	const char *fname = "\\lockt9.lck";
	uint16_t fnum;
	bool correct = False;
	int pipe_in[2], pipe_out[2];
	pid_t child_pid;
	char c = '\0';
	int ret;
	struct timeval start;
	double seconds;
	NTSTATUS status;

	printf("starting locktest9\n");

	if (local_path == NULL) {
		d_fprintf(stderr, "locktest9 must be given a local path via -l <localpath>\n");
		return false;
	}

	if (pipe(pipe_in) == -1 || pipe(pipe_out) == -1) {
		return false;
	}

	child_pid = fork();
	if (child_pid == -1) {
		return false;
	}

	if (child_pid == 0) {
		/* Child. */
		do_local_lock(pipe_out[0], pipe_in[1]);
		exit(0);
	}

	close(pipe_out[0]);
	close(pipe_in[1]);
	pipe_out[0] = -1;
	pipe_in[1] = -1;

	/* Parent. */
	ret = read(pipe_in[0], &c, 1);
	if (ret != 1) {
		d_fprintf(stderr, "failed to read start signal from child. %s\n",
			strerror(errno));
		return false;
	}

	if (!torture_open_connection(&cli1, 0)) {
		return false;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	status = cli_openx(cli1, fname, O_RDWR, DENY_NONE,
			  &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_openx returned %s\n", nt_errstr(status));
		return false;
	}

	/* Ensure the child has the lock. */
	status = cli_lock32(cli1, fnum, 0, 4, 0, WRITE_LOCK);
	if (NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Got the lock on range 0:4 - this should not happen !\n");
		goto fail;
	} else {
		d_printf("Child has the lock.\n");
	}

	/* Tell the child to wait 5 seconds then exit. */
	ret = write(pipe_out[1], &c, 1);
	if (ret != 1) {
		d_fprintf(stderr, "failed to send exit signal to child. %s\n",
			strerror(errno));
		goto fail;
	}

	/* Wait 20 seconds for the lock. */
	alarm_cli = cli1;
	CatchSignal(SIGALRM, alarm_handler_parent);
	alarm(20);

	start = timeval_current();

	status = cli_lock32(cli1, fnum, 0, 4, -1, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Unable to apply write lock on range 0:4, error was "
		       "%s\n", nt_errstr(status));
		goto fail_nofd;
	}
	alarm(0);

	seconds = timeval_elapsed(&start);

	printf("Parent got the lock after %.2f seconds.\n",
		seconds);

	status = cli_close(cli1, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_close(fnum1) %s\n", nt_errstr(status));
		goto fail;
	}

	correct = true;

fail:
	cli_close(cli1, fnum);
	torture_close_connection(cli1);

fail_nofd:

	printf("finished locktest9\n");
	return correct;
}

/*
test whether fnums and tids open on one VC are available on another (a major
security hole)
*/
static bool run_fdpasstest(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "\\fdpass.tst";
	uint16_t fnum1;
	char buf[1024];
	NTSTATUS status;

	if (!torture_open_connection(&cli1, 0) || !torture_open_connection(&cli2, 1)) {
		return False;
	}
	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("starting fdpasstest\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
	                  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_writeall(cli1, fnum1, 0, (const uint8_t *)"hello world\n", 0,
			      13, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_state_set_uid(cli2, cli_state_get_uid(cli1));
	cli_state_set_tid(cli2, cli_state_get_tid(cli1));
	cli_setpid(cli2, cli_getpid(cli1));

	if (test_cli_read(cli2, fnum1, buf, 0, 13, NULL, 13)) {
		printf("read succeeded! nasty security hole [%s]\n", buf);
		return false;
	}

	cli_close(cli1, fnum1);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	torture_close_connection(cli1);
	torture_close_connection(cli2);

	printf("finished fdpasstest\n");
	return True;
}

static bool run_fdsesstest(int dummy)
{
	struct cli_state *cli;
	uint16 new_vuid;
	uint16 saved_vuid;
	uint16 new_cnum;
	uint16 saved_cnum;
	const char *fname = "\\fdsess.tst";
	const char *fname1 = "\\fdsess1.tst";
	uint16_t fnum1;
	uint16_t fnum2;
	char buf[1024];
	bool ret = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0))
		return False;
	smbXcli_conn_set_sockopt(cli->conn, sockops);

	if (!torture_cli_session_setup2(cli, &new_vuid))
		return False;

	saved_cnum = cli_state_get_tid(cli);
	if (!NT_STATUS_IS_OK(cli_tree_connect(cli, share, "?????", "", 1)))
		return False;
	new_cnum = cli_state_get_tid(cli);
	cli_state_set_tid(cli, saved_cnum);

	printf("starting fdsesstest\n");

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_writeall(cli, fnum1, 0, (const uint8_t *)"hello world\n", 0, 13,
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write failed (%s)\n", nt_errstr(status));
		return False;
	}

	saved_vuid = cli_state_get_uid(cli);
	cli_state_set_uid(cli, new_vuid);

	if (test_cli_read(cli, fnum1, buf, 0, 13, NULL, 13)) {
		printf("read succeeded with different vuid! "
		       "nasty security hole [%s]\n", buf);
		ret = false;
	}
	/* Try to open a file with different vuid, samba cnum. */
	if (NT_STATUS_IS_OK(cli_openx(cli, fname1, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum2))) {
		printf("create with different vuid, same cnum succeeded.\n");
		cli_close(cli, fnum2);
		cli_unlink(cli, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	} else {
		printf("create with different vuid, same cnum failed.\n");
		printf("This will cause problems with service clients.\n");
		ret = False;
	}

	cli_state_set_uid(cli, saved_vuid);

	/* Try with same vuid, different cnum. */
	cli_state_set_tid(cli, new_cnum);

	if (test_cli_read(cli, fnum1, buf, 0, 13, NULL, 13)) {
		printf("read succeeded with different cnum![%s]\n", buf);
		ret = false;
	}

	cli_state_set_tid(cli, saved_cnum);
	cli_close(cli, fnum1);
	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	torture_close_connection(cli);

	printf("finished fdsesstest\n");
	return ret;
}

/*
  This test checks that 

  1) the server does not allow an unlink on a file that is open
*/
static bool run_unlinktest(int dummy)
{
	struct cli_state *cli;
	const char *fname = "\\unlink.tst";
	uint16_t fnum;
	bool correct = True;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	printf("starting unlink test\n");

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	cli_setpid(cli, 1);

	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_unlink(cli, fname,
			    FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (NT_STATUS_IS_OK(status)) {
		printf("error: server allowed unlink on an open file\n");
		correct = False;
	} else {
		correct = check_error(__LINE__, status, ERRDOS, ERRbadshare,
				      NT_STATUS_SHARING_VIOLATION);
	}

	cli_close(cli, fnum);
	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("unlink test finished\n");

	return correct;
}


/*
test how many open files this server supports on the one socket
*/
static bool run_maxfidtest(int dummy)
{
	struct cli_state *cli;
	fstring fname;
	uint16_t fnums[0x11000];
	int i;
	int retries=4;
	bool correct = True;
	NTSTATUS status;

	cli = current_cli;

	if (retries <= 0) {
		printf("failed to connect\n");
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	for (i=0; i<0x11000; i++) {
		slprintf(fname,sizeof(fname)-1,"\\maxfid.%d.%d", i,(int)getpid());
		status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_TRUNC, DENY_NONE,
		                  &fnums[i]);
		if (!NT_STATUS_IS_OK(status)) {
			printf("open of %s failed (%s)\n", 
			       fname, nt_errstr(status));
			printf("maximum fnum is %d\n", i);
			break;
		}
		printf("%6d\r", i);
	}
	printf("%6d\n", i);
	i--;

	printf("cleaning up\n");
	for (;i>=0;i--) {
		slprintf(fname,sizeof(fname)-1,"\\maxfid.%d.%d", i,(int)getpid());
		cli_close(cli, fnums[i]);

		status = cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlink of %s failed (%s)\n", 
			       fname, nt_errstr(status));
			correct = False;
		}
		printf("%6d\r", i);
	}
	printf("%6d\n", 0);

	printf("maxfid test finished\n");
	if (!torture_close_connection(cli)) {
		correct = False;
	}
	return correct;
}

/* generate a random buffer */
static void rand_buf(char *buf, int len)
{
	while (len--) {
		*buf = (char)sys_random();
		buf++;
	}
}

/* send smb negprot commands, not reading the response */
static bool run_negprot_nowait(int dummy)
{
	struct tevent_context *ev;
	int i;
	struct cli_state *cli;
	bool correct = True;

	printf("starting negprot nowait test\n");

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		return false;
	}

	if (!(cli = open_nbt_connection())) {
		TALLOC_FREE(ev);
		return False;
	}

	for (i=0;i<50000;i++) {
		struct tevent_req *req;

		req = smbXcli_negprot_send(ev, ev, cli->conn, cli->timeout,
					   PROTOCOL_CORE, PROTOCOL_NT1);
		if (req == NULL) {
			TALLOC_FREE(ev);
			return false;
		}
		if (!tevent_req_poll(req, ev)) {
			d_fprintf(stderr, "tevent_req_poll failed: %s\n",
				  strerror(errno));
			TALLOC_FREE(ev);
			return false;
		}
		TALLOC_FREE(req);
	}

	if (torture_close_connection(cli)) {
		correct = False;
	}

	printf("finished negprot nowait test\n");

	return correct;
}

/* send smb negprot commands, not reading the response */
static bool run_bad_nbt_session(int dummy)
{
	struct nmb_name called, calling;
	struct sockaddr_storage ss;
	NTSTATUS status;
	int fd;
	bool ret;

	printf("starting bad nbt session test\n");

	make_nmb_name(&calling, myname, 0x0);
	make_nmb_name(&called , host, 0x20);

	if (!resolve_name(host, &ss, 0x20, true)) {
		d_fprintf(stderr, "Could not resolve name %s\n", host);
		return false;
	}

	status = open_socket_out(&ss, NBT_SMB_PORT, 10000, &fd);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "open_socket_out failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	ret = cli_bad_session_request(fd, &calling, &called);
	close(fd);
	if (!ret) {
		d_fprintf(stderr, "open_socket_out failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	printf("finished bad nbt session test\n");
	return true;
}

/* send random IPC commands */
static bool run_randomipc(int dummy)
{
	char *rparam = NULL;
	char *rdata = NULL;
	unsigned int rdrcnt,rprcnt;
	char param[1024];
	int api, param_len, i;
	struct cli_state *cli;
	bool correct = True;
	int count = 50000;

	printf("starting random ipc test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	for (i=0;i<count;i++) {
		api = sys_random() % 500;
		param_len = (sys_random() % 64);

		rand_buf(param, param_len);

		SSVAL(param,0,api); 

		cli_api(cli, 
			param, param_len, 8,  
			NULL, 0, CLI_BUFFER_SIZE,
			&rparam, &rprcnt,     
			&rdata, &rdrcnt);
		if (i % 100 == 0) {
			printf("%d/%d\r", i,count);
		}
	}
	printf("%d/%d\n", i, count);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	printf("finished random ipc test\n");

	return correct;
}



static void browse_callback(const char *sname, uint32 stype, 
			    const char *comment, void *state)
{
	printf("\t%20.20s %08x %s\n", sname, stype, comment);
}



/*
  This test checks the browse list code

*/
static bool run_browsetest(int dummy)
{
	static struct cli_state *cli;
	bool correct = True;

	printf("starting browse test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	printf("domain list:\n");
	cli_NetServerEnum(cli, cli->server_domain, 
			  SV_TYPE_DOMAIN_ENUM,
			  browse_callback, NULL);

	printf("machine list:\n");
	cli_NetServerEnum(cli, cli->server_domain, 
			  SV_TYPE_ALL,
			  browse_callback, NULL);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("browse test finished\n");

	return correct;

}


/*
  This checks how the getatr calls works
*/
static bool run_attrtest(int dummy)
{
	struct cli_state *cli;
	uint16_t fnum;
	time_t t, t2;
	const char *fname = "\\attrib123456789.tst";
	bool correct = True;
	NTSTATUS status;

	printf("starting attrib test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_openx(cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE, &fnum);
	cli_close(cli, fnum);

	status = cli_getatr(cli, fname, NULL, NULL, &t);
	if (!NT_STATUS_IS_OK(status)) {
		printf("getatr failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (abs(t - time(NULL)) > 60*60*24*10) {
		printf("ERROR: SMBgetatr bug. time is %s",
		       ctime(&t));
		t = time(NULL);
		correct = True;
	}

	t2 = t-60*60*24; /* 1 day ago */

	status = cli_setatr(cli, fname, 0, t2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("setatr failed (%s)\n", nt_errstr(status));
		correct = True;
	}

	status = cli_getatr(cli, fname, NULL, NULL, &t);
	if (!NT_STATUS_IS_OK(status)) {
		printf("getatr failed (%s)\n", nt_errstr(status));
		correct = True;
	}

	if (t != t2) {
		printf("ERROR: getatr/setatr bug. times are\n%s",
		       ctime(&t));
		printf("%s", ctime(&t2));
		correct = True;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("attrib test finished\n");

	return correct;
}


/*
  This checks a couple of trans2 calls
*/
static bool run_trans2test(int dummy)
{
	struct cli_state *cli;
	uint16_t fnum;
	off_t size;
	time_t c_time, a_time, m_time;
	struct timespec c_time_ts, a_time_ts, m_time_ts, w_time_ts, m_time2_ts;
	const char *fname = "\\trans2.tst";
	const char *dname = "\\trans2";
	const char *fname2 = "\\trans2\\trans2.tst";
	char *pname;
	bool correct = True;
	NTSTATUS status;
	uint32_t fs_attr;

	printf("starting trans2 test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	status = cli_get_fs_attr_info(cli, &fs_attr);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: cli_get_fs_attr_info returned %s\n",
		       nt_errstr(status));
		correct = false;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_openx(cli, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_NONE, &fnum);
	status = cli_qfileinfo_basic(cli, fnum, NULL, &size, &c_time_ts,
	                             &a_time_ts, &w_time_ts, &m_time_ts, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qfileinfo failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_qfilename(cli, fnum, talloc_tos(), &pname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qfilename failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (strcmp(pname, fname)) {
		printf("qfilename gave different name? [%s] [%s]\n",
		       fname, pname);
		correct = False;
	}

	cli_close(cli, fnum);

	sleep(2);

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	status = cli_openx(cli, fname, O_RDWR | O_CREAT | O_TRUNC, DENY_NONE,
	                  &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}
	cli_close(cli, fnum);

	status = cli_qpathinfo1(cli, fname, &c_time, &a_time, &m_time, &size,
				NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qpathinfo failed (%s)\n", nt_errstr(status));
		correct = False;
	} else {
		time_t t = time(NULL);

		if (c_time != m_time) {
			printf("create time=%s", ctime(&c_time));
			printf("modify time=%s", ctime(&m_time));
			printf("This system appears to have sticky create times\n");
		}
		if ((abs(a_time - t) > 60) && (a_time % (60*60) == 0)) {
			printf("access time=%s", ctime(&a_time));
			printf("This system appears to set a midnight access time\n");
			correct = False;
		}

		if (abs(m_time - t) > 60*60*24*7) {
			printf("ERROR: totally incorrect times - maybe word reversed? mtime=%s", ctime(&m_time));
			correct = False;
		}
	}


	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_openx(cli, fname, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE, &fnum);
	cli_close(cli, fnum);
	status = cli_qpathinfo2(cli, fname, &c_time_ts, &a_time_ts, &w_time_ts,
				&m_time_ts, &size, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", nt_errstr(status));
		correct = False;
	} else {
		if (w_time_ts.tv_sec < 60*60*24*2) {
			printf("write time=%s", ctime(&w_time_ts.tv_sec));
			printf("This system appears to set a initial 0 write time\n");
			correct = False;
		}
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);


	/* check if the server updates the directory modification time
           when creating a new file */
	status = cli_mkdir(cli, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: mkdir failed (%s)\n", nt_errstr(status));
		correct = False;
	}
	sleep(3);
	status = cli_qpathinfo2(cli, "\\trans2\\", &c_time_ts, &a_time_ts,
				&w_time_ts, &m_time_ts, &size, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	cli_openx(cli, fname2, 
			O_RDWR | O_CREAT | O_TRUNC, DENY_NONE, &fnum);
	cli_writeall(cli, fnum,  0, (uint8_t *)&fnum, 0, sizeof(fnum), NULL);
	cli_close(cli, fnum);
	status = cli_qpathinfo2(cli, "\\trans2\\", &c_time_ts, &a_time_ts,
				&w_time_ts, &m_time2_ts, &size, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qpathinfo2 failed (%s)\n", nt_errstr(status));
		correct = False;
	} else {
		if (memcmp(&m_time_ts, &m_time2_ts, sizeof(struct timespec))
		    == 0) {
			printf("This system does not update directory modification times\n");
			correct = False;
		}
	}
	cli_unlink(cli, fname2, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, dname);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("trans2 test finished\n");

	return correct;
}

/*
  This checks new W2K calls.
*/

static NTSTATUS new_trans(struct cli_state *pcli, int fnum, int level)
{
	uint8_t *buf = NULL;
	uint32 len;
	NTSTATUS status;

	status = cli_qfileinfo(talloc_tos(), pcli, fnum, level, 0,
			       CLI_BUFFER_SIZE, NULL, &buf, &len);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: qfileinfo (%d) failed (%s)\n", level,
		       nt_errstr(status));
	} else {
		printf("qfileinfo: level %d, len = %u\n", level, len);
		dump_data(0, (uint8 *)buf, len);
		printf("\n");
	}
	TALLOC_FREE(buf);
	return status;
}

static bool run_w2ktest(int dummy)
{
	struct cli_state *cli;
	uint16_t fnum;
	const char *fname = "\\w2ktest\\w2k.tst";
	int level;
	bool correct = True;

	printf("starting w2k test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	cli_openx(cli, fname, 
			O_RDWR | O_CREAT , DENY_NONE, &fnum);

	for (level = 1004; level < 1040; level++) {
		new_trans(cli, fnum, level);
	}

	cli_close(cli, fnum);

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("w2k test finished\n");

	return correct;
}


/*
  this is a harness for some oplock tests
 */
static bool run_oplock1(int dummy)
{
	struct cli_state *cli1;
	const char *fname = "\\lockt1.lck";
	uint16_t fnum1;
	bool correct = True;
	NTSTATUS status;

	printf("starting oplock test 1\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	cli1->use_oplocks = True;

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
			  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	cli1->use_oplocks = False;

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		return False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}

	printf("finished oplock test 1\n");

	return correct;
}

static bool run_oplock2(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "\\lockt2.lck";
	uint16_t fnum1, fnum2;
	int saved_use_oplocks = use_oplocks;
	char buf[4];
	bool correct = True;
	volatile bool *shared_correct;
	size_t nread;
	NTSTATUS status;

	shared_correct = (volatile bool *)anonymous_shared_allocate(sizeof(bool));
	*shared_correct = True;

	use_level_II_oplocks = True;
	use_oplocks = True;

	printf("starting oplock test 2\n");

	if (!torture_open_connection(&cli1, 0)) {
		use_level_II_oplocks = False;
		use_oplocks = saved_use_oplocks;
		return False;
	}

	if (!torture_open_connection(&cli2, 1)) {
		use_level_II_oplocks = False;
		use_oplocks = saved_use_oplocks;
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
	                  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	/* Don't need the globals any more. */
	use_level_II_oplocks = False;
	use_oplocks = saved_use_oplocks;

	if (fork() == 0) {
		/* Child code */
		status = cli_openx(cli2, fname, O_RDWR, DENY_NONE, &fnum2);
		if (!NT_STATUS_IS_OK(status)) {
			printf("second open of %s failed (%s)\n", fname, nt_errstr(status));
			*shared_correct = False;
			exit(0);
		}

		sleep(2);

		status = cli_close(cli2, fnum2);
		if (!NT_STATUS_IS_OK(status)) {
			printf("close2 failed (%s)\n", nt_errstr(status));
			*shared_correct = False;
		}

		exit(0);
	}

	sleep(2);

	/* Ensure cli1 processes the break. Empty file should always return 0
	 * bytes.  */
	status = cli_read(cli1, fnum1, buf, 0, 4, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("read on fnum1 failed (%s)\n", nt_errstr(status));
		correct = false;
	} else if (nread != 0) {
		printf("read on empty fnum1 failed. recv %ld expected %d\n",
		      (unsigned long)nread, 0);
		correct = false;
	}

	/* Should now be at level II. */
	/* Test if sending a write locks causes a break to none. */
	status = cli_lock32(cli1, fnum1, 0, 4, 0, READ_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	cli_unlock(cli1, fnum1, 0, 4);

	sleep(2);

	status = cli_lock32(cli1, fnum1, 0, 4, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	cli_unlock(cli1, fnum1, 0, 4);

	sleep(2);

	cli_read(cli1, fnum1, buf, 0, 4, NULL);

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	sleep(4);

	status = cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}

	if (!*shared_correct) {
		correct = False;
	}

	printf("finished oplock test 2\n");

	return correct;
}

struct oplock4_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	bool *got_break;
	uint16_t *fnum2;
};

static void oplock4_got_break(struct tevent_req *req);
static void oplock4_got_open(struct tevent_req *req);

static bool run_oplock4(int dummy)
{
	struct tevent_context *ev;
	struct cli_state *cli1, *cli2;
	struct tevent_req *oplock_req, *open_req;
	const char *fname = "\\lockt4.lck";
	const char *fname_ln = "\\lockt4_ln.lck";
	uint16_t fnum1, fnum2;
	int saved_use_oplocks = use_oplocks;
	NTSTATUS status;
	bool correct = true;

	bool got_break;

	struct oplock4_state *state;

	printf("starting oplock test 4\n");

	if (!torture_open_connection(&cli1, 0)) {
		use_level_II_oplocks = false;
		use_oplocks = saved_use_oplocks;
		return false;
	}

	if (!torture_open_connection(&cli2, 1)) {
		use_level_II_oplocks = false;
		use_oplocks = saved_use_oplocks;
		return false;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname_ln, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	/* Create the file. */
	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE,
	                  &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return false;
	}

	/* Now create a hardlink. */
	status = cli_nt_hardlink(cli1, fname, fname_ln);
	if (!NT_STATUS_IS_OK(status)) {
		printf("nt hardlink failed (%s)\n", nt_errstr(status));
		return false;
	}

	/* Prove that opening hardlinks cause deny modes to conflict. */
	status = cli_openx(cli1, fname, O_RDWR, DENY_ALL, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}

	status = cli_openx(cli1, fname_ln, O_RDWR, DENY_NONE, &fnum2);
	if (NT_STATUS_IS_OK(status)) {
		printf("open of %s succeeded - should fail with sharing violation.\n",
			fname_ln);
		return false;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		printf("open of %s should fail with sharing violation. Got %s\n",
			fname_ln, nt_errstr(status));
		return false;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return false;
	}

	cli1->use_oplocks = true;
	cli2->use_oplocks = true;

	status = cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("tevent_context_init failed\n");
		return false;
	}

	state = talloc(ev, struct oplock4_state);
	if (state == NULL) {
		printf("talloc failed\n");
		return false;
	}
	state->ev = ev;
	state->cli = cli1;
	state->got_break = &got_break;
	state->fnum2 = &fnum2;

	oplock_req = cli_smb_oplock_break_waiter_send(
		talloc_tos(), ev, cli1);
	if (oplock_req == NULL) {
		printf("cli_smb_oplock_break_waiter_send failed\n");
		return false;
	}
	tevent_req_set_callback(oplock_req, oplock4_got_break, state);

	open_req = cli_openx_send(
		talloc_tos(), ev, cli2, fname_ln, O_RDWR, DENY_NONE);
	if (open_req == NULL) {
		printf("cli_openx_send failed\n");
		return false;
	}
	tevent_req_set_callback(open_req, oplock4_got_open, state);

	got_break = false;
	fnum2 = 0xffff;

	while (!got_break || fnum2 == 0xffff) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret == -1) {
			printf("tevent_loop_once failed: %s\n",
			       strerror(errno));
			return false;
		}
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		correct = false;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		correct = false;
	}

	status = cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		correct = false;
	}

	status = cli_unlink(cli1, fname_ln, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink failed (%s)\n", nt_errstr(status));
		correct = false;
	}

	if (!torture_close_connection(cli1)) {
		correct = false;
	}

	if (!got_break) {
		correct = false;
	}

	printf("finished oplock test 4\n");

	return correct;
}

static void oplock4_got_break(struct tevent_req *req)
{
	struct oplock4_state *state = tevent_req_callback_data(
		req, struct oplock4_state);
	uint16_t fnum;
	uint8_t level;
	NTSTATUS status;

	status = cli_smb_oplock_break_waiter_recv(req, &fnum, &level);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_smb_oplock_break_waiter_recv returned %s\n",
		       nt_errstr(status));
		return;
	}
	*state->got_break = true;

	req = cli_oplock_ack_send(state, state->ev, state->cli, fnum,
				  NO_OPLOCK);
	if (req == NULL) {
		printf("cli_oplock_ack_send failed\n");
		return;
	}
}

static void oplock4_got_open(struct tevent_req *req)
{
	struct oplock4_state *state = tevent_req_callback_data(
		req, struct oplock4_state);
	NTSTATUS status;

	status = cli_openx_recv(req, state->fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_openx_recv returned %s\n", nt_errstr(status));
		*state->fnum2 = 0xffff;
	}
}

/*
  Test delete on close semantics.
 */
static bool run_deletetest(int dummy)
{
	struct cli_state *cli1 = NULL;
	struct cli_state *cli2 = NULL;
	const char *fname = "\\delete.file";
	uint16_t fnum1 = (uint16_t)-1;
	uint16_t fnum2 = (uint16_t)-1;
	bool correct = false;
	NTSTATUS status;

	printf("starting delete test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	/* Test 1 - this should delete the file on close. */

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, GENERIC_ALL_ACCESS|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			      FILE_DELETE_ON_CLOSE, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[1] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[1] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_openx(cli1, fname, O_RDWR, DENY_NONE, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("[1] open of %s succeeded (should fail)\n", fname);
		goto fail;
	}

	printf("first delete on close test succeeded.\n");

	/* Test 2 - this should delete the file on close. */

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, GENERIC_ALL_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[2] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[2] setting delete_on_close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[2] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("[2] open of %s succeeded should have been deleted on close !\n", fname);
		status = cli_close(cli1, fnum1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("[2] close failed (%s)\n", nt_errstr(status));
		}
		cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		goto fail;
	}

	printf("second delete on close test succeeded.\n");

	/* Test 3 - ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, GENERIC_ALL_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[3] open - 1 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	/* This should fail with a sharing violation - open for delete is only compatible
	   with SHARE_DELETE. */

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("[3] open  - 2 of %s succeeded - should have failed.\n", fname);
		goto fail;
	}

	/* This should succeed. */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OPEN, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[3] open  - 3 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[3] setting delete_on_close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[3] close 1 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[3] close 2 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This should fail - file should no longer be there. */

	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("[3] open of %s succeeded should have been deleted on close !\n", fname);
		status = cli_close(cli1, fnum1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("[3] close failed (%s)\n", nt_errstr(status));
		}
		cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		goto fail;
	}

	printf("third delete on close test succeeded.\n");

	/* Test 4 ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0,
	                      FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[4] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	/* This should succeed. */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
	                     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OPEN, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[4] open  - 2 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[4] close - 1 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[4] setting delete_on_close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This should fail - no more opens once delete on close set. */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("[4] open  - 3 of %s succeeded ! Should have failed.\n", fname );
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[4] close - 2 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	printf("fourth delete on close test succeeded.\n");

	/* Test 5 ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[5] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	/* This should fail - only allowed on NT opens with DELETE access. */

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (NT_STATUS_IS_OK(status)) {
		printf("[5] setting delete_on_close on OpenX file succeeded - should fail !\n");
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[5] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	printf("fifth delete on close test succeeded.\n");

	/* Test 6 ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, FILE_READ_DATA|FILE_WRITE_DATA,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[6] open of %s failed (%s)\n", fname,
		       nt_errstr(status));
		goto fail;
	}

	/* This should fail - only allowed on NT opens with DELETE access. */

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (NT_STATUS_IS_OK(status)) {
		printf("[6] setting delete_on_close on file with no delete access succeeded - should fail !\n");
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[6] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	printf("sixth delete on close test succeeded.\n");

	/* Test 7 ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0,
	                      FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			      0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] setting delete_on_close on file failed !\n");
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, false);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] unsetting delete_on_close on file failed !\n");
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] close - 1 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This next open should succeed - we reset the flag. */
	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[7] close - 2 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	printf("seventh delete on close test succeeded.\n");

	/* Test 8 ... */
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_open_connection(&cli2, 1)) {
		printf("[8] failed to open second connection.\n");
		goto fail;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	status = cli_ntcreate(cli1, fname, 0,
	                     FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[8] open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_ntcreate(cli2, fname, 0,
			     FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			     FILE_ATTRIBUTE_NORMAL,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OPEN, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[8] open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[8] setting delete_on_close on file failed !\n");
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[8] close - 1 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[8] close - 2 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This should fail.. */
	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("[8] open of %s succeeded should have been deleted on close !\n", fname);
		goto fail;
	}

	printf("eighth delete on close test succeeded.\n");

	/* Test 9 ... */

	/* This should fail - we need to set DELETE_ACCESS. */
	status = cli_ntcreate(cli1, fname, 0, FILE_READ_DATA|FILE_WRITE_DATA,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF,
			      FILE_DELETE_ON_CLOSE, 0, &fnum1, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("[9] open of %s succeeded should have failed!\n", fname);
		goto fail;
	}

	printf("ninth delete on close test succeeded.\n");

	/* Test 10 ... */

	status = cli_ntcreate(cli1, fname, 0,
			     FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			     FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			     FILE_OVERWRITE_IF, FILE_DELETE_ON_CLOSE,
			     0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[10] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	/* This should delete the file. */
	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[10] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This should fail.. */
	status = cli_openx(cli1, fname, O_RDONLY, DENY_NONE, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("[10] open of %s succeeded should have been deleted on close !\n", fname);
		goto fail;
	}

	printf("tenth delete on close test succeeded.\n");

	/* Test 11 ... */

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	/* Can we open a read-only file with delete access? */

	/* Create a readonly file. */
	status = cli_ntcreate(cli1, fname, 0, FILE_READ_DATA|FILE_WRITE_DATA,
	                      FILE_ATTRIBUTE_READONLY, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[11] open of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[11] close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* Now try open for delete access. */
	status = cli_ntcreate(cli1, fname, 0,
			     FILE_READ_ATTRIBUTES|DELETE_ACCESS,
			     0,
			     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OPEN, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[11] open of %s failed: %s\n", fname, nt_errstr(status));
		goto fail;
	}

	cli_close(cli1, fnum1);

	printf("eleventh delete on close test succeeded.\n");

	/*
	 * Test 12
	 * like test 4 but with initial delete on close
	 */

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0,
	                      FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OVERWRITE_IF,
			      FILE_DELETE_ON_CLOSE, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] open 2 of %s failed(%s).\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] close 1 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] setting delete_on_close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/* This should fail - no more opens once delete on close set. */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("[12] open 3 of %s succeeded - should fail).\n", fname);
		goto fail;
	}

	status = cli_nt_delete_on_close(cli1, fnum1, false);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] unsetting delete_on_close failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] open 4 of %s failed (%s)\n", fname, nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] close 2 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("[12] close 3 failed (%s)\n", nt_errstr(status));
		goto fail;
	}

	/*
	 * setting delete on close on the handle does
	 * not unset the initial delete on close...
	 */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			      FILE_OPEN, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("[12] open 5 of %s succeeded - should fail).\n", fname);
		goto fail;
	} else if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		printf("ntcreate returned %s, expected "
		       "NT_STATUS_OBJECT_NAME_NOT_FOUND\n",
		       nt_errstr(status));
		goto fail;
	}

	printf("twelfth delete on close test succeeded.\n");


	printf("finished delete test\n");

	correct = true;

  fail:
	/* FIXME: This will crash if we aborted before cli2 got
	 * intialized, because these functions don't handle
	 * uninitialized connections. */

	if (fnum1 != (uint16_t)-1) cli_close(cli1, fnum1);
	if (fnum2 != (uint16_t)-1) cli_close(cli1, fnum2);
	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (cli1 && !torture_close_connection(cli1)) {
		correct = False;
	}
	if (cli2 && !torture_close_connection(cli2)) {
		correct = False;
	}
	return correct;
}

static bool run_deletetest_ln(int dummy)
{
	struct cli_state *cli;
	const char *fname = "\\delete1";
	const char *fname_ln = "\\delete1_ln";
	uint16_t fnum;
	uint16_t fnum1;
	NTSTATUS status;
	bool correct = true;
	time_t t;

	printf("starting deletetest-ln\n");

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli, fname_ln, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	/* Create the file. */
	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}

	status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close1 failed (%s)\n", nt_errstr(status));
		return false;
	}

	/* Now create a hardlink. */
	status = cli_nt_hardlink(cli, fname, fname_ln);
	if (!NT_STATUS_IS_OK(status)) {
		printf("nt hardlink failed (%s)\n", nt_errstr(status));
		return false;
	}

	/* Open the original file. */
	status = cli_ntcreate(cli, fname, 0, FILE_READ_DATA,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			FILE_OPEN_IF, 0, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ntcreate of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}

	/* Unlink the hard link path. */
	status = cli_ntcreate(cli, fname_ln, 0, DELETE_ACCESS,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			FILE_OPEN_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ntcreate of %s failed (%s)\n", fname_ln, nt_errstr(status));
		return false;
	}
	status = cli_nt_delete_on_close(cli, fnum1, true);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("(%s) failed to set delete_on_close %s: %s\n",
			__location__, fname_ln, nt_errstr(status));
		return false;
	}

	status = cli_close(cli, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close %s failed (%s)\n",
			fname_ln, nt_errstr(status));
		return false;
	}

	status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close %s failed (%s)\n",
			fname, nt_errstr(status));
		return false;
	}

	/* Ensure the original file is still there. */
        status = cli_getatr(cli, fname, NULL, NULL, &t);
        if (!NT_STATUS_IS_OK(status)) {
                printf("%s getatr on file %s failed (%s)\n",
			__location__,
			fname,
			nt_errstr(status));
                correct = False;
        }

	/* Ensure the link path is gone. */
	status = cli_getatr(cli, fname_ln, NULL, NULL, &t);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
                printf("%s, getatr for file %s returned wrong error code %s "
			"- should have been deleted\n",
			__location__,
			fname_ln, nt_errstr(status));
                correct = False;
        }

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli, fname_ln, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_close_connection(cli)) {
		correct = false;
	}

	printf("finished deletetest-ln\n");

	return correct;
}

/*
  print out server properties
 */
static bool run_properties(int dummy)
{
	struct cli_state *cli;
	bool correct = True;

	printf("starting properties test\n");

	ZERO_STRUCT(cli);

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	d_printf("Capabilities 0x%08x\n", smb1cli_conn_capabilities(cli->conn));

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	return correct;
}



/* FIRST_DESIRED_ACCESS   0xf019f */
#define FIRST_DESIRED_ACCESS   FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|\
                               FILE_READ_EA|                           /* 0xf */ \
                               FILE_WRITE_EA|FILE_READ_ATTRIBUTES|     /* 0x90 */ \
                               FILE_WRITE_ATTRIBUTES|                  /* 0x100 */ \
                               DELETE_ACCESS|READ_CONTROL_ACCESS|\
                               WRITE_DAC_ACCESS|WRITE_OWNER_ACCESS     /* 0xf0000 */
/* SECOND_DESIRED_ACCESS  0xe0080 */
#define SECOND_DESIRED_ACCESS  FILE_READ_ATTRIBUTES|                   /* 0x80 */ \
                               READ_CONTROL_ACCESS|WRITE_DAC_ACCESS|\
                               WRITE_OWNER_ACCESS                      /* 0xe0000 */

#if 0
#define THIRD_DESIRED_ACCESS   FILE_READ_ATTRIBUTES|                   /* 0x80 */ \
                               READ_CONTROL_ACCESS|WRITE_DAC_ACCESS|\
                               FILE_READ_DATA|\
                               WRITE_OWNER_ACCESS                      /* */
#endif

/*
  Test ntcreate calls made by xcopy
 */
static bool run_xcopy(int dummy)
{
	static struct cli_state *cli1;
	const char *fname = "\\test.txt";
	bool correct = True;
	uint16_t fnum1, fnum2;
	NTSTATUS status;

	printf("starting xcopy test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	status = cli_ntcreate(cli1, fname, 0, FIRST_DESIRED_ACCESS,
			      FILE_ATTRIBUTE_ARCHIVE, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0x4044, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("First open failed - %s\n", nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli1, fname, 0, SECOND_DESIRED_ACCESS, 0,
	                     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			     FILE_OPEN, 0x200000, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("second open failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}

	return correct;
}

/*
  Test rename on files open with share delete and no share delete.
 */
static bool run_rename(int dummy)
{
	static struct cli_state *cli1;
	const char *fname = "\\test.txt";
	const char *fname1 = "\\test1.txt";
	bool correct = True;
	uint16_t fnum1;
	uint16_t attr;
	NTSTATUS status;

	printf("starting rename test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("First open failed - %s\n", nt_errstr(status));
		return False;
	}

	status = cli_rename(cli1, fname, fname1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("First rename failed (SHARE_READ) (this is correct) - %s\n", nt_errstr(status));
	} else {
		printf("First rename succeeded (SHARE_READ) - this should have failed !\n");
		correct = False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close - 1 failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS, FILE_ATTRIBUTE_NORMAL,
#if 0
			      FILE_SHARE_DELETE|FILE_SHARE_NONE,
#else
			      FILE_SHARE_DELETE|FILE_SHARE_READ,
#endif
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Second open failed - %s\n", nt_errstr(status));
		return False;
	}

	status = cli_rename(cli1, fname, fname1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Second rename failed (SHARE_DELETE | SHARE_READ) - this should have succeeded - %s\n", nt_errstr(status));
		correct = False;
	} else {
		printf("Second rename succeeded (SHARE_DELETE | SHARE_READ)\n");
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close - 2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, READ_CONTROL_ACCESS,
	                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Third open failed - %s\n", nt_errstr(status));
		return False;
	}


#if 0
  {
	uint16_t fnum2;

	if (!NT_STATUS_IS_OK(cli_ntcreate(cli1, fname, 0, DELETE_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   FILE_SHARE_NONE, FILE_OVERWRITE_IF, 0, 0, &fnum2, NULL))) {
		printf("Fourth open failed - %s\n", cli_errstr(cli1));
		return False;
	}
	if (!NT_STATUS_IS_OK(cli_nt_delete_on_close(cli1, fnum2, true))) {
		printf("[8] setting delete_on_close on file failed !\n");
		return False;
	}

	if (!NT_STATUS_IS_OK(cli_close(cli1, fnum2))) {
		printf("close - 4 failed (%s)\n", cli_errstr(cli1));
		return False;
	}
  }
#endif

	status = cli_rename(cli1, fname, fname1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Third rename failed (SHARE_NONE) - this should have succeeded - %s\n", nt_errstr(status));
		correct = False;
	} else {
		printf("Third rename succeeded (SHARE_NONE)\n");
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close - 3 failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

        /*----*/

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
	                      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ | FILE_SHARE_WRITE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Fourth open failed - %s\n", nt_errstr(status));
		return False;
	}

	status = cli_rename(cli1, fname, fname1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Fourth rename failed (SHARE_READ | SHARE_WRITE) (this is correct) - %s\n", nt_errstr(status));
	} else {
		printf("Fourth rename succeeded (SHARE_READ | SHARE_WRITE) - this should have failed !\n");
		correct = False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close - 4 failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

        /*--*/

	status = cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS,
	                 FILE_ATTRIBUTE_NORMAL,
			 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			 FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Fifth open failed - %s\n", nt_errstr(status));
		return False;
	}

	status = cli_rename(cli1, fname, fname1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Fifth rename failed (SHARE_READ | SHARE_WRITE | SHARE_DELETE) - this should have succeeded - %s ! \n", nt_errstr(status));
		correct = False;
	} else {
		printf("Fifth rename succeeded (SHARE_READ | SHARE_WRITE | SHARE_DELETE) (this is correct) - %s\n", nt_errstr(status));
	}

        /*
         * Now check if the first name still exists ...
         */

        /* if (!NT_STATUS_OP(cli_ntcreate(cli1, fname, 0, GENERIC_READ_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				   FILE_OVERWRITE_IF, 0, 0, &fnum2, NULL))) {
          printf("Opening original file after rename of open file fails: %s\n",
              cli_errstr(cli1));
        }
        else {
          printf("Opening original file after rename of open file works ...\n");
          (void)cli_close(cli1, fnum2);
          } */

        /*--*/
	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close - 5 failed (%s)\n", nt_errstr(status));
		return False;
	}

	/* Check that the renamed file has FILE_ATTRIBUTE_ARCHIVE. */
	status = cli_getatr(cli1, fname1, &attr, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("getatr on file %s failed - %s ! \n",
			fname1, nt_errstr(status));
		correct = False;
	} else {
		if (attr != FILE_ATTRIBUTE_ARCHIVE) {
			printf("Renamed file %s has wrong attr 0x%x "
				"(should be 0x%x)\n",
				fname1,
				attr,
				(unsigned int)FILE_ATTRIBUTE_ARCHIVE);
			correct = False;
		} else {
			printf("Renamed file %s has archive bit set\n", fname1);
		}
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli1, fname1, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}

	return correct;
}

static bool run_pipe_number(int dummy)
{
	struct cli_state *cli1;
	const char *pipe_name = "\\SPOOLSS";
	uint16_t fnum;
	int num_pipes = 0;
	NTSTATUS status;

	printf("starting pipenumber test\n");
	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);
	while(1) {
		status = cli_ntcreate(cli1, pipe_name, 0, FILE_READ_DATA,
				      FILE_ATTRIBUTE_NORMAL,
				      FILE_SHARE_READ|FILE_SHARE_WRITE,
				      FILE_OPEN_IF, 0, 0, &fnum, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Open of pipe %s failed with error (%s)\n", pipe_name, nt_errstr(status));
			break;
		}
		num_pipes++;
		printf("\r%6d", num_pipes);
	}

	printf("pipe_number test - we can open %d %s pipes.\n", num_pipes, pipe_name );
	torture_close_connection(cli1);
	return True;
}

/*
  Test open mode returns on read-only files.
 */
static bool run_opentest(int dummy)
{
	static struct cli_state *cli1;
	static struct cli_state *cli2;
	const char *fname = "\\readonly.file";
	uint16_t fnum1, fnum2;
	char buf[20];
	off_t fsize;
	bool correct = True;
	char *tmp_path;
	NTSTATUS status;

	printf("starting open test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_setatr(cli1, fname, FILE_ATTRIBUTE_READONLY, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_setatr failed (%s)\n", nt_errstr(status));
		return False;
	}

	status = cli_openx(cli1, fname, O_RDONLY, DENY_WRITE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	/* This will fail - but the error should be ERRnoaccess, not ERRbadshare. */
	status = cli_openx(cli1, fname, O_RDWR, DENY_ALL, &fnum2);

        if (check_error(__LINE__, status, ERRDOS, ERRnoaccess,
			NT_STATUS_ACCESS_DENIED)) {
		printf("correct error code ERRDOS/ERRnoaccess returned\n");
	}

	printf("finished open test 1\n");

	cli_close(cli1, fnum1);

	/* Now try not readonly and ensure ERRbadshare is returned. */

	cli_setatr(cli1, fname, 0, 0);

	status = cli_openx(cli1, fname, O_RDONLY, DENY_WRITE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	/* This will fail - but the error should be ERRshare. */
	status = cli_openx(cli1, fname, O_RDWR, DENY_ALL, &fnum2);

	if (check_error(__LINE__, status, ERRDOS, ERRbadshare,
			NT_STATUS_SHARING_VIOLATION)) {
		printf("correct error code ERRDOS/ERRbadshare returned\n");
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("finished open test 2\n");

	/* Test truncate open disposition on file opened for read. */
	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(3) open (1) of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	/* write 20 bytes. */

	memset(buf, '\0', 20);

	status = cli_writeall(cli1, fnum1, 0, (uint8_t *)buf, 0, 20, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write failed (%s)\n", nt_errstr(status));
		correct = False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(3) close1 failed (%s)\n", nt_errstr(status));
		return False;
	}

	/* Ensure size == 20. */
	status = cli_getatr(cli1, fname, NULL, &fsize, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(3) getatr failed (%s)\n", nt_errstr(status));
		return False;
	}

	if (fsize != 20) {
		printf("(3) file size != 20\n");
		return False;
	}

	/* Now test if we can truncate a file opened for readonly. */
	status = cli_openx(cli1, fname, O_RDONLY|O_TRUNC, DENY_NONE, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(3) open (2) of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close2 failed (%s)\n", nt_errstr(status));
		return False;
	}

	/* Ensure size == 0. */
	status = cli_getatr(cli1, fname, NULL, &fsize, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(3) getatr failed (%s)\n", nt_errstr(status));
		return False;
	}

	if (fsize != 0) {
		printf("(3) file size != 0\n");
		return False;
	}
	printf("finished open test 3\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("Do ctemp tests\n");
	status = cli_ctemp(cli1, talloc_tos(), "\\", &fnum1, &tmp_path);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ctemp failed (%s)\n", nt_errstr(status));
		return False;
	}

	printf("ctemp gave path %s\n", tmp_path);
	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close of temp failed (%s)\n", nt_errstr(status));
	}

	status = cli_unlink(cli1, tmp_path, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		printf("unlink of temp failed (%s)\n", nt_errstr(status));
	}

	/* Test the non-io opens... */

	if (!torture_open_connection(&cli2, 1)) {
		return False;
	}

	cli_setatr(cli2, fname, 0, 0);
	cli_unlink(cli2, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	smbXcli_conn_set_sockopt(cli2->conn, sockops);

	printf("TEST #1 testing 2 non-io opens (no delete)\n");
	status = cli_ntcreate(cli1, fname, 0, FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #1 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0, FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #1 open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #1 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #1 close 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #1 passed.\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("TEST #2 testing 2 non-io opens (first with delete)\n");

	status = cli_ntcreate(cli1, fname, 0,
	                      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #2 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0, FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #2 open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #2 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #2 close 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #2 passed.\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("TEST #3 testing 2 non-io opens (second with delete)\n");

	status = cli_ntcreate(cli1, fname, 0, FILE_READ_ATTRIBUTES,
	                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #3 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0,
	                      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #3 open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #3 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #3 close 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #3 passed.\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("TEST #4 testing 2 non-io opens (both with delete)\n");

	status = cli_ntcreate(cli1, fname, 0,
			       DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			       FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			       FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #4 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0,
			      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("TEST #4 open 2 of %s SUCCEEDED - should have failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("TEST #4 open 2 of %s gave %s (correct error should be %s)\n", fname, nt_errstr(status), "sharing violation");

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #4 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #4 passed.\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("TEST #5 testing 2 non-io opens (both with delete - both with file share delete)\n");

	status = cli_ntcreate(cli1, fname, 0,
	                      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #5 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0,
			      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #5 open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #5 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #5 close 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #5 passed.\n");

	printf("TEST #6 testing 1 non-io open, one io open\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, FILE_READ_DATA,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #6 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0, FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #6 open 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #6 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_close(cli2, fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #6 close 2 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #6 passed.\n");

	printf("TEST #7 testing 1 non-io open, one io open with delete\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli1, fname, 0, FILE_READ_DATA,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
			      FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #7 open 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_ntcreate(cli2, fname, 0,
			      DELETE_ACCESS|FILE_READ_ATTRIBUTES,
			      FILE_ATTRIBUTE_NORMAL,
			      FILE_SHARE_READ|FILE_SHARE_DELETE,
			      FILE_OPEN_IF, 0, 0, &fnum2, NULL);
	if (NT_STATUS_IS_OK(status)) {
		printf("TEST #7 open 2 of %s SUCCEEDED - should have failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("TEST #7 open 2 of %s gave %s (correct error should be %s)\n", fname, nt_errstr(status), "sharing violation");

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #7 close 1 of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	printf("non-io open test #7 passed.\n");

	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("TEST #8 testing open without WRITE_ATTRIBUTES, updating close write time.\n");
	status = cli_ntcreate(cli1, fname, 0, FILE_WRITE_DATA, FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
				FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #8 open of %s failed (%s)\n", fname, nt_errstr(status));
		correct = false;
		goto out;
	}

	/* Write to ensure we have to update the file time. */
	status = cli_writeall(cli1, fnum1, 0, (const uint8_t *)"TEST DATA\n", 0, 10,
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TEST #8 cli_write failed: %s\n", nt_errstr(status));
		correct = false;
		goto out;
	}

        status = cli_close(cli1, fnum1);
        if (!NT_STATUS_IS_OK(status)) {
                printf("TEST #8 close of %s failed (%s)\n", fname, nt_errstr(status));
		correct = false;
        }

  out:

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}

	return correct;
}

NTSTATUS torture_setup_unix_extensions(struct cli_state *cli)
{
	uint16 major, minor;
	uint32 caplow, caphigh;
	NTSTATUS status;

	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		printf("Server doesn't support UNIX CIFS extensions.\n");
		return NT_STATUS_NOT_SUPPORTED;
	}

	status = cli_unix_extensions_version(cli, &major, &minor, &caplow,
					     &caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Server didn't return UNIX CIFS extensions: %s\n",
		       nt_errstr(status));
		return status;
	}

	status = cli_set_unix_extensions_capabilities(cli, major, minor,
						      caplow, caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Server doesn't support setting UNIX CIFS extensions: "
		       "%s.\n", nt_errstr(status));
		return status;
        }

	return NT_STATUS_OK;
}

/*
  Test POSIX open /mkdir calls.
 */
static bool run_simple_posix_open_test(int dummy)
{
	static struct cli_state *cli1;
	const char *fname = "posix:file";
	const char *hname = "posix:hlink";
	const char *sname = "posix:symlink";
	const char *dname = "posix:dir";
	char buf[10];
	char namebuf[11];
	uint16_t fnum1 = (uint16_t)-1;
	SMB_STRUCT_STAT sbuf;
	bool correct = false;
	NTSTATUS status;
	size_t nread;
	const char *fname_windows = "windows_file";
	uint16_t fnum2 = (uint16_t)-1;

	printf("Starting simple POSIX open test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return false;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	status = torture_setup_unix_extensions(cli1);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	cli_setatr(cli1, fname, 0, 0);
	cli_posix_unlink(cli1, fname);
	cli_setatr(cli1, dname, 0, 0);
	cli_posix_rmdir(cli1, dname);
	cli_setatr(cli1, hname, 0, 0);
	cli_posix_unlink(cli1, hname);
	cli_setatr(cli1, sname, 0, 0);
	cli_posix_unlink(cli1, sname);
	cli_setatr(cli1, fname_windows, 0, 0);
	cli_posix_unlink(cli1, fname_windows);

	/* Create a directory. */
	status = cli_posix_mkdir(cli1, dname, 0777);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX mkdir of %s failed (%s)\n", dname, nt_errstr(status));
		goto out;
	}

	status = cli_posix_open(cli1, fname, O_RDWR|O_CREAT|O_EXCL,
				0600, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX create of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	/* Test ftruncate - set file size. */
	status = cli_ftruncate(cli1, fnum1, 1000);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ftruncate failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Ensure st_size == 1000 */
	status = cli_posix_stat(cli1, fname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("stat failed (%s)\n", nt_errstr(status));
		goto out;
	}

	if (sbuf.st_ex_size != 1000) {
		printf("ftruncate - stat size (%u) != 1000\n", (unsigned int)sbuf.st_ex_size);
		goto out;
	}

	/* Ensure st_mode == 0600 */
	if ((sbuf.st_ex_mode & 07777) != 0600) {
		printf("posix_open - bad permissions 0%o != 0600\n",
				(unsigned int)(sbuf.st_ex_mode & 07777));
		goto out;
	}

	/* Test ftruncate - set file size back to zero. */
	status = cli_ftruncate(cli1, fnum1, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ftruncate failed (%s)\n", nt_errstr(status));
		goto out;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Now open the file again for read only. */
	status = cli_posix_open(cli1, fname, O_RDONLY, 0, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX open of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	/* Now unlink while open. */
	status = cli_posix_unlink(cli1, fname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX unlink of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close(2) failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Ensure the file has gone. */
	status = cli_posix_open(cli1, fname, O_RDONLY, 0, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("POSIX open of %s succeeded, should have been deleted.\n", fname);
		goto out;
	}

	/* Create again to test open with O_TRUNC. */
	status = cli_posix_open(cli1, fname, O_RDWR|O_CREAT|O_EXCL, 0600, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX create of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	/* Test ftruncate - set file size. */
	status = cli_ftruncate(cli1, fnum1, 1000);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ftruncate failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Ensure st_size == 1000 */
	status = cli_posix_stat(cli1, fname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("stat failed (%s)\n", nt_errstr(status));
		goto out;
	}

	if (sbuf.st_ex_size != 1000) {
		printf("ftruncate - stat size (%u) != 1000\n", (unsigned int)sbuf.st_ex_size);
		goto out;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close(2) failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Re-open with O_TRUNC. */
	status = cli_posix_open(cli1, fname, O_WRONLY|O_TRUNC, 0600, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX create of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	/* Ensure st_size == 0 */
	status = cli_posix_stat(cli1, fname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("stat failed (%s)\n", nt_errstr(status));
		goto out;
	}

	if (sbuf.st_ex_size != 0) {
		printf("O_TRUNC - stat size (%u) != 0\n", (unsigned int)sbuf.st_ex_size);
		goto out;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed (%s)\n", nt_errstr(status));
		goto out;
	}

	status = cli_posix_unlink(cli1, fname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX unlink of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	status = cli_posix_open(cli1, dname, O_RDONLY, 0, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX open directory O_RDONLY of %s failed (%s)\n",
			dname, nt_errstr(status));
		goto out;
	}

	cli_close(cli1, fnum1);

	/* What happens when we try and POSIX open a directory for write ? */
	status = cli_posix_open(cli1, dname, O_RDWR, 0, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("POSIX open of directory %s succeeded, should have failed.\n", fname);
		goto out;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, EISDIR,
				NT_STATUS_FILE_IS_A_DIRECTORY)) {
			goto out;
		}
	}

	/* Create the file. */
	status = cli_posix_open(cli1, fname, O_RDWR|O_CREAT|O_EXCL,
				0600, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX create of %s failed (%s)\n", fname, nt_errstr(status));
		goto out;
	}

	/* Write some data into it. */
	status = cli_writeall(cli1, fnum1, 0, (const uint8_t *)"TEST DATA\n", 0, 10,
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_write failed: %s\n", nt_errstr(status));
		goto out;
	}

	cli_close(cli1, fnum1);

	/* Now create a hardlink. */
	status = cli_posix_hardlink(cli1, fname, hname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX hardlink of %s failed (%s)\n", hname, nt_errstr(status));
		goto out;
	}

	/* Now create a symlink. */
	status = cli_posix_symlink(cli1, fname, sname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX symlink of %s failed (%s)\n", sname, nt_errstr(status));
		goto out;
	}

	/* Open the hardlink for read. */
	status = cli_posix_open(cli1, hname, O_RDONLY, 0, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX open of %s failed (%s)\n", hname, nt_errstr(status));
		goto out;
	}

	status = cli_read(cli1, fnum1, buf, 0, 10, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX read of %s failed (%s)\n", hname,
		       nt_errstr(status));
		goto out;
	} else if (nread != 10) {
		printf("POSIX read of %s failed. Received %ld, expected %d\n",
		       hname, (unsigned long)nread, 10);
		goto out;
	}

	if (memcmp(buf, "TEST DATA\n", 10)) {
		printf("invalid data read from hardlink\n");
		goto out;
	}

	/* Do a POSIX lock/unlock. */
	status = cli_posix_lock(cli1, fnum1, 0, 100, true, READ_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX lock failed %s\n", nt_errstr(status));
		goto out;
	}

	/* Punch a hole in the locked area. */
	status = cli_posix_unlock(cli1, fnum1, 10, 80);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX unlock failed %s\n", nt_errstr(status));
		goto out;
	}

	cli_close(cli1, fnum1);

	/* Open the symlink for read - this should fail. A POSIX
	   client should not be doing opens on a symlink. */
	status = cli_posix_open(cli1, sname, O_RDONLY, 0, &fnum1);
	if (NT_STATUS_IS_OK(status)) {
		printf("POSIX open of %s succeeded (should have failed)\n", sname);
		goto out;
	} else {
		if (!check_both_error(__LINE__, status, ERRDOS, ERRbadpath,
				NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
			printf("POSIX open of %s should have failed "
				"with NT_STATUS_OBJECT_PATH_NOT_FOUND, "
				"failed with %s instead.\n",
				sname, nt_errstr(status));
			goto out;
		}
	}

	status = cli_posix_readlink(cli1, sname, namebuf, sizeof(namebuf));
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX readlink on %s failed (%s)\n", sname, nt_errstr(status));
		goto out;
	}

	if (strcmp(namebuf, fname) != 0) {
		printf("POSIX readlink on %s failed to match name %s (read %s)\n",
			sname, fname, namebuf);
		goto out;
	}

	status = cli_posix_rmdir(cli1, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX rmdir failed (%s)\n", nt_errstr(status));
		goto out;
	}

	/* Check directory opens with a specific permission. */
	status = cli_posix_mkdir(cli1, dname, 0700);
	if (!NT_STATUS_IS_OK(status)) {
		printf("POSIX mkdir of %s failed (%s)\n", dname, nt_errstr(status));
		goto out;
	}

	/* Ensure st_mode == 0700 */
	status = cli_posix_stat(cli1, dname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("stat failed (%s)\n", nt_errstr(status));
		goto out;
	}

	if ((sbuf.st_ex_mode & 07777) != 0700) {
		printf("posix_mkdir - bad permissions 0%o != 0700\n",
				(unsigned int)(sbuf.st_ex_mode & 07777));
		goto out;
	}

	/*
	 * Now create a Windows file, and attempt a POSIX unlink.
	 * This should fail with a sharing violation but due to:
	 *
	 * [Bug 9571] Unlink after open causes smbd to panic
	 *
	 * ensure we've fixed the lock ordering violation.
	 */

	status = cli_ntcreate(cli1, fname_windows, 0,
			FILE_READ_DATA|FILE_WRITE_DATA, 0,
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			FILE_CREATE,
			0x0, 0x0, &fnum2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Windows create of %s failed (%s)\n", fname_windows,
			nt_errstr(status));
		goto out;
	}

	/* Now try posix_unlink. */
	status = cli_posix_unlink(cli1, fname_windows);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		printf("POSIX unlink of %s should fail "
			"with NT_STATUS_SHARING_VIOLATION "
			"got %s instead !\n",
			fname_windows,
			nt_errstr(status));
		goto out;
	}

	cli_close(cli1, fnum2);

	printf("Simple POSIX open test passed\n");
	correct = true;

  out:

	if (fnum1 != (uint16_t)-1) {
		cli_close(cli1, fnum1);
		fnum1 = (uint16_t)-1;
	}

	if (fnum2 != (uint16_t)-1) {
		cli_close(cli1, fnum2);
		fnum2 = (uint16_t)-1;
	}

	cli_setatr(cli1, sname, 0, 0);
	cli_posix_unlink(cli1, sname);
	cli_setatr(cli1, hname, 0, 0);
	cli_posix_unlink(cli1, hname);
	cli_setatr(cli1, fname, 0, 0);
	cli_posix_unlink(cli1, fname);
	cli_setatr(cli1, dname, 0, 0);
	cli_posix_rmdir(cli1, dname);
	cli_setatr(cli1, fname_windows, 0, 0);
	cli_posix_unlink(cli1, fname_windows);

	if (!torture_close_connection(cli1)) {
		correct = false;
	}

	return correct;
}


static uint32 open_attrs_table[] = {
		FILE_ATTRIBUTE_NORMAL,
		FILE_ATTRIBUTE_ARCHIVE,
		FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,

		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,
		FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_SYSTEM,
};

struct trunc_open_results {
	unsigned int num;
	uint32 init_attr;
	uint32 trunc_attr;
	uint32 result_attr;
};

static struct trunc_open_results attr_results[] = {
	{ 0, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 1, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 2, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 16, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE },
	{ 17, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE },
	{ 18, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY },
	{ 51, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 54, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 56, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 68, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 71, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 73, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 99, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 102, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 104, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 116, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 119,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM,  FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 121, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM },
	{ 170, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN },
	{ 173, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM },
	{ 227, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 230, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_HIDDEN },
	{ 232, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN },
	{ 244, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 247, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_SYSTEM },
	{ 249, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM }
};

static bool run_openattrtest(int dummy)
{
	static struct cli_state *cli1;
	const char *fname = "\\openattr.file";
	uint16_t fnum1;
	bool correct = True;
	uint16 attr;
	unsigned int i, j, k, l;
	NTSTATUS status;

	printf("starting open attr test\n");

	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	for (k = 0, i = 0; i < sizeof(open_attrs_table)/sizeof(uint32); i++) {
		cli_setatr(cli1, fname, 0, 0);
		cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

		status = cli_ntcreate(cli1, fname, 0, FILE_WRITE_DATA,
				       open_attrs_table[i], FILE_SHARE_NONE,
				       FILE_OVERWRITE_IF, 0, 0, &fnum1, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("open %d (1) of %s failed (%s)\n", i, fname, nt_errstr(status));
			return False;
		}

		status = cli_close(cli1, fnum1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("close %d (1) of %s failed (%s)\n", i, fname, nt_errstr(status));
			return False;
		}

		for (j = 0; j < sizeof(open_attrs_table)/sizeof(uint32); j++) {
			status = cli_ntcreate(cli1, fname, 0,
					      FILE_READ_DATA|FILE_WRITE_DATA,
					      open_attrs_table[j],
					      FILE_SHARE_NONE, FILE_OVERWRITE,
					      0, 0, &fnum1, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				for (l = 0; l < sizeof(attr_results)/sizeof(struct trunc_open_results); l++) {
					if (attr_results[l].num == k) {
						printf("[%d] trunc open 0x%x -> 0x%x of %s failed - should have succeeded !(0x%x:%s)\n",
								k, open_attrs_table[i],
								open_attrs_table[j],
								fname, NT_STATUS_V(status), nt_errstr(status));
						correct = False;
					}
				}

				if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
					printf("[%d] trunc open 0x%x -> 0x%x failed with wrong error code %s\n",
							k, open_attrs_table[i], open_attrs_table[j],
							nt_errstr(status));
					correct = False;
				}
#if 0
				printf("[%d] trunc open 0x%x -> 0x%x failed\n", k, open_attrs_table[i], open_attrs_table[j]);
#endif
				k++;
				continue;
			}

			status = cli_close(cli1, fnum1);
			if (!NT_STATUS_IS_OK(status)) {
				printf("close %d (2) of %s failed (%s)\n", j, fname, nt_errstr(status));
				return False;
			}

			status = cli_getatr(cli1, fname, &attr, NULL, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				printf("getatr(2) failed (%s)\n", nt_errstr(status));
				return False;
			}

#if 0
			printf("[%d] getatr check [0x%x] trunc [0x%x] got attr 0x%x\n",
					k,  open_attrs_table[i],  open_attrs_table[j], attr );
#endif

			for (l = 0; l < sizeof(attr_results)/sizeof(struct trunc_open_results); l++) {
				if (attr_results[l].num == k) {
					if (attr != attr_results[l].result_attr ||
							open_attrs_table[i] != attr_results[l].init_attr ||
							open_attrs_table[j] != attr_results[l].trunc_attr) {
						printf("getatr check failed. [0x%x] trunc [0x%x] got attr 0x%x, should be 0x%x\n",
						open_attrs_table[i],
						open_attrs_table[j],
						(unsigned int)attr,
						attr_results[l].result_attr);
						correct = False;
					}
					break;
				}
			}
			k++;
		}
	}

	cli_setatr(cli1, fname, 0, 0);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	printf("open attr test %s.\n", correct ? "passed" : "failed");

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	return correct;
}

static NTSTATUS list_fn(const char *mnt, struct file_info *finfo,
		    const char *name, void *state)
{
	int *matched = (int *)state;
	if (matched != NULL) {
		*matched += 1;
	}
	return NT_STATUS_OK;
}

/*
  test directory listing speed
 */
static bool run_dirtest(int dummy)
{
	int i;
	static struct cli_state *cli;
	uint16_t fnum;
	struct timeval core_start;
	bool correct = True;
	int matched;

	printf("starting directory test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	srandom(0);
	for (i=0;i<torture_numops;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "\\%x", (int)random());
		if (!NT_STATUS_IS_OK(cli_openx(cli, fname, O_RDWR|O_CREAT, DENY_NONE, &fnum))) {
			fprintf(stderr,"Failed to open %s\n", fname);
			return False;
		}
		cli_close(cli, fnum);
	}

	core_start = timeval_current();

	matched = 0;
	cli_list(cli, "a*.*", 0, list_fn, &matched);
	printf("Matched %d\n", matched);

	matched = 0;
	cli_list(cli, "b*.*", 0, list_fn, &matched);
	printf("Matched %d\n", matched);

	matched = 0;
	cli_list(cli, "xyzabc", 0, list_fn, &matched);
	printf("Matched %d\n", matched);

	printf("dirtest core %g seconds\n", timeval_elapsed(&core_start));

	srandom(0);
	for (i=0;i<torture_numops;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "\\%x", (int)random());
		cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	}

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("finished dirtest\n");

	return correct;
}

static NTSTATUS del_fn(const char *mnt, struct file_info *finfo, const char *mask,
		   void *state)
{
	struct cli_state *pcli = (struct cli_state *)state;
	fstring fname;
	slprintf(fname, sizeof(fname), "\\LISTDIR\\%s", finfo->name);

	if (strcmp(finfo->name, ".") == 0 || strcmp(finfo->name, "..") == 0)
		return NT_STATUS_OK;

	if (finfo->mode & FILE_ATTRIBUTE_DIRECTORY) {
		if (!NT_STATUS_IS_OK(cli_rmdir(pcli, fname)))
			printf("del_fn: failed to rmdir %s\n,", fname );
	} else {
		if (!NT_STATUS_IS_OK(cli_unlink(pcli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)))
			printf("del_fn: failed to unlink %s\n,", fname );
	}
	return NT_STATUS_OK;
}


/*
  sees what IOCTLs are supported
 */
bool torture_ioctl_test(int dummy)
{
	static struct cli_state *cli;
	uint16_t device, function;
	uint16_t fnum;
	const char *fname = "\\ioctl.dat";
	DATA_BLOB blob;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	printf("starting ioctl test\n");

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_openx(cli, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return False;
	}

	status = cli_raw_ioctl(cli, fnum, 0x2d0000 | (0x0420<<2), &blob);
	printf("ioctl device info: %s\n", nt_errstr(status));

	status = cli_raw_ioctl(cli, fnum, IOCTL_QUERY_JOB_INFO, &blob);
	printf("ioctl job info: %s\n", nt_errstr(status));

	for (device=0;device<0x100;device++) {
		printf("ioctl test with device = 0x%x\n", device);
		for (function=0;function<0x100;function++) {
			uint32 code = (device<<16) | function;

			status = cli_raw_ioctl(cli, fnum, code, &blob);

			if (NT_STATUS_IS_OK(status)) {
				printf("ioctl 0x%x OK : %d bytes\n", (int)code,
				       (int)blob.length);
				data_blob_free(&blob);
			}
		}
	}

	if (!torture_close_connection(cli)) {
		return False;
	}

	return True;
}


/*
  tries varients of chkpath
 */
bool torture_chkpath_test(int dummy)
{
	static struct cli_state *cli;
	uint16_t fnum;
	bool ret;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	printf("starting chkpath test\n");

	/* cleanup from an old run */
	cli_rmdir(cli, "\\chkpath.dir\\dir2");
	cli_unlink(cli, "\\chkpath.dir\\*", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, "\\chkpath.dir");

	status = cli_mkdir(cli, "\\chkpath.dir");
	if (!NT_STATUS_IS_OK(status)) {
		printf("mkdir1 failed : %s\n", nt_errstr(status));
		return False;
	}

	status = cli_mkdir(cli, "\\chkpath.dir\\dir2");
	if (!NT_STATUS_IS_OK(status)) {
		printf("mkdir2 failed : %s\n", nt_errstr(status));
		return False;
	}

	status = cli_openx(cli, "\\chkpath.dir\\foo.txt", O_RDWR|O_CREAT|O_EXCL,
			  DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open1 failed (%s)\n", nt_errstr(status));
		return False;
	}
	cli_close(cli, fnum);

	status = cli_chkpath(cli, "\\chkpath.dir");
	if (!NT_STATUS_IS_OK(status)) {
		printf("chkpath1 failed: %s\n", nt_errstr(status));
		ret = False;
	}

	status = cli_chkpath(cli, "\\chkpath.dir\\dir2");
	if (!NT_STATUS_IS_OK(status)) {
		printf("chkpath2 failed: %s\n", nt_errstr(status));
		ret = False;
	}

	status = cli_chkpath(cli, "\\chkpath.dir\\foo.txt");
	if (!NT_STATUS_IS_OK(status)) {
		ret = check_error(__LINE__, status, ERRDOS, ERRbadpath,
				  NT_STATUS_NOT_A_DIRECTORY);
	} else {
		printf("* chkpath on a file should fail\n");
		ret = False;
	}

	status = cli_chkpath(cli, "\\chkpath.dir\\bar.txt");
	if (!NT_STATUS_IS_OK(status)) {
		ret = check_error(__LINE__, status, ERRDOS, ERRbadfile,
				  NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		printf("* chkpath on a non existent file should fail\n");
		ret = False;
	}

	status = cli_chkpath(cli, "\\chkpath.dir\\dirxx\\bar.txt");
	if (!NT_STATUS_IS_OK(status)) {
		ret = check_error(__LINE__, status, ERRDOS, ERRbadpath,
				  NT_STATUS_OBJECT_PATH_NOT_FOUND);
	} else {
		printf("* chkpath on a non existent component should fail\n");
		ret = False;
	}

	cli_rmdir(cli, "\\chkpath.dir\\dir2");
	cli_unlink(cli, "\\chkpath.dir\\*", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, "\\chkpath.dir");

	if (!torture_close_connection(cli)) {
		return False;
	}

	return ret;
}

static bool run_eatest(int dummy)
{
	static struct cli_state *cli;
	const char *fname = "\\eatest.txt";
	bool correct = True;
	uint16_t fnum;
	int i;
	size_t num_eas;
	struct ea_struct *ea_list = NULL;
	TALLOC_CTX *mem_ctx = talloc_init("eatest");
	NTSTATUS status;

	printf("starting eatest\n");

	if (!torture_open_connection(&cli, 0)) {
		talloc_destroy(mem_ctx);
		return False;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli, fname, 0,
                              FIRST_DESIRED_ACCESS, FILE_ATTRIBUTE_ARCHIVE,
                              FILE_SHARE_NONE, FILE_OVERWRITE_IF,
                              0x4044, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open failed - %s\n", nt_errstr(status));
		talloc_destroy(mem_ctx);
		return False;
	}

	for (i = 0; i < 10; i++) {
		fstring ea_name, ea_val;

		slprintf(ea_name, sizeof(ea_name), "EA_%d", i);
		memset(ea_val, (char)i+1, i+1);
		status = cli_set_ea_fnum(cli, fnum, ea_name, ea_val, i+1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("ea_set of name %s failed - %s\n", ea_name,
			       nt_errstr(status));
			talloc_destroy(mem_ctx);
			return False;
		}
	}

	cli_close(cli, fnum);
	for (i = 0; i < 10; i++) {
		fstring ea_name, ea_val;

		slprintf(ea_name, sizeof(ea_name), "EA_%d", i+10);
		memset(ea_val, (char)i+1, i+1);
		status = cli_set_ea_path(cli, fname, ea_name, ea_val, i+1);
		if (!NT_STATUS_IS_OK(status)) {
			printf("ea_set of name %s failed - %s\n", ea_name,
			       nt_errstr(status));
			talloc_destroy(mem_ctx);
			return False;
		}
	}

	status = cli_get_ea_list_path(cli, fname, mem_ctx, &num_eas, &ea_list);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ea_get list failed - %s\n", nt_errstr(status));
		correct = False;
	}

	printf("num_eas = %d\n", (int)num_eas);

	if (num_eas != 20) {
		printf("Should be 20 EA's stored... failing.\n");
		correct = False;
	}

	for (i = 0; i < num_eas; i++) {
		printf("%d: ea_name = %s. Val = ", i, ea_list[i].name);
		dump_data(0, ea_list[i].value.data,
			  ea_list[i].value.length);
	}

	/* Setting EA's to zero length deletes them. Test this */
	printf("Now deleting all EA's - case indepenent....\n");

#if 1
	cli_set_ea_path(cli, fname, "", "", 0);
#else
	for (i = 0; i < 20; i++) {
		fstring ea_name;
		slprintf(ea_name, sizeof(ea_name), "ea_%d", i);
		status = cli_set_ea_path(cli, fname, ea_name, "", 0);
		if (!NT_STATUS_IS_OK(status)) {
			printf("ea_set of name %s failed - %s\n", ea_name,
			       nt_errstr(status));
			talloc_destroy(mem_ctx);
			return False;
		}
	}
#endif

	status = cli_get_ea_list_path(cli, fname, mem_ctx, &num_eas, &ea_list);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ea_get list failed - %s\n", nt_errstr(status));
		correct = False;
	}

	printf("num_eas = %d\n", (int)num_eas);
	for (i = 0; i < num_eas; i++) {
		printf("%d: ea_name = %s. Val = ", i, ea_list[i].name);
		dump_data(0, ea_list[i].value.data,
			  ea_list[i].value.length);
	}

	if (num_eas != 0) {
		printf("deleting EA's failed.\n");
		correct = False;
	}

	/* Try and delete a non existent EA. */
	status = cli_set_ea_path(cli, fname, "foo", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("deleting non-existent EA 'foo' should succeed. %s\n",
		       nt_errstr(status));
		correct = False;
	}

	talloc_destroy(mem_ctx);
	if (!torture_close_connection(cli)) {
		correct = False;
	}

	return correct;
}

static bool run_dirtest1(int dummy)
{
	int i;
	static struct cli_state *cli;
	uint16_t fnum;
	int num_seen;
	bool correct = True;

	printf("starting directory test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	cli_list(cli, "\\LISTDIR\\*", 0, del_fn, cli);
	cli_list(cli, "\\LISTDIR\\*", FILE_ATTRIBUTE_DIRECTORY, del_fn, cli);
	cli_rmdir(cli, "\\LISTDIR");
	cli_mkdir(cli, "\\LISTDIR");

	/* Create 1000 files and 1000 directories. */
	for (i=0;i<1000;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "\\LISTDIR\\f%d", i);
		if (!NT_STATUS_IS_OK(cli_ntcreate(cli, fname, 0, GENERIC_ALL_ACCESS, FILE_ATTRIBUTE_ARCHIVE,
				   FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
				   0, 0, &fnum, NULL))) {
			fprintf(stderr,"Failed to open %s\n", fname);
			return False;
		}
		cli_close(cli, fnum);
	}
	for (i=0;i<1000;i++) {
		fstring fname;
		slprintf(fname, sizeof(fname), "\\LISTDIR\\d%d", i);
		if (!NT_STATUS_IS_OK(cli_mkdir(cli, fname))) {
			fprintf(stderr,"Failed to open %s\n", fname);
			return False;
		}
	}

	/* Now ensure that doing an old list sees both files and directories. */
	num_seen = 0;
	cli_list_old(cli, "\\LISTDIR\\*", FILE_ATTRIBUTE_DIRECTORY, list_fn, &num_seen);
	printf("num_seen = %d\n", num_seen );
	/* We should see 100 files + 1000 directories + . and .. */
	if (num_seen != 2002)
		correct = False;

	/* Ensure if we have the "must have" bits we only see the
	 * relevent entries.
	 */
	num_seen = 0;
	cli_list_old(cli, "\\LISTDIR\\*", (FILE_ATTRIBUTE_DIRECTORY<<8)|FILE_ATTRIBUTE_DIRECTORY, list_fn, &num_seen);
	printf("num_seen = %d\n", num_seen );
	if (num_seen != 1002)
		correct = False;

	num_seen = 0;
	cli_list_old(cli, "\\LISTDIR\\*", (FILE_ATTRIBUTE_ARCHIVE<<8)|FILE_ATTRIBUTE_DIRECTORY, list_fn, &num_seen);
	printf("num_seen = %d\n", num_seen );
	if (num_seen != 1000)
		correct = False;

	/* Delete everything. */
	cli_list(cli, "\\LISTDIR\\*", 0, del_fn, cli);
	cli_list(cli, "\\LISTDIR\\*", FILE_ATTRIBUTE_DIRECTORY, del_fn, cli);
	cli_rmdir(cli, "\\LISTDIR");

#if 0
	printf("Matched %d\n", cli_list(cli, "a*.*", 0, list_fn, NULL));
	printf("Matched %d\n", cli_list(cli, "b*.*", 0, list_fn, NULL));
	printf("Matched %d\n", cli_list(cli, "xyzabc", 0, list_fn, NULL));
#endif

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("finished dirtest1\n");

	return correct;
}

static bool run_error_map_extract(int dummy) {

	static struct cli_state *c_dos;
	static struct cli_state *c_nt;
	NTSTATUS status;

	uint32 error;

	uint32 errnum;
        uint8 errclass;

	NTSTATUS nt_status;

	fstring user;

	/* NT-Error connection */

	disable_spnego = true;
	if (!(c_nt = open_nbt_connection())) {
		disable_spnego = false;
		return False;
	}
	disable_spnego = false;

	status = smbXcli_negprot(c_nt->conn, c_nt->timeout, PROTOCOL_CORE,
				 PROTOCOL_NT1);

	if (!NT_STATUS_IS_OK(status)) {
		printf("%s rejected the NT-error negprot (%s)\n", host,
		       nt_errstr(status));
		cli_shutdown(c_nt);
		return False;
	}

	status = cli_session_setup(c_nt, "", "", 0, "", 0, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s rejected the NT-error initial session setup (%s)\n",host, nt_errstr(status));
		return False;
	}

	/* DOS-Error connection */

	disable_spnego = true;
	force_dos_errors = true;
	if (!(c_dos = open_nbt_connection())) {
		disable_spnego = false;
		force_dos_errors = false;
		return False;
	}
	disable_spnego = false;
	force_dos_errors = false;

	status = smbXcli_negprot(c_dos->conn, c_dos->timeout, PROTOCOL_CORE,
				 PROTOCOL_NT1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s rejected the DOS-error negprot (%s)\n", host,
		       nt_errstr(status));
		cli_shutdown(c_dos);
		return False;
	}

	status = cli_session_setup(c_dos, "", "", 0, "", 0, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s rejected the DOS-error initial session setup (%s)\n",
			host, nt_errstr(status));
		return False;
	}

	c_nt->map_dos_errors = false;
	c_dos->map_dos_errors = false;

	for (error=(0xc0000000 | 0x1); error < (0xc0000000| 0xFFF); error++) {
		fstr_sprintf(user, "%X", error);

		status = cli_session_setup(c_nt, user,
					   password, strlen(password),
					   password, strlen(password),
					   workgroup);
		if (NT_STATUS_IS_OK(status)) {
			printf("/** Session setup succeeded.  This shouldn't happen...*/\n");
		}

		/* Case #1: 32-bit NT errors */
		if (!NT_STATUS_IS_DOS(status)) {
			nt_status = status;
		} else {
			printf("/** Dos error on NT connection! (%s) */\n", 
			       nt_errstr(status));
			nt_status = NT_STATUS(0xc0000000);
		}

		status = cli_session_setup(c_dos, user,
					   password, strlen(password),
					   password, strlen(password),
					   workgroup);
		if (NT_STATUS_IS_OK(status)) {
			printf("/** Session setup succeeded.  This shouldn't happen...*/\n");
		}

		/* Case #1: 32-bit NT errors */
		if (NT_STATUS_IS_DOS(status)) {
			printf("/** NT error on DOS connection! (%s) */\n", 
			       nt_errstr(status));
			errnum = errclass = 0;
		} else {
			errclass = NT_STATUS_DOS_CLASS(status);
			errnum = NT_STATUS_DOS_CODE(status);
		}

		if (NT_STATUS_V(nt_status) != error) { 
			printf("/*\t{ This NT error code was 'sqashed'\n\t from %s to %s \n\t during the session setup }\n*/\n", 
			       get_nt_error_c_code(talloc_tos(), NT_STATUS(error)), 
			       get_nt_error_c_code(talloc_tos(), nt_status));
		}

		printf("\t{%s,\t%s,\t%s},\n", 
		       smb_dos_err_class(errclass), 
		       smb_dos_err_name(errclass, errnum), 
		       get_nt_error_c_code(talloc_tos(), NT_STATUS(error)));
	}
	return True;
}

static bool run_sesssetup_bench(int dummy)
{
	static struct cli_state *c;
	const char *fname = "\\file.dat";
	uint16_t fnum;
	NTSTATUS status;
	int i;

	if (!torture_open_connection(&c, 0)) {
		return false;
	}

	status = cli_ntcreate(c, fname, 0, GENERIC_ALL_ACCESS|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			      FILE_DELETE_ON_CLOSE, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("open %s failed: %s\n", fname, nt_errstr(status));
		return false;
	}

	for (i=0; i<torture_numops; i++) {
		status = cli_session_setup(
			c, username,
			password, strlen(password),
			password, strlen(password),
			workgroup);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("(%s) cli_session_setup failed: %s\n",
				 __location__, nt_errstr(status));
			return false;
		}

		d_printf("\r%d   ", (int)cli_state_get_uid(c));

		status = cli_ulogoff(c);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("(%s) cli_ulogoff failed: %s\n",
				 __location__, nt_errstr(status));
			return false;
		}
	}

	return true;
}

static bool subst_test(const char *str, const char *user, const char *domain,
		       uid_t uid, gid_t gid, const char *expected)
{
	char *subst;
	bool result = true;

	subst = talloc_sub_specified(talloc_tos(), str, user, NULL, domain, uid, gid);

	if (strcmp(subst, expected) != 0) {
		printf("sub_specified(%s, %s, %s, %d, %d) returned [%s], expected "
		       "[%s]\n", str, user, domain, (int)uid, (int)gid, subst,
		       expected);
		result = false;
	}

	TALLOC_FREE(subst);
	return result;
}

static void chain1_open_completion(struct tevent_req *req)
{
	uint16_t fnum;
	NTSTATUS status;
	status = cli_openx_recv(req, &fnum);
	TALLOC_FREE(req);

	d_printf("cli_openx_recv returned %s: %d\n",
		 nt_errstr(status),
		 NT_STATUS_IS_OK(status) ? fnum : -1);
}

static void chain1_write_completion(struct tevent_req *req)
{
	size_t written;
	NTSTATUS status;
	status = cli_write_andx_recv(req, &written);
	TALLOC_FREE(req);

	d_printf("cli_write_andx_recv returned %s: %d\n",
		 nt_errstr(status),
		 NT_STATUS_IS_OK(status) ? (int)written : -1);
}

static void chain1_close_completion(struct tevent_req *req)
{
	NTSTATUS status;
	bool *done = (bool *)tevent_req_callback_data_void(req);

	status = cli_close_recv(req);
	*done = true;

	TALLOC_FREE(req);

	d_printf("cli_close returned %s\n", nt_errstr(status));
}

static bool run_chain1(int dummy)
{
	struct cli_state *cli1;
	struct tevent_context *evt = samba_tevent_context_init(NULL);
	struct tevent_req *reqs[3], *smbreqs[3];
	bool done = false;
	const char *str = "foobar";
	NTSTATUS status;

	printf("starting chain1 test\n");
	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	reqs[0] = cli_openx_create(talloc_tos(), evt, cli1, "\\test",
				  O_CREAT|O_RDWR, 0, &smbreqs[0]);
	if (reqs[0] == NULL) return false;
	tevent_req_set_callback(reqs[0], chain1_open_completion, NULL);


	reqs[1] = cli_write_andx_create(talloc_tos(), evt, cli1, 0, 0,
					(const uint8_t *)str, 0, strlen(str)+1,
					smbreqs, 1, &smbreqs[1]);
	if (reqs[1] == NULL) return false;
	tevent_req_set_callback(reqs[1], chain1_write_completion, NULL);

	reqs[2] = cli_close_create(talloc_tos(), evt, cli1, 0, &smbreqs[2]);
	if (reqs[2] == NULL) return false;
	tevent_req_set_callback(reqs[2], chain1_close_completion, &done);

	status = smb1cli_req_chain_submit(smbreqs, ARRAY_SIZE(smbreqs));
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	while (!done) {
		tevent_loop_once(evt);
	}

	torture_close_connection(cli1);
	return True;
}

static void chain2_sesssetup_completion(struct tevent_req *req)
{
	NTSTATUS status;
	status = cli_session_setup_guest_recv(req);
	d_printf("sesssetup returned %s\n", nt_errstr(status));
}

static void chain2_tcon_completion(struct tevent_req *req)
{
	bool *done = (bool *)tevent_req_callback_data_void(req);
	NTSTATUS status;
	status = cli_tcon_andx_recv(req);
	d_printf("tcon_and_x returned %s\n", nt_errstr(status));
	*done = true;
}

static bool run_chain2(int dummy)
{
	struct cli_state *cli1;
	struct tevent_context *evt = samba_tevent_context_init(NULL);
	struct tevent_req *reqs[2], *smbreqs[2];
	bool done = false;
	NTSTATUS status;

	printf("starting chain2 test\n");
	status = cli_start_connection(&cli1, lp_netbios_name(), host, NULL,
				      port_to_use, SMB_SIGNING_DEFAULT, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	reqs[0] = cli_session_setup_guest_create(talloc_tos(), evt, cli1,
						 &smbreqs[0]);
	if (reqs[0] == NULL) return false;
	tevent_req_set_callback(reqs[0], chain2_sesssetup_completion, NULL);

	reqs[1] = cli_tcon_andx_create(talloc_tos(), evt, cli1, "IPC$",
				       "?????", NULL, 0, &smbreqs[1]);
	if (reqs[1] == NULL) return false;
	tevent_req_set_callback(reqs[1], chain2_tcon_completion, &done);

	status = smb1cli_req_chain_submit(smbreqs, ARRAY_SIZE(smbreqs));
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	while (!done) {
		tevent_loop_once(evt);
	}

	torture_close_connection(cli1);
	return True;
}


struct torture_createdel_state {
	struct tevent_context *ev;
	struct cli_state *cli;
};

static void torture_createdel_created(struct tevent_req *subreq);
static void torture_createdel_closed(struct tevent_req *subreq);

static struct tevent_req *torture_createdel_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct cli_state *cli,
						 const char *name)
{
	struct tevent_req *req, *subreq;
	struct torture_createdel_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct torture_createdel_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	subreq = cli_ntcreate_send(
		state, ev, cli, name, 0,
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN_IF, FILE_DELETE_ON_CLOSE, 0);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, torture_createdel_created, req);
	return req;
}

static void torture_createdel_created(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct torture_createdel_state *state = tevent_req_data(
		req, struct torture_createdel_state);
	NTSTATUS status;
	uint16_t fnum;

	status = cli_ntcreate_recv(subreq, &fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DEBUG(10, ("cli_ntcreate_recv returned %s\n",
			   nt_errstr(status)));
		return;
	}

	subreq = cli_close_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, torture_createdel_closed, req);
}

static void torture_createdel_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		DEBUG(10, ("cli_close_recv returned %s\n", nt_errstr(status)));
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS torture_createdel_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct torture_createdels_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *base_name;
	int sent;
	int received;
	int num_files;
	struct tevent_req **reqs;
};

static void torture_createdels_done(struct tevent_req *subreq);

static struct tevent_req *torture_createdels_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct cli_state *cli,
						  const char *base_name,
						  int num_parallel,
						  int num_files)
{
	struct tevent_req *req;
	struct torture_createdels_state *state;
	int i;

	req = tevent_req_create(mem_ctx, &state,
				struct torture_createdels_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->base_name = talloc_strdup(state, base_name);
	if (tevent_req_nomem(state->base_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->num_files = MAX(num_parallel, num_files);
	state->sent = 0;
	state->received = 0;

	state->reqs = talloc_array(state, struct tevent_req *, num_parallel);
	if (tevent_req_nomem(state->reqs, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_parallel; i++) {
		char *name;

		name = talloc_asprintf(state, "%s%8.8d", state->base_name,
				       state->sent);
		if (tevent_req_nomem(name, req)) {
			return tevent_req_post(req, ev);
		}
		state->reqs[i] = torture_createdel_send(
			state->reqs, state->ev, state->cli, name);
		if (tevent_req_nomem(state->reqs[i], req)) {
			return tevent_req_post(req, ev);
		}
		name = talloc_move(state->reqs[i], &name);
		tevent_req_set_callback(state->reqs[i],
					torture_createdels_done, req);
		state->sent += 1;
	}
	return req;
}

static void torture_createdels_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct torture_createdels_state *state = tevent_req_data(
		req, struct torture_createdels_state);
	size_t num_parallel = talloc_array_length(state->reqs);
	NTSTATUS status;
	char *name;
	int i;

	status = torture_createdel_recv(subreq);
	if (!NT_STATUS_IS_OK(status)){
		DEBUG(10, ("torture_createdel_recv returned %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}

	for (i=0; i<num_parallel; i++) {
		if (subreq == state->reqs[i]) {
			break;
		}
	}
	if (i == num_parallel) {
		DEBUG(10, ("received something we did not send\n"));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	TALLOC_FREE(state->reqs[i]);

	if (state->sent >= state->num_files) {
		tevent_req_done(req);
		return;
	}

	name = talloc_asprintf(state, "%s%8.8d", state->base_name,
			       state->sent);
	if (tevent_req_nomem(name, req)) {
		return;
	}
	state->reqs[i] = torture_createdel_send(state->reqs, state->ev,
						state->cli, name);
	if (tevent_req_nomem(state->reqs[i], req)) {
		return;
	}
	name = talloc_move(state->reqs[i], &name);
	tevent_req_set_callback(state->reqs[i],	torture_createdels_done, req);
	state->sent += 1;
}

static NTSTATUS torture_createdels_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct swallow_notify_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;
	uint32_t completion_filter;
	bool recursive;
	bool (*fn)(uint32_t action, const char *name, void *priv);
	void *priv;
};

static void swallow_notify_done(struct tevent_req *subreq);

static struct tevent_req *swallow_notify_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct cli_state *cli,
					      uint16_t fnum,
					      uint32_t completion_filter,
					      bool recursive,
					      bool (*fn)(uint32_t action,
							 const char *name,
							 void *priv),
					      void *priv)
{
	struct tevent_req *req, *subreq;
	struct swallow_notify_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct swallow_notify_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fnum = fnum;
	state->completion_filter = completion_filter;
	state->recursive = recursive;
	state->fn = fn;
	state->priv = priv;

	subreq = cli_notify_send(state, state->ev, state->cli, state->fnum,
				 0xffff, state->completion_filter,
				 state->recursive);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, swallow_notify_done, req);
	return req;
}

static void swallow_notify_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct swallow_notify_state *state = tevent_req_data(
		req, struct swallow_notify_state);
	NTSTATUS status;
	uint32_t i, num_changes;
	struct notify_change *changes;

	status = cli_notify_recv(subreq, state, &num_changes, &changes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("cli_notify_recv returned %s\n",
			   nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	for (i=0; i<num_changes; i++) {
		state->fn(changes[i].action, changes[i].name, state->priv);
	}
	TALLOC_FREE(changes);

	subreq = cli_notify_send(state, state->ev, state->cli, state->fnum,
				 0xffff, state->completion_filter,
				 state->recursive);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, swallow_notify_done, req);
}

static bool print_notifies(uint32_t action, const char *name, void *priv)
{
	if (DEBUGLEVEL > 5) {
		d_printf("%d %s\n", (int)action, name);
	}
	return true;
}

static void notify_bench_done(struct tevent_req *req)
{
	int *num_finished = (int *)tevent_req_callback_data_void(req);
	*num_finished += 1;
}

static bool run_notify_bench(int dummy)
{
	const char *dname = "\\notify-bench";
	struct tevent_context *ev;
	NTSTATUS status;
	uint16_t dnum;
	struct tevent_req *req1;
	struct tevent_req *req2 = NULL;
	int i, num_unc_names;
	int num_finished = 0;

	printf("starting notify-bench test\n");

	if (use_multishare_conn) {
		char **unc_list;
		unc_list = file_lines_load(multishare_conn_fname,
					   &num_unc_names, 0, NULL);
		if (!unc_list || num_unc_names <= 0) {
			d_printf("Failed to load unc names list from '%s'\n",
				 multishare_conn_fname);
			return false;
		}
		TALLOC_FREE(unc_list);
	} else {
		num_unc_names = 1;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		d_printf("tevent_context_init failed\n");
		return false;
	}

	for (i=0; i<num_unc_names; i++) {
		struct cli_state *cli;
		char *base_fname;

		base_fname = talloc_asprintf(talloc_tos(), "%s\\file%3.3d.",
					     dname, i);
		if (base_fname == NULL) {
			return false;
		}

		if (!torture_open_connection(&cli, i)) {
			return false;
		}

		status = cli_ntcreate(cli, dname, 0,
				      MAXIMUM_ALLOWED_ACCESS,
				      0, FILE_SHARE_READ|FILE_SHARE_WRITE|
				      FILE_SHARE_DELETE,
				      FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0,
				      &dnum, NULL);

		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Could not create %s: %s\n", dname,
				 nt_errstr(status));
			return false;
		}

		req1 = swallow_notify_send(talloc_tos(), ev, cli, dnum,
					   FILE_NOTIFY_CHANGE_FILE_NAME |
					   FILE_NOTIFY_CHANGE_DIR_NAME |
					   FILE_NOTIFY_CHANGE_ATTRIBUTES |
					   FILE_NOTIFY_CHANGE_LAST_WRITE,
					   false, print_notifies, NULL);
		if (req1 == NULL) {
			d_printf("Could not create notify request\n");
			return false;
		}

		req2 = torture_createdels_send(talloc_tos(), ev, cli,
					       base_fname, 10, torture_numops);
		if (req2 == NULL) {
			d_printf("Could not create createdels request\n");
			return false;
		}
		TALLOC_FREE(base_fname);

		tevent_req_set_callback(req2, notify_bench_done,
					&num_finished);
	}

	while (num_finished < num_unc_names) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			d_printf("tevent_loop_once failed\n");
			return false;
		}
	}

	if (!tevent_req_poll(req2, ev)) {
		d_printf("tevent_req_poll failed\n");
	}

	status = torture_createdels_recv(req2);
	d_printf("torture_createdels_recv returned %s\n", nt_errstr(status));

	return true;
}

static bool run_mangle1(int dummy)
{
	struct cli_state *cli;
	const char *fname = "this_is_a_long_fname_to_be_mangled.txt";
	uint16_t fnum;
	fstring alt_name;
	NTSTATUS status;
	time_t change_time, access_time, write_time;
	off_t size;
	uint16_t mode;

	printf("starting mangle1 test\n");
	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	status = cli_ntcreate(cli, fname, 0, GENERIC_ALL_ACCESS|DELETE_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			      0, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("open %s failed: %s\n", fname, nt_errstr(status));
		return false;
	}
	cli_close(cli, fnum);

	status = cli_qpathinfo_alt_name(cli, fname, alt_name);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_qpathinfo_alt_name failed: %s\n",
			 nt_errstr(status));
		return false;
	}
	d_printf("alt_name: %s\n", alt_name);

	status = cli_openx(cli, alt_name, O_RDONLY, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_openx(%s) failed: %s\n", alt_name,
			 nt_errstr(status));
		return false;
	}
	cli_close(cli, fnum);

	status = cli_qpathinfo1(cli, alt_name, &change_time, &access_time,
				&write_time, &size, &mode);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_qpathinfo1(%s) failed: %s\n", alt_name,
			 nt_errstr(status));
		return false;
	}

	return true;
}

static size_t null_source(uint8_t *buf, size_t n, void *priv)
{
	size_t *to_pull = (size_t *)priv;
	size_t thistime = *to_pull;

	thistime = MIN(thistime, n);
	if (thistime == 0) {
		return 0;
	}

	memset(buf, 0, thistime);
	*to_pull -= thistime;
	return thistime;
}

static bool run_windows_write(int dummy)
{
	struct cli_state *cli1;
	uint16_t fnum;
	int i;
	bool ret = false;
	const char *fname = "\\writetest.txt";
	struct timeval start_time;
	double seconds;
	double kbytes;
	NTSTATUS status;

	printf("starting windows_write test\n");
	if (!torture_open_connection(&cli1, 0)) {
		return False;
	}

	status = cli_openx(cli1, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open failed (%s)\n", nt_errstr(status));
		return False;
	}

	smbXcli_conn_set_sockopt(cli1->conn, sockops);

	start_time = timeval_current();

	for (i=0; i<torture_numops; i++) {
		uint8_t c = 0;
		off_t start = i * torture_blocksize;
		size_t to_pull = torture_blocksize - 1;

		status = cli_writeall(cli1, fnum, 0, &c,
				      start + torture_blocksize - 1, 1, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("cli_write failed: %s\n", nt_errstr(status));
			goto fail;
		}

		status = cli_push(cli1, fnum, 0, i * torture_blocksize, torture_blocksize,
				  null_source, &to_pull);
		if (!NT_STATUS_IS_OK(status)) {
			printf("cli_push returned: %s\n", nt_errstr(status));
			goto fail;
		}
	}

	seconds = timeval_elapsed(&start_time);
	kbytes = (double)torture_blocksize * torture_numops;
	kbytes /= 1024;

	printf("Wrote %d kbytes in %.2f seconds: %d kb/sec\n", (int)kbytes,
	       (double)seconds, (int)(kbytes/seconds));

	ret = true;
 fail:
	cli_close(cli1, fnum);
	cli_unlink(cli1, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	torture_close_connection(cli1);
	return ret;
}

static size_t calc_expected_return(struct cli_state *cli, size_t len_requested)
{
	size_t max_pdu = 0x1FFFF;

	if (cli->server_posix_capabilities & CIFS_UNIX_LARGE_READ_CAP) {
		max_pdu = 0xFFFFFF;
	}

	if (smb1cli_conn_signing_is_active(cli->conn)) {
		max_pdu = 0x1FFFF;
	}

	if (smb1cli_conn_encryption_on(cli->conn)) {
		max_pdu = CLI_BUFFER_SIZE;
	}

	if ((len_requested & 0xFFFF0000) == 0xFFFF0000) {
		len_requested &= 0xFFFF;
	}

	return MIN(len_requested,
		   max_pdu - (MIN_SMB_SIZE + VWV(12) + 1 /* padding byte */));
}

static bool check_read_call(struct cli_state *cli,
			    uint16_t fnum,
			    uint8_t *buf,
			    size_t len_requested)
{
	NTSTATUS status;
	struct tevent_req *subreq = NULL;
	ssize_t len_read = 0;
	size_t len_expected = 0;
	struct tevent_context *ev = NULL;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		return false;
	}

	subreq = cli_read_andx_send(talloc_tos(),
				    ev,
				    cli,
				    fnum,
				    0,
				    len_requested);

	if (!tevent_req_poll_ntstatus(subreq, ev, &status)) {
		return false;
	}

	status = cli_read_andx_recv(subreq, &len_read, &buf);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_read_andx_recv failed: %s\n", nt_errstr(status));
		return false;
	}

	TALLOC_FREE(subreq);
	TALLOC_FREE(ev);

	len_expected = calc_expected_return(cli, len_requested);

	if (len_expected > 0x10000 && len_read == 0x10000) {
		/* Windows servers only return a max of 0x10000,
		   doesn't matter if you set CAP_LARGE_READX in
		   the client sessionsetupX call or not. */
		d_printf("Windows server - returned 0x10000 on a read of 0x%x\n",
			(unsigned int)len_requested);
	} else if (len_read != len_expected) {
		d_printf("read of 0x%x failed: got 0x%x, expected 0x%x\n",
			(unsigned int)len_requested,
			(unsigned int)len_read,
			(unsigned int)len_expected);
		return false;
	} else {
		d_printf("Correct read reply.\n");
	}

	return true;
}

/* Test large readX variants. */
static bool large_readx_tests(struct cli_state *cli,
				uint16_t fnum,
				uint8_t *buf)
{
	/* A read of 0xFFFF0001 should *always* return 1 byte. */
	if (check_read_call(cli, fnum, buf, 0xFFFF0001) == false) {
		return false;
	}
	/* A read of 0x10000 should return 0x10000 bytes. */
	if (check_read_call(cli, fnum, buf,    0x10000) == false) {
		return false;
	}
	/* A read of 0x10000 should return 0x10001 bytes. */
	if (check_read_call(cli, fnum, buf,    0x10001) == false) {
		return false;
	}
	/* A read of 0x1FFFF - (MIN_SMB_SIZE + VWV(12) should return
	   the requested number of bytes. */
	if (check_read_call(cli, fnum, buf, 0x1FFFF - (MIN_SMB_SIZE + VWV(12))) == false) {
		return false;
	}
	/* A read of 1MB should return 1MB bytes (on Samba). */
	if (check_read_call(cli, fnum, buf,   0x100000) == false) {
		return false;
	}

	if (check_read_call(cli, fnum, buf,    0x20001) == false) {
		return false;
	}
	if (check_read_call(cli, fnum, buf, 0x22000001) == false) {
		return false;
	}
	if (check_read_call(cli, fnum, buf, 0xFFFE0001) == false) {
		return false;
	}
	return true;
}

static bool run_large_readx(int dummy)
{
	uint8_t *buf = NULL;
	struct cli_state *cli1 = NULL;
	struct cli_state *cli2 = NULL;
	bool correct = false;
	const char *fname = "\\large_readx.dat";
	NTSTATUS status;
	uint16_t fnum1 = UINT16_MAX;
	uint32_t normal_caps = 0;
	size_t file_size = 20*1024*1024;
	TALLOC_CTX *frame = talloc_stackframe();
	size_t i;
	struct {
		const char *name;
		enum smb_signing_setting signing_setting;
		enum protocol_types protocol;
	} runs[] = {
		{
			.name = "NT1",
			.signing_setting = SMB_SIGNING_IF_REQUIRED,
			.protocol = PROTOCOL_NT1,
		},{
			.name = "NT1 - SIGNING_REQUIRED",
			.signing_setting = SMB_SIGNING_REQUIRED,
			.protocol = PROTOCOL_NT1,
		},
	};

	printf("starting large_readx test\n");

	if (!torture_open_connection(&cli1, 0)) {
		goto out;
	}

	normal_caps = smb1cli_conn_capabilities(cli1->conn);

	if (!(normal_caps & CAP_LARGE_READX)) {
		d_printf("Server doesn't have CAP_LARGE_READX 0x%x\n",
			(unsigned int)normal_caps);
		goto out;
	}

	/* Create a file of size 4MB. */
	status = cli_ntcreate(cli1, fname, 0, GENERIC_ALL_ACCESS,
			FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			0, 0, &fnum1, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("open %s failed: %s\n", fname, nt_errstr(status));
		goto out;
	}

	/* Write file_size bytes. */
	buf = talloc_zero_array(frame, uint8_t, file_size);
	if (buf == NULL) {
		goto out;
	}

	status = cli_writeall(cli1,
			      fnum1,
			      0,
			      buf,
			      0,
			      file_size,
			      NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_writeall failed: %s\n", nt_errstr(status));
		goto out;
	}

	status = cli_close(cli1, fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_close failed: %s\n", nt_errstr(status));
		goto out;
	}

	fnum1 = UINT16_MAX;

	for (i=0; i < ARRAY_SIZE(runs); i++) {
		enum smb_signing_setting saved_signing_setting = signing_state;
		uint16_t fnum2 = -1;

		if (do_encrypt &&
		    (runs[i].signing_setting == SMB_SIGNING_REQUIRED))
		{
			d_printf("skip[%u] - %s\n", (unsigned)i, runs[i].name);
			continue;
		}

		d_printf("run[%u] - %s\n", (unsigned)i, runs[i].name);

		signing_state = runs[i].signing_setting;
		cli2 = open_nbt_connection();
		signing_state = saved_signing_setting;
		if (cli2 == NULL) {
			goto out;
		}

		status = smbXcli_negprot(cli2->conn,
					 cli2->timeout,
					 runs[i].protocol,
					 runs[i].protocol);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = cli_session_setup(cli2,
					username,
					password,
					strlen(password)+1,
					password,
					strlen(password)+1,
					workgroup);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = cli_tree_connect(cli2,
					share,
					"?????",
					password,
					strlen(password)+1);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		cli_set_timeout(cli2, 120000); /* set a really long timeout (2 minutes) */

		normal_caps = smb1cli_conn_capabilities(cli2->conn);

		if (!(normal_caps & CAP_LARGE_READX)) {
			d_printf("Server doesn't have CAP_LARGE_READX 0x%x\n",
				(unsigned int)normal_caps);
			goto out;
		}

		if (do_encrypt) {
			if (force_cli_encryption(cli2, share) == false) {
				goto out;
			}
		} else if (SERVER_HAS_UNIX_CIFS(cli2)) {
			uint16_t major, minor;
			uint32_t caplow, caphigh;

			status = cli_unix_extensions_version(cli2,
							     &major, &minor,
							     &caplow, &caphigh);
			if (!NT_STATUS_IS_OK(status)) {
				goto out;
			}
		}

		status = cli_ntcreate(cli2, fname, 0, FILE_READ_DATA,
				FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
				0, 0, &fnum2, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Second open %s failed: %s\n", fname, nt_errstr(status));
			goto out;
		}

		/* All reads must return less than file_size bytes. */
		if (!large_readx_tests(cli2, fnum2, buf)) {
			goto out;
		}

		status = cli_close(cli2, fnum2);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("cli_close failed: %s\n", nt_errstr(status));
			goto out;
		}
		fnum2 = -1;

		if (!torture_close_connection(cli2)) {
			goto out;
		}
		cli2 = NULL;
	}

	correct = true;
	printf("Success on large_readx test\n");

  out:

	if (cli2) {
		if (!torture_close_connection(cli2)) {
			correct = false;
		}
	}

	if (cli1) {
		if (fnum1 != UINT16_MAX) {
			status = cli_close(cli1, fnum1);
			if (!NT_STATUS_IS_OK(status)) {
				d_printf("cli_close failed: %s\n", nt_errstr(status));
			}
			fnum1 = UINT16_MAX;
		}

		status = cli_unlink(cli1, fname,
				    FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			printf("unlink failed (%s)\n", nt_errstr(status));
		}

		if (!torture_close_connection(cli1)) {
			correct = false;
		}
	}

	TALLOC_FREE(frame);

	printf("finished large_readx test\n");
	return correct;
}

static bool run_cli_echo(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;

	printf("starting cli_echo test\n");
	if (!torture_open_connection(&cli, 0)) {
		return false;
	}
	smbXcli_conn_set_sockopt(cli->conn, sockops);

	status = cli_echo(cli, 5, data_blob_const("hello", 5));

	d_printf("cli_echo returned %s\n", nt_errstr(status));

	torture_close_connection(cli);
	return NT_STATUS_IS_OK(status);
}

static bool run_uid_regression_test(int dummy)
{
	static struct cli_state *cli;
	int16_t old_vuid;
	int16_t old_cnum;
	bool correct = True;
	NTSTATUS status;

	printf("starting uid regression test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	/* Ok - now save then logoff our current user. */
	old_vuid = cli_state_get_uid(cli);

	status = cli_ulogoff(cli);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("(%s) cli_ulogoff failed: %s\n",
			 __location__, nt_errstr(status));
		correct = false;
		goto out;
	}

	cli_state_set_uid(cli, old_vuid);

	/* Try an operation. */
	status = cli_mkdir(cli, "\\uid_reg_test");
	if (NT_STATUS_IS_OK(status)) {
		d_printf("(%s) cli_mkdir succeeded\n",
			 __location__);
		correct = false;
		goto out;
	} else {
		/* Should be bad uid. */
		if (!check_error(__LINE__, status, ERRSRV, ERRbaduid,
				 NT_STATUS_USER_SESSION_DELETED)) {
			correct = false;
			goto out;
		}
	}

	old_cnum = cli_state_get_tid(cli);

	/* Now try a SMBtdis with the invald vuid set to zero. */
	cli_state_set_uid(cli, 0);

	/* This should succeed. */
	status = cli_tdis(cli);

	if (NT_STATUS_IS_OK(status)) {
		d_printf("First tdis with invalid vuid should succeed.\n");
	} else {
		d_printf("First tdis failed (%s)\n", nt_errstr(status));
		correct = false;
		goto out;
	}

	cli_state_set_uid(cli, old_vuid);
	cli_state_set_tid(cli, old_cnum);

	/* This should fail. */
	status = cli_tdis(cli);
	if (NT_STATUS_IS_OK(status)) {
		d_printf("Second tdis with invalid vuid should fail - succeeded instead !.\n");
		correct = false;
		goto out;
	} else {
		/* Should be bad tid. */
		if (!check_error(__LINE__, status, ERRSRV, ERRinvnid,
				NT_STATUS_NETWORK_NAME_DELETED)) {
			correct = false;
			goto out;
		}
	}

	cli_rmdir(cli, "\\uid_reg_test");

  out:

	cli_shutdown(cli);
	return correct;
}


static const char *illegal_chars = "*\\/?<>|\":";
static char force_shortname_chars[] = " +,.[];=\177";

static NTSTATUS shortname_del_fn(const char *mnt, struct file_info *finfo,
			     const char *mask, void *state)
{
	struct cli_state *pcli = (struct cli_state *)state;
	fstring fname;
	NTSTATUS status = NT_STATUS_OK;

	slprintf(fname, sizeof(fname), "\\shortname\\%s", finfo->name);

	if (strcmp(finfo->name, ".") == 0 || strcmp(finfo->name, "..") == 0)
		return NT_STATUS_OK;

	if (finfo->mode & FILE_ATTRIBUTE_DIRECTORY) {
		status = cli_rmdir(pcli, fname);
		if (!NT_STATUS_IS_OK(status)) {
			printf("del_fn: failed to rmdir %s\n,", fname );
		}
	} else {
		status = cli_unlink(pcli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			printf("del_fn: failed to unlink %s\n,", fname );
		}
	}
	return status;
}

struct sn_state {
	int matched;
	int i;
	bool val;
};

static NTSTATUS shortname_list_fn(const char *mnt, struct file_info *finfo,
			      const char *name, void *state)
{
	struct sn_state *s = (struct sn_state  *)state;
	int i = s->i;

#if 0
	printf("shortname list: i = %d, name = |%s|, shortname = |%s|\n",
		i, finfo->name, finfo->short_name);
#endif

	if (strchr(force_shortname_chars, i)) {
		if (!finfo->short_name) {
			/* Shortname not created when it should be. */
			d_printf("(%s) ERROR: Shortname was not created for file %s containing %d\n",
				__location__, finfo->name, i);
			s->val = true;
		}
	} else if (finfo->short_name){
		/* Shortname created when it should not be. */
		d_printf("(%s) ERROR: Shortname %s was created for file %s\n",
			__location__, finfo->short_name, finfo->name);
		s->val = true;
	}
	s->matched += 1;
	return NT_STATUS_OK;
}

static bool run_shortname_test(int dummy)
{
	static struct cli_state *cli;
	bool correct = True;
	int i;
	struct sn_state s;
	char fname[40];
	NTSTATUS status;

	printf("starting shortname test\n");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	smbXcli_conn_set_sockopt(cli->conn, sockops);

	cli_list(cli, "\\shortname\\*", 0, shortname_del_fn, cli);
	cli_list(cli, "\\shortname\\*", FILE_ATTRIBUTE_DIRECTORY, shortname_del_fn, cli);
	cli_rmdir(cli, "\\shortname");

	status = cli_mkdir(cli, "\\shortname");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("(%s) cli_mkdir of \\shortname failed: %s\n",
			__location__, nt_errstr(status));
		correct = false;
		goto out;
	}

	if (strlcpy(fname, "\\shortname\\", sizeof(fname)) >= sizeof(fname)) {
		correct = false;
		goto out;
	}
	if (strlcat(fname, "test .txt", sizeof(fname)) >= sizeof(fname)) {
		correct = false;
		goto out;
	}

	s.val = false;

	for (i = 32; i < 128; i++) {
		uint16_t fnum = (uint16_t)-1;

		s.i = i;

		if (strchr(illegal_chars, i)) {
			continue;
		}
		fname[15] = i;

		status = cli_ntcreate(cli, fname, 0, GENERIC_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ|FILE_SHARE_WRITE,
				   FILE_OVERWRITE_IF, 0, 0, &fnum, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("(%s) cli_nt_create of %s failed: %s\n",
				__location__, fname, nt_errstr(status));
			correct = false;
			goto out;
		}
		cli_close(cli, fnum);

		s.matched = 0;
		status = cli_list(cli, "\\shortname\\test*.*", 0,
				  shortname_list_fn, &s);
		if (s.matched != 1) {
			d_printf("(%s) failed to list %s: %s\n",
				__location__, fname, nt_errstr(status));
			correct = false;
			goto out;
		}

		status = cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("(%s) failed to delete %s: %s\n",
				__location__, fname, nt_errstr(status));
			correct = false;
			goto out;
		}

		if (s.val) {
			correct = false;
			goto out;
		}
	}

  out:

	cli_list(cli, "\\shortname\\*", 0, shortname_del_fn, cli);
	cli_list(cli, "\\shortname\\*", FILE_ATTRIBUTE_DIRECTORY, shortname_del_fn, cli);
	cli_rmdir(cli, "\\shortname");
	torture_close_connection(cli);
	return correct;
}

static void pagedsearch_cb(struct tevent_req *req)
{
	int rc;
	struct tldap_message *msg;
	char *dn;

	rc = tldap_search_paged_recv(req, talloc_tos(), &msg);
	if (rc != TLDAP_SUCCESS) {
		d_printf("tldap_search_paged_recv failed: %s\n",
			 tldap_err2string(rc));
		return;
	}
	if (tldap_msg_type(msg) != TLDAP_RES_SEARCH_ENTRY) {
		TALLOC_FREE(msg);
		return;
	}
	if (!tldap_entry_dn(msg, &dn)) {
		d_printf("tldap_entry_dn failed\n");
		return;
	}
	d_printf("%s\n", dn);
	TALLOC_FREE(msg);
}

static bool run_tldap(int dummy)
{
	struct tldap_context *ld;
	int fd, rc;
	NTSTATUS status;
	struct sockaddr_storage addr;
	struct tevent_context *ev;
	struct tevent_req *req;
	char *basedn;
	const char *filter;

	if (!resolve_name(host, &addr, 0, false)) {
		d_printf("could not find host %s\n", host);
		return false;
	}
	status = open_socket_out(&addr, 389, 9999, &fd);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("open_socket_out failed: %s\n", nt_errstr(status));
		return false;
	}

	ld = tldap_context_create(talloc_tos(), fd);
	if (ld == NULL) {
		close(fd);
		d_printf("tldap_context_create failed\n");
		return false;
	}

	rc = tldap_fetch_rootdse(ld);
	if (rc != TLDAP_SUCCESS) {
		d_printf("tldap_fetch_rootdse failed: %s\n",
			 tldap_errstr(talloc_tos(), ld, rc));
		return false;
	}

	basedn = tldap_talloc_single_attribute(
		tldap_rootdse(ld), "defaultNamingContext", talloc_tos());
	if (basedn == NULL) {
		d_printf("no defaultNamingContext\n");
		return false;
	}
	d_printf("defaultNamingContext: %s\n", basedn);

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		d_printf("tevent_context_init failed\n");
		return false;
	}

	req = tldap_search_paged_send(talloc_tos(), ev, ld, basedn,
				      TLDAP_SCOPE_SUB, "(objectclass=*)",
				      NULL, 0, 0,
				      NULL, 0, NULL, 0, 0, 0, 0, 5);
	if (req == NULL) {
		d_printf("tldap_search_paged_send failed\n");
		return false;
	}
	tevent_req_set_callback(req, pagedsearch_cb, NULL);

	tevent_req_poll(req, ev);

	TALLOC_FREE(req);

	/* test search filters against rootDSE */
	filter = "(&(|(name=samba)(nextRid<=10000000)(usnChanged>=10)(samba~=ambas)(!(name=s*m*a)))"
		   "(|(name:=samba)(name:dn:2.5.13.5:=samba)(:dn:2.5.13.5:=samba)(!(name=*samba))))";

	rc = tldap_search(ld, "", TLDAP_SCOPE_BASE, filter,
			  NULL, 0, 0, NULL, 0, NULL, 0, 0, 0, 0,
			  talloc_tos(), NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		d_printf("tldap_search with complex filter failed: %s\n",
			 tldap_errstr(talloc_tos(), ld, rc));
		return false;
	}

	TALLOC_FREE(ld);
	return true;
}

/* Torture test to ensure no regression of :
https://bugzilla.samba.org/show_bug.cgi?id=7084
*/

static bool run_dir_createtime(int dummy)
{
	struct cli_state *cli;
	const char *dname = "\\testdir";
	const char *fname = "\\testdir\\testfile";
	NTSTATUS status;
	struct timespec create_time;
	struct timespec create_time1;
	uint16_t fnum;
	bool ret = false;

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, dname);

	status = cli_mkdir(cli, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("mkdir failed: %s\n", nt_errstr(status));
		goto out;
	}

	status = cli_qpathinfo2(cli, dname, &create_time, NULL, NULL, NULL,
				NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_qpathinfo2 returned %s\n",
		       nt_errstr(status));
		goto out;
	}

	/* Sleep 3 seconds, then create a file. */
	sleep(3);

	status = cli_openx(cli, fname, O_RDWR | O_CREAT | O_EXCL,
                         DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_openx failed: %s\n", nt_errstr(status));
		goto out;
	}

	status = cli_qpathinfo2(cli, dname, &create_time1, NULL, NULL, NULL,
				NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_qpathinfo2 (2) returned %s\n",
		       nt_errstr(status));
		goto out;
	}

	if (timespec_compare(&create_time1, &create_time)) {
		printf("run_dir_createtime: create time was updated (error)\n");
	} else {
		printf("run_dir_createtime: create time was not updated (correct)\n");
		ret = true;
	}

  out:

	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, dname);
	if (!torture_close_connection(cli)) {
		ret = false;
	}
	return ret;
}


static bool run_streamerror(int dummy)
{
	struct cli_state *cli;
	const char *dname = "\\testdir";
	const char *streamname =
		"testdir:{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}:$DATA";
	NTSTATUS status;
	time_t change_time, access_time, write_time;
	off_t size;
	uint16_t mode, fnum;
	bool ret = true;

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	cli_unlink(cli, "\\testdir\\*", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cli_rmdir(cli, dname);

	status = cli_mkdir(cli, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("mkdir failed: %s\n", nt_errstr(status));
		return false;
	}

	status = cli_qpathinfo1(cli, streamname, &change_time, &access_time,
				&write_time, &size, &mode);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		printf("pathinfo returned %s, expected "
		       "NT_STATUS_OBJECT_NAME_NOT_FOUND\n",
		       nt_errstr(status));
		ret = false;
	}

	status = cli_ntcreate(cli, streamname, 0x16,
			      FILE_READ_DATA|FILE_READ_EA|
			      FILE_READ_ATTRIBUTES|READ_CONTROL_ACCESS,
			      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
			      FILE_OPEN, 0, 0, &fnum, NULL);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		printf("ntcreate returned %s, expected "
		       "NT_STATUS_OBJECT_NAME_NOT_FOUND\n",
		       nt_errstr(status));
		ret = false;
	}


	cli_rmdir(cli, dname);
	return ret;
}

static bool run_local_substitute(int dummy)
{
	bool ok = true;

	ok &= subst_test("%U", "bla", "", -1, -1, "bla");
	ok &= subst_test("%u%U", "bla", "", -1, -1, "blabla");
	ok &= subst_test("%g", "", "", -1, -1, "NO_GROUP");
	ok &= subst_test("%G", "", "", -1, -1, "NO_GROUP");
	ok &= subst_test("%g", "", "", -1, 0, gidtoname(0));
	ok &= subst_test("%G", "", "", -1, 0, gidtoname(0));
	ok &= subst_test("%D%u", "u", "dom", -1, 0, "domu");
	ok &= subst_test("%i %I", "", "", -1, -1, "0.0.0.0 0.0.0.0");

	/* Different captialization rules in sub_basic... */

	ok &=  (strcmp(talloc_sub_basic(talloc_tos(), "BLA", "dom", "%U%D"),
		       "blaDOM") == 0);

	return ok;
}

static bool run_local_base64(int dummy)
{
	int i;
	bool ret = true;

	for (i=1; i<2000; i++) {
		DATA_BLOB blob1, blob2;
		char *b64;

		blob1.data = talloc_array(talloc_tos(), uint8_t, i);
		blob1.length = i;
		generate_random_buffer(blob1.data, blob1.length);

		b64 = base64_encode_data_blob(talloc_tos(), blob1);
		if (b64 == NULL) {
			d_fprintf(stderr, "base64_encode_data_blob failed "
				  "for %d bytes\n", i);
			ret = false;
		}
		blob2 = base64_decode_data_blob(b64);
		TALLOC_FREE(b64);

		if (data_blob_cmp(&blob1, &blob2)) {
			d_fprintf(stderr, "data_blob_cmp failed for %d "
				  "bytes\n", i);
			ret = false;
		}
		TALLOC_FREE(blob1.data);
		data_blob_free(&blob2);
	}
	return ret;
}

static void parse_fn(time_t timeout, DATA_BLOB blob, void *private_data)
{
	return;
}

static bool run_local_gencache(int dummy)
{
	char *val;
	time_t tm;
	DATA_BLOB blob;
	char v;
	struct memcache *mem;
	int i;

	mem = memcache_init(NULL, 0);
	if (mem == NULL) {
		d_printf("%s: memcache_init failed\n", __location__);
		return false;
	}
	memcache_set_global(mem);

	if (!gencache_set("foo", "bar", time(NULL) + 1000)) {
		d_printf("%s: gencache_set() failed\n", __location__);
		return False;
	}

	if (!gencache_get("foo", NULL, NULL, NULL)) {
		d_printf("%s: gencache_get() failed\n", __location__);
		return False;
	}

	for (i=0; i<1000000; i++) {
		gencache_parse("foo", parse_fn, NULL);
	}

	if (!gencache_get("foo", talloc_tos(), &val, &tm)) {
		d_printf("%s: gencache_get() failed\n", __location__);
		return False;
	}
	TALLOC_FREE(val);

	if (!gencache_get("foo", talloc_tos(), &val, &tm)) {
		d_printf("%s: gencache_get() failed\n", __location__);
		return False;
	}

	if (strcmp(val, "bar") != 0) {
		d_printf("%s: gencache_get() returned %s, expected %s\n",
			 __location__, val, "bar");
		TALLOC_FREE(val);
		return False;
	}

	TALLOC_FREE(val);

	if (!gencache_del("foo")) {
		d_printf("%s: gencache_del() failed\n", __location__);
		return False;
	}
	if (gencache_del("foo")) {
		d_printf("%s: second gencache_del() succeeded\n",
			 __location__);
		return False;
	}

	if (gencache_get("foo", talloc_tos(), &val, &tm)) {
		d_printf("%s: gencache_get() on deleted entry "
			 "succeeded\n", __location__);
		return False;
	}

	blob = data_blob_string_const_null("bar");
	tm = time(NULL) + 60;

	if (!gencache_set_data_blob("foo", &blob, tm)) {
		d_printf("%s: gencache_set_data_blob() failed\n", __location__);
		return False;
	}

	if (!gencache_get_data_blob("foo", talloc_tos(), &blob, NULL, NULL)) {
		d_printf("%s: gencache_get_data_blob() failed\n", __location__);
		return False;
	}

	if (strcmp((const char *)blob.data, "bar") != 0) {
		d_printf("%s: gencache_get_data_blob() returned %s, expected %s\n",
			 __location__, (const char *)blob.data, "bar");
		data_blob_free(&blob);
		return False;
	}

	data_blob_free(&blob);

	if (!gencache_del("foo")) {
		d_printf("%s: gencache_del() failed\n", __location__);
		return False;
	}
	if (gencache_del("foo")) {
		d_printf("%s: second gencache_del() succeeded\n",
			 __location__);
		return False;
	}

	if (gencache_get_data_blob("foo", talloc_tos(), &blob, NULL, NULL)) {
		d_printf("%s: gencache_get_data_blob() on deleted entry "
			 "succeeded\n", __location__);
		return False;
	}

	v = 1;
	blob.data = (uint8_t *)&v;
	blob.length = sizeof(v);

	if (!gencache_set_data_blob("blob", &blob, tm)) {
		d_printf("%s: gencache_set_data_blob() failed\n",
			 __location__);
		return false;
	}
	if (gencache_get("blob", talloc_tos(), &val, &tm)) {
		d_printf("%s: gencache_get succeeded\n", __location__);
		return false;
	}

	return True;
}

static bool rbt_testval(struct db_context *db, const char *key,
			const char *value)
{
	struct db_record *rec;
	TDB_DATA data = string_tdb_data(value);
	bool ret = false;
	NTSTATUS status;
	TDB_DATA dbvalue;

	rec = dbwrap_fetch_locked(db, db, string_tdb_data(key));
	if (rec == NULL) {
		d_fprintf(stderr, "fetch_locked failed\n");
		goto done;
	}
	status = dbwrap_record_store(rec, data, 0);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "store failed: %s\n", nt_errstr(status));
		goto done;
	}
	TALLOC_FREE(rec);

	rec = dbwrap_fetch_locked(db, db, string_tdb_data(key));
	if (rec == NULL) {
		d_fprintf(stderr, "second fetch_locked failed\n");
		goto done;
	}

	dbvalue = dbwrap_record_get_value(rec);
	if ((dbvalue.dsize != data.dsize)
	    || (memcmp(dbvalue.dptr, data.dptr, data.dsize) != 0)) {
		d_fprintf(stderr, "Got wrong data back\n");
		goto done;
	}

	ret = true;
 done:
	TALLOC_FREE(rec);
	return ret;
}

static bool run_local_rbtree(int dummy)
{
	struct db_context *db;
	bool ret = false;
	int i;

	db = db_open_rbt(NULL);

	if (db == NULL) {
		d_fprintf(stderr, "db_open_rbt failed\n");
		return false;
	}

	for (i=0; i<1000; i++) {
		char *key, *value;

		if (asprintf(&key, "key%ld", random()) == -1) {
			goto done;
		}
		if (asprintf(&value, "value%ld", random()) == -1) {
			SAFE_FREE(key);
			goto done;
		}

		if (!rbt_testval(db, key, value)) {
			SAFE_FREE(key);
			SAFE_FREE(value);
			goto done;
		}

		SAFE_FREE(value);
		if (asprintf(&value, "value%ld", random()) == -1) {
			SAFE_FREE(key);
			goto done;
		}

		if (!rbt_testval(db, key, value)) {
			SAFE_FREE(key);
			SAFE_FREE(value);
			goto done;
		}

		SAFE_FREE(key);
		SAFE_FREE(value);
	}

	ret = true;

 done:
	TALLOC_FREE(db);
	return ret;
}


/*
  local test for character set functions

  This is a very simple test for the functionality in convert_string_error()
 */
static bool run_local_convert_string(int dummy)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	const char *test_strings[2] = { "March", "M\303\244rz" };
	char dst[7];
	int i;

	for (i=0; i<2; i++) {
		const char *str = test_strings[i];
		int len = strlen(str);
		size_t converted_size;
		bool ret;

		memset(dst, 'X', sizeof(dst));

		/* first try with real source length */
		ret = convert_string_error(CH_UNIX, CH_UTF8,
					   str, len,
					   dst, sizeof(dst),
					   &converted_size);
		if (ret != true) {
			d_fprintf(stderr, "Failed to convert '%s' to CH_DISPLAY\n", str);
			goto failed;
		}

		if (converted_size != len) {
			d_fprintf(stderr, "Converted size of '%s' should be %d - got %d\n",
				  str, len, (int)converted_size);
			goto failed;
		}

		if (strncmp(str, dst, converted_size) != 0) {
			d_fprintf(stderr, "Expected '%s' to match '%s'\n", str, dst);
			goto failed;
		}

		if (strlen(str) != converted_size) {
			d_fprintf(stderr, "Expected '%s' length %d - got %d\n", str,
				  (int)strlen(str), (int)converted_size);
			goto failed;
		}

		if (dst[converted_size] != 'X') {
			d_fprintf(stderr, "Expected no termination of '%s'\n", dst);
			goto failed;
		}

		/* now with srclen==-1, this causes the nul to be
		 * converted too */
		ret = convert_string_error(CH_UNIX, CH_UTF8,
					   str, -1,
					   dst, sizeof(dst),
					   &converted_size);
		if (ret != true) {
			d_fprintf(stderr, "Failed to convert '%s' to CH_DISPLAY\n", str);
			goto failed;
		}

		if (converted_size != len+1) {
			d_fprintf(stderr, "Converted size of '%s' should be %d - got %d\n",
				  str, len, (int)converted_size);
			goto failed;
		}

		if (strncmp(str, dst, converted_size) != 0) {
			d_fprintf(stderr, "Expected '%s' to match '%s'\n", str, dst);
			goto failed;
		}

		if (len+1 != converted_size) {
			d_fprintf(stderr, "Expected '%s' length %d - got %d\n", str,
				  len+1, (int)converted_size);
			goto failed;
		}

		if (dst[converted_size] != 'X') {
			d_fprintf(stderr, "Expected no termination of '%s'\n", dst);
			goto failed;
		}

	}


	TALLOC_FREE(tmp_ctx);
	return true;
failed:
	TALLOC_FREE(tmp_ctx);
	return false;
}


struct talloc_dict_test {
	int content;
};

static int talloc_dict_traverse_fn(DATA_BLOB key, void *data, void *priv)
{
	int *count = (int *)priv;
	*count += 1;
	return 0;
}

static bool run_local_talloc_dict(int dummy)
{
	struct talloc_dict *dict;
	struct talloc_dict_test *t;
	int key, count, res;
	bool ok;

	dict = talloc_dict_init(talloc_tos());
	if (dict == NULL) {
		return false;
	}

	t = talloc(talloc_tos(), struct talloc_dict_test);
	if (t == NULL) {
		return false;
	}

	key = 1;
	t->content = 1;
	ok = talloc_dict_set(dict, data_blob_const(&key, sizeof(key)), &t);
	if (!ok) {
		return false;
	}

	count = 0;
	res = talloc_dict_traverse(dict, talloc_dict_traverse_fn, &count);
	if (res == -1) {
		return false;
	}

	if (count != 1) {
		return false;
	}

	if (count != res) {
		return false;
	}

	TALLOC_FREE(dict);

	return true;
}

static bool run_local_string_to_sid(int dummy) {
	struct dom_sid sid;

	if (string_to_sid(&sid, "S--1-5-32-545")) {
		printf("allowing S--1-5-32-545\n");
		return false;
	}
	if (string_to_sid(&sid, "S-1-5-32-+545")) {
		printf("allowing S-1-5-32-+545\n");
		return false;
	}
	if (string_to_sid(&sid, "S-1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6-7-8-9-0")) {
		printf("allowing S-1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6-7-8-9-0\n");
		return false;
	}
	if (string_to_sid(&sid, "S-1-5-32-545-abc")) {
		printf("allowing S-1-5-32-545-abc\n");
		return false;
	}
	if (string_to_sid(&sid, "S-300-5-32-545")) {
		printf("allowing S-300-5-32-545\n");
		return false;
	}
	if (string_to_sid(&sid, "S-1-0xfffffffffffffe-32-545")) {
		printf("allowing S-1-0xfffffffffffffe-32-545\n");
		return false;
	}
	if (string_to_sid(&sid, "S-1-0xffffffffffff-5294967297-545")) {
		printf("allowing S-1-0xffffffffffff-5294967297-545\n");
		return false;
	}
	if (!string_to_sid(&sid, "S-1-0xfffffffffffe-32-545")) {
		printf("could not parse S-1-0xfffffffffffe-32-545\n");
		return false;
	}
	if (!string_to_sid(&sid, "S-1-5-32-545")) {
		printf("could not parse S-1-5-32-545\n");
		return false;
	}
	if (!dom_sid_equal(&sid, &global_sid_Builtin_Users)) {
		printf("mis-parsed S-1-5-32-545 as %s\n",
		       sid_string_tos(&sid));
		return false;
	}
	return true;
}

static bool sid_to_string_test(const char *expected) {
	char *str;
	bool res = true;
	struct dom_sid sid;

	if (!string_to_sid(&sid, expected)) {
		printf("could not parse %s\n", expected);
		return false;
	}

	str = dom_sid_string(NULL, &sid);
	if (strcmp(str, expected)) {
		printf("Comparison failed (%s != %s)\n", str, expected);
		res = false;
	}
	TALLOC_FREE(str);
	return res;
}

static bool run_local_sid_to_string(int dummy) {
	if (!sid_to_string_test("S-1-0xffffffffffff-1-1-1-1-1-1-1-1-1-1-1-1"))
		return false;
	if (!sid_to_string_test("S-1-545"))
		return false;
	if (!sid_to_string_test("S-255-3840-1-1-1-1"))
		return false;
	return true;
}

static bool run_local_binary_to_sid(int dummy) {
	struct dom_sid *sid = talloc(NULL, struct dom_sid);
	static const char good_binary_sid[] = {
		0x1, /* revision number */
		15, /* num auths */
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, /* id_auth */
		0x1, 0x1, 0x1, 0x1, /* auth[0] */
		0x1, 0x1, 0x1, 0x1, /* auth[1] */
		0x1, 0x1, 0x1, 0x1, /* auth[2] */
		0x1, 0x1, 0x1, 0x1, /* auth[3] */
		0x1, 0x1, 0x1, 0x1, /* auth[4] */
		0x1, 0x1, 0x1, 0x1, /* auth[5] */
		0x1, 0x1, 0x1, 0x1, /* auth[6] */
		0x1, 0x1, 0x1, 0x1, /* auth[7] */
		0x1, 0x1, 0x1, 0x1, /* auth[8] */
		0x1, 0x1, 0x1, 0x1, /* auth[9] */
		0x1, 0x1, 0x1, 0x1, /* auth[10] */
		0x1, 0x1, 0x1, 0x1, /* auth[11] */
		0x1, 0x1, 0x1, 0x1, /* auth[12] */
		0x1, 0x1, 0x1, 0x1, /* auth[13] */
		0x1, 0x1, 0x1, 0x1, /* auth[14] */
	};

	static const char long_binary_sid[] = {
		0x1, /* revision number */
		15, /* num auths */
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, /* id_auth */
		0x1, 0x1, 0x1, 0x1, /* auth[0] */
		0x1, 0x1, 0x1, 0x1, /* auth[1] */
		0x1, 0x1, 0x1, 0x1, /* auth[2] */
		0x1, 0x1, 0x1, 0x1, /* auth[3] */
		0x1, 0x1, 0x1, 0x1, /* auth[4] */
		0x1, 0x1, 0x1, 0x1, /* auth[5] */
		0x1, 0x1, 0x1, 0x1, /* auth[6] */
		0x1, 0x1, 0x1, 0x1, /* auth[7] */
		0x1, 0x1, 0x1, 0x1, /* auth[8] */
		0x1, 0x1, 0x1, 0x1, /* auth[9] */
		0x1, 0x1, 0x1, 0x1, /* auth[10] */
		0x1, 0x1, 0x1, 0x1, /* auth[11] */
		0x1, 0x1, 0x1, 0x1, /* auth[12] */
		0x1, 0x1, 0x1, 0x1, /* auth[13] */
		0x1, 0x1, 0x1, 0x1, /* auth[14] */
		0x1, 0x1, 0x1, 0x1, /* auth[15] */
		0x1, 0x1, 0x1, 0x1, /* auth[16] */
		0x1, 0x1, 0x1, 0x1, /* auth[17] */
	};

	static const char long_binary_sid2[] = {
		0x1, /* revision number */
		32, /* num auths */
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, /* id_auth */
		0x1, 0x1, 0x1, 0x1, /* auth[0] */
		0x1, 0x1, 0x1, 0x1, /* auth[1] */
		0x1, 0x1, 0x1, 0x1, /* auth[2] */
		0x1, 0x1, 0x1, 0x1, /* auth[3] */
		0x1, 0x1, 0x1, 0x1, /* auth[4] */
		0x1, 0x1, 0x1, 0x1, /* auth[5] */
		0x1, 0x1, 0x1, 0x1, /* auth[6] */
		0x1, 0x1, 0x1, 0x1, /* auth[7] */
		0x1, 0x1, 0x1, 0x1, /* auth[8] */
		0x1, 0x1, 0x1, 0x1, /* auth[9] */
		0x1, 0x1, 0x1, 0x1, /* auth[10] */
		0x1, 0x1, 0x1, 0x1, /* auth[11] */
		0x1, 0x1, 0x1, 0x1, /* auth[12] */
		0x1, 0x1, 0x1, 0x1, /* auth[13] */
		0x1, 0x1, 0x1, 0x1, /* auth[14] */
		0x1, 0x1, 0x1, 0x1, /* auth[15] */
		0x1, 0x1, 0x1, 0x1, /* auth[16] */
		0x1, 0x1, 0x1, 0x1, /* auth[17] */
		0x1, 0x1, 0x1, 0x1, /* auth[18] */
		0x1, 0x1, 0x1, 0x1, /* auth[19] */
		0x1, 0x1, 0x1, 0x1, /* auth[20] */
		0x1, 0x1, 0x1, 0x1, /* auth[21] */
		0x1, 0x1, 0x1, 0x1, /* auth[22] */
		0x1, 0x1, 0x1, 0x1, /* auth[23] */
		0x1, 0x1, 0x1, 0x1, /* auth[24] */
		0x1, 0x1, 0x1, 0x1, /* auth[25] */
		0x1, 0x1, 0x1, 0x1, /* auth[26] */
		0x1, 0x1, 0x1, 0x1, /* auth[27] */
		0x1, 0x1, 0x1, 0x1, /* auth[28] */
		0x1, 0x1, 0x1, 0x1, /* auth[29] */
		0x1, 0x1, 0x1, 0x1, /* auth[30] */
		0x1, 0x1, 0x1, 0x1, /* auth[31] */
	};

	if (!sid_parse(good_binary_sid, sizeof(good_binary_sid), sid)) {
		return false;
	}
	if (sid_parse(long_binary_sid2, sizeof(long_binary_sid2), sid)) {
		return false;
	}
	if (sid_parse(long_binary_sid, sizeof(long_binary_sid), sid)) {
		return false;
	}
	return true;
}

/* Split a path name into filename and stream name components. Canonicalise
 * such that an implicit $DATA token is always explicit.
 *
 * The "specification" of this function can be found in the
 * run_local_stream_name() function in torture.c, I've tried those
 * combinations against a W2k3 server.
 */

static NTSTATUS split_ntfs_stream_name(TALLOC_CTX *mem_ctx, const char *fname,
				       char **pbase, char **pstream)
{
	char *base = NULL;
	char *stream = NULL;
	char *sname; /* stream name */
	const char *stype; /* stream type */

	DEBUG(10, ("split_ntfs_stream_name called for [%s]\n", fname));

	sname = strchr_m(fname, ':');

	if (lp_posix_pathnames() || (sname == NULL)) {
		if (pbase != NULL) {
			base = talloc_strdup(mem_ctx, fname);
			NT_STATUS_HAVE_NO_MEMORY(base);
		}
		goto done;
	}

	if (pbase != NULL) {
		base = talloc_strndup(mem_ctx, fname, PTR_DIFF(sname, fname));
		NT_STATUS_HAVE_NO_MEMORY(base);
	}

	sname += 1;

	stype = strchr_m(sname, ':');

	if (stype == NULL) {
		sname = talloc_strdup(mem_ctx, sname);
		stype = "$DATA";
	}
	else {
		if (strcasecmp_m(stype, ":$DATA") != 0) {
			/*
			 * If there is an explicit stream type, so far we only
			 * allow $DATA. Is there anything else allowed? -- vl
			 */
			DEBUG(10, ("[%s] is an invalid stream type\n", stype));
			TALLOC_FREE(base);
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		sname = talloc_strndup(mem_ctx, sname, PTR_DIFF(stype, sname));
		stype += 1;
	}

	if (sname == NULL) {
		TALLOC_FREE(base);
		return NT_STATUS_NO_MEMORY;
	}

	if (sname[0] == '\0') {
		/*
		 * no stream name, so no stream
		 */
		goto done;
	}

	if (pstream != NULL) {
		stream = talloc_asprintf(mem_ctx, "%s:%s", sname, stype);
		if (stream == NULL) {
			TALLOC_FREE(sname);
			TALLOC_FREE(base);
			return NT_STATUS_NO_MEMORY;
		}
		/*
		 * upper-case the type field
		 */
		(void)strupper_m(strchr_m(stream, ':')+1);
	}

 done:
	if (pbase != NULL) {
		*pbase = base;
	}
	if (pstream != NULL) {
		*pstream = stream;
	}
	return NT_STATUS_OK;
}

static bool test_stream_name(const char *fname, const char *expected_base,
			     const char *expected_stream,
			     NTSTATUS expected_status)
{
	NTSTATUS status;
	char *base = NULL;
	char *stream = NULL;

	status = split_ntfs_stream_name(talloc_tos(), fname, &base, &stream);
	if (!NT_STATUS_EQUAL(status, expected_status)) {
		goto error;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return true;
	}

	if (base == NULL) goto error;

	if (strcmp(expected_base, base) != 0) goto error;

	if ((expected_stream != NULL) && (stream == NULL)) goto error;
	if ((expected_stream == NULL) && (stream != NULL)) goto error;

	if ((stream != NULL) && (strcmp(expected_stream, stream) != 0))
		goto error;

	TALLOC_FREE(base);
	TALLOC_FREE(stream);
	return true;

 error:
	d_fprintf(stderr, "Do test_stream(%s, %s, %s, %s)\n",
		  fname, expected_base ? expected_base : "<NULL>",
		  expected_stream ? expected_stream : "<NULL>",
		  nt_errstr(expected_status));
	d_fprintf(stderr, "-> base=%s, stream=%s, status=%s\n",
		  base ? base : "<NULL>", stream ? stream : "<NULL>",
		  nt_errstr(status));
	TALLOC_FREE(base);
	TALLOC_FREE(stream);
	return false;
}

static bool run_local_stream_name(int dummy)
{
	bool ret = true;

	ret &= test_stream_name(
		"bla", "bla", NULL, NT_STATUS_OK);
	ret &= test_stream_name(
		"bla::$DATA", "bla", NULL, NT_STATUS_OK);
	ret &= test_stream_name(
		"bla:blub:", "bla", NULL, NT_STATUS_OBJECT_NAME_INVALID);
	ret &= test_stream_name(
		"bla::", NULL, NULL, NT_STATUS_OBJECT_NAME_INVALID);
	ret &= test_stream_name(
		"bla::123", "bla", NULL, NT_STATUS_OBJECT_NAME_INVALID);
	ret &= test_stream_name(
		"bla:$DATA", "bla", "$DATA:$DATA", NT_STATUS_OK);
	ret &= test_stream_name(
		"bla:x:$DATA", "bla", "x:$DATA", NT_STATUS_OK);
	ret &= test_stream_name(
		"bla:x", "bla", "x:$DATA", NT_STATUS_OK);

	return ret;
}

static bool data_blob_equal(DATA_BLOB a, DATA_BLOB b)
{
	if (a.length != b.length) {
		printf("a.length=%d != b.length=%d\n",
		       (int)a.length, (int)b.length);
		return false;
	}
	if (memcmp(a.data, b.data, a.length) != 0) {
		printf("a.data and b.data differ\n");
		return false;
	}
	return true;
}

static bool run_local_memcache(int dummy)
{
	struct memcache *cache;
	DATA_BLOB k1, k2;
	DATA_BLOB d1, d2, d3;
	DATA_BLOB v1, v2, v3;

	TALLOC_CTX *mem_ctx;
	char *str1, *str2;
	size_t size1, size2;
	bool ret = false;

	cache = memcache_init(NULL, sizeof(void *) == 8 ? 200 : 100);

	if (cache == NULL) {
		printf("memcache_init failed\n");
		return false;
	}

	d1 = data_blob_const("d1", 2);
	d2 = data_blob_const("d2", 2);
	d3 = data_blob_const("d3", 2);

	k1 = data_blob_const("d1", 2);
	k2 = data_blob_const("d2", 2);

	memcache_add(cache, STAT_CACHE, k1, d1);
	memcache_add(cache, GETWD_CACHE, k2, d2);

	if (!memcache_lookup(cache, STAT_CACHE, k1, &v1)) {
		printf("could not find k1\n");
		return false;
	}
	if (!data_blob_equal(d1, v1)) {
		return false;
	}

	if (!memcache_lookup(cache, GETWD_CACHE, k2, &v2)) {
		printf("could not find k2\n");
		return false;
	}
	if (!data_blob_equal(d2, v2)) {
		return false;
	}

	memcache_add(cache, STAT_CACHE, k1, d3);

	if (!memcache_lookup(cache, STAT_CACHE, k1, &v3)) {
		printf("could not find replaced k1\n");
		return false;
	}
	if (!data_blob_equal(d3, v3)) {
		return false;
	}

	memcache_add(cache, GETWD_CACHE, k1, d1);

	if (memcache_lookup(cache, GETWD_CACHE, k2, &v2)) {
		printf("Did find k2, should have been purged\n");
		return false;
	}

	TALLOC_FREE(cache);

	cache = memcache_init(NULL, 0);

	mem_ctx = talloc_init("foo");

	str1 = talloc_strdup(mem_ctx, "string1");
	str2 = talloc_strdup(mem_ctx, "string2");

	memcache_add_talloc(cache, SINGLETON_CACHE_TALLOC,
			    data_blob_string_const("torture"), &str1);
	size1 = talloc_total_size(cache);

	memcache_add_talloc(cache, SINGLETON_CACHE_TALLOC,
			    data_blob_string_const("torture"), &str2);
	size2 = talloc_total_size(cache);

	printf("size1=%d, size2=%d\n", (int)size1, (int)size2);

	if (size2 > size1) {
		printf("memcache leaks memory!\n");
		goto fail;
	}

	ret = true;
 fail:
	TALLOC_FREE(cache);
	return ret;
}

static void wbclient_done(struct tevent_req *req)
{
	wbcErr wbc_err;
	struct winbindd_response *wb_resp;
	int *i = (int *)tevent_req_callback_data_void(req);

	wbc_err = wb_trans_recv(req, req, &wb_resp);
	TALLOC_FREE(req);
	*i += 1;
	d_printf("wb_trans_recv %d returned %s\n", *i, wbcErrorString(wbc_err));
}

static bool run_local_wbclient(int dummy)
{
	struct tevent_context *ev;
	struct wb_context **wb_ctx;
	struct winbindd_request wb_req;
	bool result = false;
	int i, j;

	BlockSignals(True, SIGPIPE);

	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}

	wb_ctx = talloc_array(ev, struct wb_context *, torture_nprocs);
	if (wb_ctx == NULL) {
		goto fail;
	}

	ZERO_STRUCT(wb_req);
	wb_req.cmd = WINBINDD_PING;

	d_printf("torture_nprocs=%d, numops=%d\n", (int)torture_nprocs, (int)torture_numops);

	for (i=0; i<torture_nprocs; i++) {
		wb_ctx[i] = wb_context_init(ev, NULL);
		if (wb_ctx[i] == NULL) {
			goto fail;
		}
		for (j=0; j<torture_numops; j++) {
			struct tevent_req *req;
			req = wb_trans_send(ev, ev, wb_ctx[i],
					    (j % 2) == 0, &wb_req);
			if (req == NULL) {
				goto fail;
			}
			tevent_req_set_callback(req, wbclient_done, &i);
		}
	}

	i = 0;

	while (i < torture_nprocs * torture_numops) {
		tevent_loop_once(ev);
	}

	result = true;
 fail:
	TALLOC_FREE(ev);
	return result;
}

static void getaddrinfo_finished(struct tevent_req *req)
{
	char *name = (char *)tevent_req_callback_data_void(req);
	struct addrinfo *ainfo;
	int res;

	res = getaddrinfo_recv(req, &ainfo);
	if (res != 0) {
		d_printf("gai(%s) returned %s\n", name, gai_strerror(res));
		return;
	}
	d_printf("gai(%s) succeeded\n", name);
	freeaddrinfo(ainfo);
}

static bool run_getaddrinfo_send(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fncall_context *ctx;
	struct tevent_context *ev;
	bool result = false;
	const char *names[4] = { "www.samba.org", "notfound.samba.org",
				 "www.slashdot.org", "heise.de" };
	struct tevent_req *reqs[4];
	int i;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	ctx = fncall_context_init(frame, 4);

	for (i=0; i<ARRAY_SIZE(names); i++) {
		reqs[i] = getaddrinfo_send(frame, ev, ctx, names[i], NULL,
					   NULL);
		if (reqs[i] == NULL) {
			goto fail;
		}
		tevent_req_set_callback(reqs[i], getaddrinfo_finished,
					discard_const_p(void, names[i]));
	}

	for (i=0; i<ARRAY_SIZE(reqs); i++) {
		tevent_loop_once(ev);
	}

	result = true;
fail:
	TALLOC_FREE(frame);
	return result;
}

static bool dbtrans_inc(struct db_context *db)
{
	struct db_record *rec;
	uint32_t val;
	bool ret = false;
	NTSTATUS status;
	TDB_DATA value;

	rec = dbwrap_fetch_locked(db, db, string_term_tdb_data("transtest"));
	if (rec == NULL) {
		printf(__location__ "fetch_lock failed\n");
		return false;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dsize != sizeof(uint32_t)) {
		printf(__location__ "value.dsize = %d\n",
		       (int)value.dsize);
		goto fail;
	}

	memcpy(&val, value.dptr, sizeof(val));
	val += 1;

	status = dbwrap_record_store(
		rec, make_tdb_data((uint8_t *)&val, sizeof(val)), 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf(__location__ "store failed: %s\n",
		       nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(rec);
	return ret;
}

static bool run_local_dbtrans(int dummy)
{
	struct db_context *db;
	struct db_record *rec;
	NTSTATUS status;
	uint32_t initial;
	int res;
	TDB_DATA value;

	db = db_open(talloc_tos(), "transtest.tdb", 0, TDB_DEFAULT,
		     O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_1,
		     DBWRAP_FLAG_NONE);
	if (db == NULL) {
		printf("Could not open transtest.db\n");
		return false;
	}

	res = dbwrap_transaction_start(db);
	if (res != 0) {
		printf(__location__ "transaction_start failed\n");
		return false;
	}

	rec = dbwrap_fetch_locked(db, db, string_term_tdb_data("transtest"));
	if (rec == NULL) {
		printf(__location__ "fetch_lock failed\n");
		return false;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dptr == NULL) {
		initial = 0;
		status = dbwrap_record_store(
			rec, make_tdb_data((uint8_t *)&initial,
					   sizeof(initial)),
			0);
		if (!NT_STATUS_IS_OK(status)) {
			printf(__location__ "store returned %s\n",
			       nt_errstr(status));
			return false;
		}
	}

	TALLOC_FREE(rec);

	res = dbwrap_transaction_commit(db);
	if (res != 0) {
		printf(__location__ "transaction_commit failed\n");
		return false;
	}

	while (true) {
		uint32_t val, val2;
		int i;

		res = dbwrap_transaction_start(db);
		if (res != 0) {
			printf(__location__ "transaction_start failed\n");
			break;
		}

		status = dbwrap_fetch_uint32_bystring(db, "transtest", &val);
		if (!NT_STATUS_IS_OK(status)) {
			printf(__location__ "dbwrap_fetch_uint32 failed: %s\n",
			       nt_errstr(status));
			break;
		}

		for (i=0; i<10; i++) {
			if (!dbtrans_inc(db)) {
				return false;
			}
		}

		status = dbwrap_fetch_uint32_bystring(db, "transtest", &val2);
		if (!NT_STATUS_IS_OK(status)) {
			printf(__location__ "dbwrap_fetch_uint32 failed: %s\n",
			       nt_errstr(status));
			break;
		}

		if (val2 != val + 10) {
			printf(__location__ "val=%d, val2=%d\n",
			       (int)val, (int)val2);
			break;
		}

		printf("val2=%d\r", val2);

		res = dbwrap_transaction_commit(db);
		if (res != 0) {
			printf(__location__ "transaction_commit failed\n");
			break;
		}
	}

	TALLOC_FREE(db);
	return true;
}

/*
 * Just a dummy test to be run under a debugger. There's no real way
 * to inspect the tevent_select specific function from outside of
 * tevent_select.c.
 */

static bool run_local_tevent_select(int dummy)
{
	struct tevent_context *ev;
	struct tevent_fd *fd1, *fd2;
	bool result = false;

	ev = tevent_context_init_byname(NULL, "select");
	if (ev == NULL) {
		d_fprintf(stderr, "tevent_context_init_byname failed\n");
		goto fail;
	}

	fd1 = tevent_add_fd(ev, ev, 2, 0, NULL, NULL);
	if (fd1 == NULL) {
		d_fprintf(stderr, "tevent_add_fd failed\n");
		goto fail;
	}
	fd2 = tevent_add_fd(ev, ev, 3, 0, NULL, NULL);
	if (fd2 == NULL) {
		d_fprintf(stderr, "tevent_add_fd failed\n");
		goto fail;
	}
	TALLOC_FREE(fd2);

	fd2 = tevent_add_fd(ev, ev, 1, 0, NULL, NULL);
	if (fd2 == NULL) {
		d_fprintf(stderr, "tevent_add_fd failed\n");
		goto fail;
	}

	result = true;
fail:
	TALLOC_FREE(ev);
	return result;
}

static bool run_local_hex_encode_buf(int dummy)
{
	char buf[17];
	uint8_t src[8];
	int i;

	for (i=0; i<sizeof(src); i++) {
		src[i] = i;
	}
	hex_encode_buf(buf, src, sizeof(src));
	if (strcmp(buf, "0001020304050607") != 0) {
	       	return false;
	}
	hex_encode_buf(buf, NULL, 0);
	if (buf[0] != '\0') {
		return false;
	}
	return true;
}

static const char *remove_duplicate_addrs2_test_strings_vector[] = {
	"0.0.0.0",
	"::0",
	"1.2.3.1",
	"0.0.0.0",
	"0.0.0.0",
	"1.2.3.2",
	"1.2.3.3",
	"1.2.3.4",
	"1.2.3.5",
	"::0",
	"1.2.3.6",
	"1.2.3.7",
	"::0",
	"::0",
	"::0",
	"1.2.3.8",
	"1.2.3.9",
	"1.2.3.10",
	"1.2.3.11",
	"1.2.3.12",
	"1.2.3.13",
	"1001:1111:1111:1000:0:1111:1111:1111",
	"1.2.3.1",
	"1.2.3.2",
	"1.2.3.3",
	"1.2.3.12",
	"::0",
	"::0"
};

static const char *remove_duplicate_addrs2_test_strings_result[] = {
	"1.2.3.1",
	"1.2.3.2",
	"1.2.3.3",
	"1.2.3.4",
	"1.2.3.5",
	"1.2.3.6",
	"1.2.3.7",
	"1.2.3.8",
	"1.2.3.9",
	"1.2.3.10",
	"1.2.3.11",
	"1.2.3.12",
	"1.2.3.13",
	"1001:1111:1111:1000:0:1111:1111:1111"
};

static bool run_local_remove_duplicate_addrs2(int dummy)
{
	struct ip_service test_vector[28];
	int count, i;

	/* Construct the sockaddr_storage test vector. */
	for (i = 0; i < 28; i++) {
		struct addrinfo hints;
		struct addrinfo *res = NULL;
		int ret;

		memset(&hints, '\0', sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		ret = getaddrinfo(remove_duplicate_addrs2_test_strings_vector[i],
				NULL,
				&hints,
				&res);
		if (ret) {
			fprintf(stderr, "getaddrinfo failed on [%s]\n",
				remove_duplicate_addrs2_test_strings_vector[i]);
			return false;
		}
		memset(&test_vector[i], '\0', sizeof(test_vector[i]));
		memcpy(&test_vector[i].ss,
			res->ai_addr,
			res->ai_addrlen);
		freeaddrinfo(res);
	}

	count = remove_duplicate_addrs2(test_vector, i);

	if (count != 14) {
		fprintf(stderr, "count wrong (%d) should be 14\n",
			count);
		return false;
	}

	for (i = 0; i < count; i++) {
		char addr[INET6_ADDRSTRLEN];

		print_sockaddr(addr, sizeof(addr), &test_vector[i].ss);

		if (strcmp(addr, remove_duplicate_addrs2_test_strings_result[i]) != 0) {
			fprintf(stderr, "mismatch on [%d] [%s] [%s]\n",
				i,
				addr,
				remove_duplicate_addrs2_test_strings_result[i]);
			return false;
		}
	}

	printf("run_local_remove_duplicate_addrs2: success\n");
	return true;
}

static bool run_local_tdb_opener(int dummy)
{
	TDB_CONTEXT *t;
	unsigned v = 0;

	while (1) {
		t = tdb_open("test.tdb", 1000, TDB_CLEAR_IF_FIRST,
			     O_RDWR|O_CREAT, 0755);
		if (t == NULL) {
			perror("tdb_open failed");
			return false;
		}
		tdb_close(t);

		v += 1;
		printf("\r%u", v);
	}
	return true;
}

static bool run_local_tdb_writer(int dummy)
{
	TDB_CONTEXT *t;
	unsigned v = 0;
	TDB_DATA val;

	t = tdb_open("test.tdb", 1000, 0, O_RDWR|O_CREAT, 0755);
	if (t == 0) {
		perror("tdb_open failed");
		return 1;
	}

	val.dptr = (uint8_t *)&v;
	val.dsize = sizeof(v);

	while (1) {
		TDB_DATA data;
		int ret;

		ret = tdb_store(t, val, val, 0);
		if (ret != 0) {
			printf("%s\n", tdb_errorstr(t));
		}
		v += 1;
		printf("\r%u", v);

		data = tdb_fetch(t, val);
		if (data.dptr != NULL) {
			SAFE_FREE(data.dptr);
		}
	}
	return true;
}

static double create_procs(bool (*fn)(int), bool *result)
{
	int i, status;
	volatile pid_t *child_status;
	volatile bool *child_status_out;
	int synccount;
	int tries = 8;
	struct timeval start;

	synccount = 0;

	child_status = (volatile pid_t *)anonymous_shared_allocate(sizeof(pid_t)*torture_nprocs);
	if (!child_status) {
		printf("Failed to setup shared memory\n");
		return -1;
	}

	child_status_out = (volatile bool *)anonymous_shared_allocate(sizeof(bool)*torture_nprocs);
	if (!child_status_out) {
		printf("Failed to setup result status shared memory\n");
		return -1;
	}

	for (i = 0; i < torture_nprocs; i++) {
		child_status[i] = 0;
		child_status_out[i] = True;
	}

	start = timeval_current();

	for (i=0;i<torture_nprocs;i++) {
		procnum = i;
		if (fork() == 0) {
			pid_t mypid = getpid();
			sys_srandom(((int)mypid) ^ ((int)time(NULL)));

			slprintf(myname,sizeof(myname),"CLIENT%d", i);

			while (1) {
				if (torture_open_connection(&current_cli, i)) break;
				if (tries-- == 0) {
					printf("pid %d failed to start\n", (int)getpid());
					_exit(1);
				}
				smb_msleep(10);	
			}

			child_status[i] = getpid();

			while (child_status[i] && timeval_elapsed(&start) < 5) smb_msleep(2);

			child_status_out[i] = fn(i);
			_exit(0);
		}
	}

	do {
		synccount = 0;
		for (i=0;i<torture_nprocs;i++) {
			if (child_status[i]) synccount++;
		}
		if (synccount == torture_nprocs) break;
		smb_msleep(10);
	} while (timeval_elapsed(&start) < 30);

	if (synccount != torture_nprocs) {
		printf("FAILED TO START %d CLIENTS (started %d)\n", torture_nprocs, synccount);
		*result = False;
		return timeval_elapsed(&start);
	}

	/* start the client load */
	start = timeval_current();

	for (i=0;i<torture_nprocs;i++) {
		child_status[i] = 0;
	}

	printf("%d clients started\n", torture_nprocs);

	for (i=0;i<torture_nprocs;i++) {
		while (waitpid(0, &status, 0) == -1 && errno == EINTR) /* noop */ ;
	}

	printf("\n");

	for (i=0;i<torture_nprocs;i++) {
		if (!child_status_out[i]) {
			*result = False;
		}
	}
	return timeval_elapsed(&start);
}

#define FLAG_MULTIPROC 1

static struct {
	const char *name;
	bool (*fn)(int);
	unsigned flags;
} torture_ops[] = {
	{"FDPASS", run_fdpasstest, 0},
	{"LOCK1",  run_locktest1,  0},
	{"LOCK2",  run_locktest2,  0},
	{"LOCK3",  run_locktest3,  0},
	{"LOCK4",  run_locktest4,  0},
	{"LOCK5",  run_locktest5,  0},
	{"LOCK6",  run_locktest6,  0},
	{"LOCK7",  run_locktest7,  0},
	{"LOCK8",  run_locktest8,  0},
	{"LOCK9",  run_locktest9,  0},
	{"UNLINK", run_unlinktest, 0},
	{"BROWSE", run_browsetest, 0},
	{"ATTR",   run_attrtest,   0},
	{"TRANS2", run_trans2test, 0},
	{"MAXFID", run_maxfidtest, FLAG_MULTIPROC},
	{"TORTURE",run_torture,    FLAG_MULTIPROC},
	{"RANDOMIPC", run_randomipc, 0},
	{"NEGNOWAIT", run_negprot_nowait, 0},
	{"NBENCH",  run_nbench, 0},
	{"NBENCH2", run_nbench2, 0},
	{"OPLOCK1",  run_oplock1, 0},
	{"OPLOCK2",  run_oplock2, 0},
	{"OPLOCK4",  run_oplock4, 0},
	{"DIR",  run_dirtest, 0},
	{"DIR1",  run_dirtest1, 0},
	{"DIR-CREATETIME",  run_dir_createtime, 0},
	{"DENY1",  torture_denytest1, 0},
	{"DENY2",  torture_denytest2, 0},
	{"TCON",  run_tcon_test, 0},
	{"TCONDEV",  run_tcon_devtype_test, 0},
	{"RW1",  run_readwritetest, 0},
	{"RW2",  run_readwritemulti, FLAG_MULTIPROC},
	{"RW3",  run_readwritelarge, 0},
	{"RW-SIGNING",  run_readwritelarge_signtest, 0},
	{"OPEN", run_opentest, 0},
	{"POSIX", run_simple_posix_open_test, 0},
	{"POSIX-APPEND", run_posix_append, 0},
	{"CASE-INSENSITIVE-CREATE", run_case_insensitive_create, 0},
	{"ASYNC-ECHO", run_async_echo, 0},
	{ "UID-REGRESSION-TEST", run_uid_regression_test, 0},
	{ "SHORTNAME-TEST", run_shortname_test, 0},
	{ "ADDRCHANGE", run_addrchange, 0},
#if 1
	{"OPENATTR", run_openattrtest, 0},
#endif
	{"XCOPY", run_xcopy, 0},
	{"RENAME", run_rename, 0},
	{"DELETE", run_deletetest, 0},
	{"DELETE-LN", run_deletetest_ln, 0},
	{"PROPERTIES", run_properties, 0},
	{"MANGLE", torture_mangle, 0},
	{"MANGLE1", run_mangle1, 0},
	{"W2K", run_w2ktest, 0},
	{"TRANS2SCAN", torture_trans2_scan, 0},
	{"NTTRANSSCAN", torture_nttrans_scan, 0},
	{"UTABLE", torture_utable, 0},
	{"CASETABLE", torture_casetable, 0},
	{"ERRMAPEXTRACT", run_error_map_extract, 0},
	{"PIPE_NUMBER", run_pipe_number, 0},
	{"TCON2",  run_tcon2_test, 0},
	{"IOCTL",  torture_ioctl_test, 0},
	{"CHKPATH",  torture_chkpath_test, 0},
	{"FDSESS", run_fdsesstest, 0},
	{ "EATEST", run_eatest, 0},
	{ "SESSSETUP_BENCH", run_sesssetup_bench, 0},
	{ "CHAIN1", run_chain1, 0},
	{ "CHAIN2", run_chain2, 0},
	{ "CHAIN3", run_chain3, 0},
	{ "WINDOWS-WRITE", run_windows_write, 0},
	{ "LARGE_READX", run_large_readx, 0},
	{ "NTTRANS-CREATE", run_nttrans_create, 0},
	{ "NTTRANS-FSCTL", run_nttrans_fsctl, 0},
	{ "CLI_ECHO", run_cli_echo, 0},
	{ "GETADDRINFO", run_getaddrinfo_send, 0},
	{ "TLDAP", run_tldap },
	{ "STREAMERROR", run_streamerror },
	{ "NOTIFY-BENCH", run_notify_bench },
	{ "NOTIFY-BENCH2", run_notify_bench2 },
	{ "NOTIFY-BENCH3", run_notify_bench3 },
	{ "BAD-NBT-SESSION", run_bad_nbt_session },
	{ "SMB-ANY-CONNECT", run_smb_any_connect },
	{ "NOTIFY-ONLINE", run_notify_online },
	{ "SMB2-BASIC", run_smb2_basic },
	{ "SMB2-NEGPROT", run_smb2_negprot },
	{ "SMB2-SESSION-RECONNECT", run_smb2_session_reconnect },
	{ "SMB2-TCON-DEPENDENCE", run_smb2_tcon_dependence },
	{ "SMB2-MULTI-CHANNEL", run_smb2_multi_channel },
	{ "SMB2-SESSION-REAUTH", run_smb2_session_reauth },
	{ "CLEANUP1", run_cleanup1 },
	{ "CLEANUP2", run_cleanup2 },
	{ "CLEANUP3", run_cleanup3 },
	{ "CLEANUP4", run_cleanup4 },
	{ "OPLOCK-CANCEL", run_oplock_cancel },
	{ "LOCAL-SUBSTITUTE", run_local_substitute, 0},
	{ "LOCAL-GENCACHE", run_local_gencache, 0},
	{ "LOCAL-TALLOC-DICT", run_local_talloc_dict, 0},
	{ "LOCAL-CTDB-CONN", run_ctdb_conn, 0},
	{ "LOCAL-DBWRAP-WATCH1", run_dbwrap_watch1, 0 },
	{ "LOCAL-MESSAGING-READ1", run_messaging_read1, 0 },
	{ "LOCAL-MESSAGING-READ2", run_messaging_read2, 0 },
	{ "LOCAL-MESSAGING-READ3", run_messaging_read3, 0 },
	{ "LOCAL-MESSAGING-READ4", run_messaging_read4, 0 },
	{ "LOCAL-MESSAGING-FDPASS1", run_messaging_fdpass1, 0 },
	{ "LOCAL-MESSAGING-FDPASS2", run_messaging_fdpass2, 0 },
	{ "LOCAL-BASE64", run_local_base64, 0},
	{ "LOCAL-RBTREE", run_local_rbtree, 0},
	{ "LOCAL-MEMCACHE", run_local_memcache, 0},
	{ "LOCAL-STREAM-NAME", run_local_stream_name, 0},
	{ "LOCAL-WBCLIENT", run_local_wbclient, 0},
	{ "LOCAL-string_to_sid", run_local_string_to_sid, 0},
	{ "LOCAL-sid_to_string", run_local_sid_to_string, 0},
	{ "LOCAL-binary_to_sid", run_local_binary_to_sid, 0},
	{ "LOCAL-DBTRANS", run_local_dbtrans, 0},
	{ "LOCAL-TEVENT-SELECT", run_local_tevent_select, 0},
	{ "LOCAL-CONVERT-STRING", run_local_convert_string, 0},
	{ "LOCAL-CONV-AUTH-INFO", run_local_conv_auth_info, 0},
	{ "LOCAL-sprintf_append", run_local_sprintf_append, 0},
	{ "LOCAL-hex_encode_buf", run_local_hex_encode_buf, 0},
	{ "LOCAL-IDMAP-TDB-COMMON", run_idmap_tdb_common_test, 0},
	{ "LOCAL-remove_duplicate_addrs2", run_local_remove_duplicate_addrs2, 0},
	{ "local-tdb-opener", run_local_tdb_opener, 0 },
	{ "local-tdb-writer", run_local_tdb_writer, 0 },
	{ "LOCAL-DBWRAP-CTDB", run_local_dbwrap_ctdb, 0 },
	{ "LOCAL-BENCH-PTHREADPOOL", run_bench_pthreadpool, 0 },
	{ "qpathinfo-bufsize", run_qpathinfo_bufsize, 0 },
	{NULL, NULL, 0}};

/*
 * dummy function to satisfy linker dependency
 */
struct tevent_context *winbind_event_context(void);
struct tevent_context *winbind_event_context(void)
{
	return NULL;
}

/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
static bool run_test(const char *name)
{
	bool ret = True;
	bool result = True;
	bool found = False;
	int i;
	double t;
	if (strequal(name,"ALL")) {
		for (i=0;torture_ops[i].name;i++) {
			run_test(torture_ops[i].name);
		}
		found = True;
	}

	for (i=0;torture_ops[i].name;i++) {
		fstr_sprintf(randomfname, "\\XX%x", 
			 (unsigned)random());

		if (strequal(name, torture_ops[i].name)) {
			found = True;
			printf("Running %s\n", name);
			if (torture_ops[i].flags & FLAG_MULTIPROC) {
				t = create_procs(torture_ops[i].fn, &result);
				if (!result) { 
					ret = False;
					printf("TEST %s FAILED!\n", name);
				}
			} else {
				struct timeval start;
				start = timeval_current();
				if (!torture_ops[i].fn(0)) {
					ret = False;
					printf("TEST %s FAILED!\n", name);
				}
				t = timeval_elapsed(&start);
			}
			printf("%s took %g secs\n\n", name, t);
		}
	}

	if (!found) {
		printf("Did not find a test named %s\n", name);
		ret = False;
	}

	return ret;
}


static void usage(void)
{
	int i;

	printf("WARNING samba4 test suite is much more complete nowadays.\n");
	printf("Please use samba4 torture.\n\n");

	printf("Usage: smbtorture //server/share <options> TEST1 TEST2 ...\n");

	printf("\t-d debuglevel\n");
	printf("\t-U user%%pass\n");
	printf("\t-k                    use kerberos\n");
	printf("\t-N numprocs\n");
	printf("\t-n my_netbios_name\n");
	printf("\t-W workgroup\n");
	printf("\t-o num_operations\n");
	printf("\t-O socket_options\n");
	printf("\t-m maximum protocol\n");
	printf("\t-L use oplocks\n");
	printf("\t-c CLIENT.TXT         specify client load file for NBENCH\n");
	printf("\t-A showall\n");
	printf("\t-p port\n");
	printf("\t-s seed\n");
	printf("\t-b unclist_filename   specify multiple shares for multiple connections\n");
	printf("\t-f filename           filename to test\n");
	printf("\t-e                    encrypt\n");
	printf("\n\n");

	printf("tests are:");
	for (i=0;torture_ops[i].name;i++) {
		printf(" %s", torture_ops[i].name);
	}
	printf("\n");

	printf("default test is ALL\n");

	exit(1);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	int opt, i;
	char *p;
	int gotuser = 0;
	int gotpass = 0;
	bool correct = True;
	TALLOC_CTX *frame = talloc_stackframe();
	int seed = time(NULL);

#ifdef HAVE_SETBUFFER
	setbuffer(stdout, NULL, 0);
#endif

	setup_logging("smbtorture", DEBUG_STDOUT);

	load_case_tables();
	fault_setup();

	if (is_default_dyn_CONFIGFILE()) {
		if(getenv("SMB_CONF_PATH")) {
			set_dyn_CONFIGFILE(getenv("SMB_CONF_PATH"));
		}
	}
	lp_load_global(get_dyn_CONFIGFILE());
	load_interfaces();

	if (argc < 2) {
		usage();
	}

        for(p = argv[1]; *p; p++)
          if(*p == '\\')
            *p = '/';

	if (strncmp(argv[1], "//", 2)) {
		usage();
	}

	fstrcpy(host, &argv[1][2]);
	p = strchr_m(&host[2],'/');
	if (!p) {
		usage();
	}
	*p = 0;
	fstrcpy(share, p+1);

	fstrcpy(myname, get_myname(talloc_tos()));
	if (!*myname) {
		fprintf(stderr, "Failed to get my hostname.\n");
		return 1;
	}

	if (*username == 0 && getenv("LOGNAME")) {
	  fstrcpy(username,getenv("LOGNAME"));
	}

	argc--;
	argv++;

	fstrcpy(workgroup, lp_workgroup());

	while ((opt = getopt(argc, argv, "p:hW:U:n:N:O:o:m:Ll:d:Aec:ks:b:B:f:"))
	       != EOF) {
		switch (opt) {
		case 'p':
			port_to_use = atoi(optarg);
			break;
		case 's':
			seed = atoi(optarg);
			break;
		case 'W':
			fstrcpy(workgroup,optarg);
			break;
		case 'm':
			lp_set_cmdline("client max protocol", optarg);
			break;
		case 'N':
			torture_nprocs = atoi(optarg);
			break;
		case 'o':
			torture_numops = atoi(optarg);
			break;
		case 'd':
			lp_set_cmdline("log level", optarg);
			break;
		case 'O':
			sockops = optarg;
			break;
		case 'L':
			use_oplocks = True;
			break;
		case 'l':
			local_path = optarg;
			break;
		case 'A':
			torture_showall = True;
			break;
		case 'n':
			fstrcpy(myname, optarg);
			break;
		case 'c':
			client_txt = optarg;
			break;
		case 'e':
			do_encrypt = true;
			break;
		case 'k':
#ifdef HAVE_KRB5
			use_kerberos = True;
#else
			d_printf("No kerberos support compiled in\n");
			exit(1);
#endif
			break;
		case 'U':
			gotuser = 1;
			fstrcpy(username,optarg);
			p = strchr_m(username,'%');
			if (p) {
				*p = 0;
				fstrcpy(password, p+1);
				gotpass = 1;
			}
			break;
		case 'b':
			fstrcpy(multishare_conn_fname, optarg);
			use_multishare_conn = True;
			break;
		case 'B':
			torture_blocksize = atoi(optarg);
			break;
		case 'f':
			test_filename = SMB_STRDUP(optarg);
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			usage();
		}
	}

	d_printf("using seed %d\n", seed);

	srandom(seed);

	if(use_kerberos && !gotuser) gotpass = True;

	while (!gotpass) {
		char pwd[256] = {0};
		int rc;

		rc = samba_getpass("Password:", pwd, sizeof(pwd), false, false);
		if (rc == 0) {
			fstrcpy(password, pwd);
			gotpass = 1;
		}
	}

	printf("host=%s share=%s user=%s myname=%s\n", 
	       host, share, username, myname);

	if (argc == optind) {
		correct = run_test("ALL");
	} else {
		for (i=optind;i<argc;i++) {
			if (!run_test(argv[i])) {
				correct = False;
			}
		}
	}

	TALLOC_FREE(frame);

	if (correct) {
		return(0);
	} else {
		return(1);
	}
}
