/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Guenther Deschner 2010

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
#include "system/dir.h"
#include "torture/smbtorture.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include <libsmbclient.h>
#include "torture/libsmbclient/proto.h"
#include "lib/param/loadparm.h"
#include "lib/param/param_global.h"
#include "dynconfig.h"

/* test string to compare with when debug_callback is called */
#define TEST_STRING "smbc_setLogCallback test"

/* Dummy log callback function */
static void debug_callback(void *private_ptr, int level, const char *msg)
{
	bool *found = private_ptr;
	if (strstr(msg, TEST_STRING) != NULL) {
		*found = true;
	}
	return;
}

static void auth_callback(const char *srv,
			  const char *shr,
			  char *wg, int wglen,
			  char *un, int unlen,
			  char *pw, int pwlen)
{
	const char *workgroup =
		cli_credentials_get_domain(popt_get_cmdline_credentials());
	const char *username =
		cli_credentials_get_username(popt_get_cmdline_credentials());
	const char *password =
		cli_credentials_get_password(popt_get_cmdline_credentials());
	ssize_t ret;

	if (workgroup != NULL) {
		ret = strlcpy(wg, workgroup, wglen);
		if (ret >= wglen) {
			abort();
		}
	}

	if (username != NULL) {
		ret = strlcpy(un, username, unlen);
		if (ret >= unlen) {
			abort();
		}
	}

	if (password != NULL) {
		ret = strlcpy(pw, password, pwlen);
		if (ret >= pwlen) {
			abort();
		}
	}
};

bool torture_libsmbclient_init_context(struct torture_context *tctx,
				       SMBCCTX **ctx_p)
{
	const char *workgroup =
		cli_credentials_get_domain(popt_get_cmdline_credentials());
	const char *username =
		cli_credentials_get_username(popt_get_cmdline_credentials());
	const char *client_proto =
		torture_setting_string(tctx, "clientprotocol", NULL);
	SMBCCTX *ctx = NULL;
	SMBCCTX *p = NULL;
	bool ok = true;
	int dbglevel = DEBUGLEVEL;

	ctx = smbc_new_context();
	torture_assert_not_null_goto(tctx,
				     ctx,
				     ok,
				     out,
				     "Failed to create new context");

	p = smbc_init_context(ctx);
	torture_assert_not_null_goto(tctx,
				     p,
				     ok,
				     out,
				     "Failed to initialize context");

	smbc_setDebug(ctx, dbglevel);
	smbc_setOptionDebugToStderr(ctx, 1);

	if (workgroup != NULL) {
		smbc_setWorkgroup(ctx, workgroup);
	}
	if (username != NULL) {
		smbc_setUser(ctx, username);
	}

	smbc_setFunctionAuthData(ctx, auth_callback);

	if (client_proto != NULL) {
		smbc_setOptionProtocols(ctx, client_proto, client_proto);
	}

	*ctx_p = ctx;

out:
	if (!ok) {
		smbc_free_context(ctx, 1);
	}

	return ok;
}

static bool torture_libsmbclient_version(struct torture_context *tctx)
{
	torture_comment(tctx, "Testing smbc_version\n");

	torture_assert(tctx, smbc_version(), "failed to get version");

	return true;
}

static bool torture_libsmbclient_initialize(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ret = false;

	torture_comment(tctx, "Testing smbc_new_context\n");

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");

	torture_comment(tctx, "Testing smbc_init_context\n");

	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	smbc_setLogCallback(ctx, &ret, debug_callback);
	DEBUG(0, (TEST_STRING"\n"));
	torture_assert(tctx, ret, "Failed debug_callback not called");
	ret = false;
	smbc_setLogCallback(ctx, NULL, NULL);
	DEBUG(0, (TEST_STRING"\n"));
	torture_assert(tctx, !ret, "Failed debug_callback called");

	smbc_free_context(ctx, 1);

	return true;
}

static bool torture_libsmbclient_setConfiguration(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	struct loadparm_global *global_config = NULL;
	const char *new_smb_conf = torture_setting_string(tctx,
				"replace_smbconf",
				"");

	ctx = smbc_new_context();
	torture_assert_not_null(tctx, ctx, "failed to get new context");

	torture_assert_not_null(
		tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_setConfiguration - new file %s\n",
		new_smb_conf);

	global_config = get_globals();
	torture_assert(tctx, global_config, "Global Config is NULL");

	/* check configuration before smbc_setConfiguration call */
	torture_comment(tctx, "'workgroup' before setConfiguration %s\n",
			global_config->workgroup);
	torture_comment(tctx, "'client min protocol' before "
			"setConfiguration %d\n",
			global_config->client_min_protocol);
	torture_comment(tctx, "'client max protocol' before "
			"setConfiguration %d\n",
			global_config->_client_max_protocol);
	torture_comment(tctx, "'client signing' before setConfiguration %d\n",
			global_config->client_signing);
	torture_comment(tctx, "'deadtime' before setConfiguration %d\n",
			global_config->deadtime);

	torture_assert_int_equal(tctx, smbc_setConfiguration(ctx, new_smb_conf),
			0, "setConfiguration conf file not found");

	/* verify configuration */
	torture_assert_str_equal(tctx, global_config->workgroup,
			"NEW_WORKGROUP",
			"smbc_setConfiguration failed, "
			"'workgroup' not updated");
	torture_assert_int_equal(tctx, global_config->client_min_protocol, 7,
			"smbc_setConfiguration failed, 'client min protocol' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->_client_max_protocol, 13,
			"smbc_setConfiguration failed, 'client max protocol' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->client_signing, 1,
			"smbc_setConfiguration failed, 'client signing' "
			"not updated");
	torture_assert_int_equal(tctx, global_config->deadtime, 5,
			"smbc_setConfiguration failed, 'deadtime' not updated");

	/* Restore configuration to default */
	smbc_setConfiguration(ctx, get_dyn_CONFIGFILE());

	smbc_free_context(ctx, 1);

	return true;
}

static bool test_opendir(struct torture_context *tctx,
			 SMBCCTX *ctx,
			 const char *fname,
			 bool expect_success)
{
	int handle, ret;

	torture_comment(tctx, "Testing smbc_opendir(%s)\n", fname);

	handle = smbc_opendir(fname);
	if (!expect_success) {
		return true;
	}
	if (handle < 0) {
		torture_fail(tctx, talloc_asprintf(tctx, "failed to obain file handle for '%s'", fname));
	}

	ret = smbc_closedir(handle);
	torture_assert_int_equal(tctx, ret, 0,
		talloc_asprintf(tctx, "failed to close file handle for '%s'", fname));

	return true;
}

static bool torture_libsmbclient_opendir(struct torture_context *tctx)
{
	size_t i;
	SMBCCTX *ctx;
	bool ret = true;
	const char *bad_urls[] = {
		"",
		NULL,
		"smb",
		"smb:",
		"smb:/",
		"smb:///",
		"bms://",
		":",
		":/",
		"://",
		":///",
		"/",
		"//",
		"///"
	};
	const char *good_urls[] = {
		"smb://",
		"smb://WORKGROUP",
		"smb://WORKGROUP/"
	};

	torture_assert(tctx, torture_libsmbclient_init_context(tctx, &ctx), "");
	smbc_set_context(ctx);

	for (i=0; i < ARRAY_SIZE(bad_urls); i++) {
		ret &= test_opendir(tctx, ctx, bad_urls[i], false);
	}
	for (i=0; i < ARRAY_SIZE(good_urls); i++) {
		ret &= test_opendir(tctx, ctx, good_urls[i], true);
	}

	smbc_free_context(ctx, 1);

	return ret;
}

static bool torture_libsmbclient_readdirplus(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	int ret = -1;
	int dhandle = -1;
	int fhandle = -1;
	bool found = false;
	const char *filename = NULL;
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);

	if (smburl == NULL) {
		torture_fail(tctx,
			"option --option=torture:smburl="
			"smb://user:password@server/share missing\n");
	}

	torture_assert(tctx, torture_libsmbclient_init_context(tctx, &ctx), "");
	smbc_set_context(ctx);

	filename = talloc_asprintf(tctx,
				"%s/test_readdirplus.txt",
				smburl);
	if (filename == NULL) {
		torture_fail(tctx,
			"talloc fail\n");
	}
	/* Ensure the file doesn't exist. */
	smbc_unlink(filename);

	/* Create it. */
	fhandle = smbc_creat(filename, 0666);
	if (fhandle < 0) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to create file '%s': %s",
				filename,
				strerror(errno)));
	}
	ret = smbc_close(fhandle);
	torture_assert_int_equal(tctx,
		ret,
		0,
		talloc_asprintf(tctx,
			"failed to close handle for '%s'",
			filename));

	dhandle = smbc_opendir(smburl);
	if (dhandle < 0) {
		int saved_errno = errno;
		smbc_unlink(filename);
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to obtain "
				"directory handle for '%s' : %s",
				smburl,
				strerror(saved_errno)));
	}

	/* Readdirplus to ensure we see the new file. */
	for (;;) {
		const struct libsmb_file_info *exstat =
			smbc_readdirplus(dhandle);
		if (exstat == NULL) {
			break;
		}
		if (strcmp(exstat->name, "test_readdirplus.txt") == 0) {
			found = true;
			break;
		}
	}

	/* Remove it again. */
	smbc_unlink(filename);
	ret = smbc_closedir(dhandle);
	torture_assert_int_equal(tctx,
		ret,
		0,
		talloc_asprintf(tctx,
			"failed to close directory handle for '%s'",
			smburl));

	smbc_free_context(ctx, 1);

	if (!found) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
				"failed to find file '%s'",
				filename));
	}

	return true;
}

static bool torture_libsmbclient_readdirplus_seek(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	int ret = -1;
	int dhandle = -1;
	int fhandle = -1;
	const char *dname = NULL;
	const char *full_filename[100] = {0};
	const char *filename[100] = {0};
	const struct libsmb_file_info *direntries[102] = {0};
	unsigned int i = 0;
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);
	bool success = false;
	off_t telldir_50 = (off_t)-1;
	off_t telldir_20 = (off_t)-1;
	size_t getdentries_size = 0;
	struct smbc_dirent *getdentries = NULL;
	struct smbc_dirent *dirent_20 = NULL;
	const struct libsmb_file_info *direntries_20 = NULL;
	const struct libsmb_file_info *direntriesplus_20 = NULL;
	const char *plus2_stat_path = NULL;
	struct stat st = {0};
	struct stat st2 = {0};

	torture_assert_not_null(
		tctx,
		smburl,
		"option --option=torture:smburl="
		"smb://user:password@server/share missing\n");

	DEBUG(0,("torture_libsmbclient_readdirplus_seek start\n"));

	torture_assert(tctx, torture_libsmbclient_init_context(tctx, &ctx), "");
	smbc_set_context(ctx);

	dname = talloc_asprintf(tctx,
				"%s/rd_seek",
				smburl);
	torture_assert_not_null_goto(
		tctx, dname, success, done, "talloc fail\n");

	/* Ensure the files don't exist. */
	for (i = 0; i < 100; i++) {
		filename[i] = talloc_asprintf(tctx,
				"test_readdirplus_%u.txt",
				i);
		torture_assert_not_null_goto(
			tctx, filename[i], success, done, "talloc fail");
		full_filename[i] = talloc_asprintf(tctx,
				"%s/%s",
				dname,
				filename[i]);
		torture_assert_not_null_goto(
			tctx, full_filename[i], success, done, "talloc fail");
		(void)smbc_unlink(full_filename[i]);
	}
	/* Ensure the directory doesn't exist. */
	(void)smbc_rmdir(dname);

	/* Create containing directory. */
	ret = smbc_mkdir(dname, 0777);
	torture_assert_goto(
		tctx,
		ret == 0,
		success,
		done,
		talloc_asprintf(tctx,
				"failed to create directory '%s': %s",
				dname,
				strerror(errno)));

	DEBUG(0,("torture_libsmbclient_readdirplus_seek create\n"));

	/* Create them. */
	for (i = 0; i < 100; i++) {
		fhandle = smbc_creat(full_filename[i], 0666);
		if (fhandle < 0) {
			torture_fail_goto(tctx,
				done,
				talloc_asprintf(tctx,
					"failed to create file '%s': %s",
					full_filename[i],
					strerror(errno)));
		}
		ret = smbc_close(fhandle);
		torture_assert_int_equal_goto(tctx,
			ret,
			0,
			success,
			done,
			talloc_asprintf(tctx,
				"failed to close handle for '%s'",
				full_filename[i]));
	}

	DEBUG(0,("torture_libsmbclient_readdirplus_seek enum\n"));

	/* Now enumerate the directory. */
	dhandle = smbc_opendir(dname);
	torture_assert_goto(
		tctx,
		dhandle >= 0,
		success,
		done,
		talloc_asprintf(tctx,
				"failed to obtain "
				"directory handle for '%s' : %s",
				dname,
				strerror(errno)));

	/* Read all the files. 100 we created plus . and .. */
	for (i = 0; i < 102; i++) {
		bool found = false;
		unsigned int j;

		direntries[i] = smbc_readdirplus(dhandle);
		if (direntries[i] == NULL) {
			break;
		}

		/* Store at offset 50. */
		if (i == 50) {
			telldir_50 = smbc_telldir(dhandle);
			torture_assert_goto(
				tctx,
				telldir_50 != (off_t)-1,
				success,
				done,
				talloc_asprintf(tctx,
						"telldir failed file %s\n",
						direntries[i]->name));
		}

		if (ISDOT(direntries[i]->name)) {
			continue;
		}
		if (ISDOTDOT(direntries[i]->name)) {
			continue;
		}

		/* Ensure all our files exist. */
		for (j = 0; j < 100; j++) {
			if (strcmp(direntries[i]->name,
				filename[j]) == 0) {
				found = true;
			}
		}
		torture_assert_goto(
			tctx,
			found,
			success,
			done,
			talloc_asprintf(tctx,
					"failed to find file %s\n",
					direntries[i]->name));
	}

	/*
	 * We're seeking on in-memory lists here, so
	 * whilst the handle is open we really should
	 * get the same files back in the same order.
	 */

	ret = smbc_lseekdir(dhandle, telldir_50);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to seek (50) directory handle for '%s'",
			dname));

	DEBUG(0,("torture_libsmbclient_readdirplus_seek seek\n"));

	for (i = 51; i < 102; i++) {
		const struct libsmb_file_info *entry =
				smbc_readdirplus(dhandle);
		torture_assert_goto(
			tctx,
			entry == direntries[i],
			success,
			done,
			talloc_asprintf(tctx,
					"after seek - failed to find "
					"file %s - got %s\n",
					direntries[i]->name,
					entry->name));
	}

	/* Seek back to the start. */
	ret = smbc_lseekdir(dhandle, 0);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to seek directory handle to start for '%s'",
			dname));

	/*
	 * Mix getdents/readdir/readdirplus with lseek to ensure
	 * we get the same result.
	 */

	/* Allocate the space for 20 entries.
	 * Tricky as we need to allocate 20 struct smbc_dirent's + space
	 * for the name lengths.
	 */
	getdentries_size = 20 * (sizeof(struct smbc_dirent) +
				strlen("test_readdirplus_1000.txt") + 1);

	getdentries = (struct smbc_dirent *)talloc_array_size(tctx,
						getdentries_size,
						1);
	torture_assert_not_null_goto(
		tctx,
		getdentries,
		success,
		done,
		"talloc fail");

	ret = smbc_getdents(dhandle, getdentries, getdentries_size);
	torture_assert_goto(tctx,
		(ret != -1),
		success,
		done,
		talloc_asprintf(tctx,
			"smbd_getdents(1) for '%s' failed\n",
			dname));

	telldir_20 = smbc_telldir(dhandle);
	torture_assert_goto(
		tctx,
		telldir_20 != (off_t)-1,
		success,
		done,
		"telldir (20) failed\n");

	/* Read another 20. */
	ret = smbc_getdents(dhandle, getdentries, getdentries_size);
	torture_assert_goto(tctx,
		(ret != -1),
		success,
		done,
		talloc_asprintf(tctx,
			"smbd_getdents(2) for '%s' failed\n",
			dname));

	/* Seek back to 20. */
	ret = smbc_lseekdir(dhandle, telldir_20);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to seek (20) directory handle for '%s'",
			dname));

	/* Read with readdir. */
	dirent_20 = smbc_readdir(dhandle);
	torture_assert_not_null_goto(
		tctx,
		dirent_20,
		success,
		done,
		"smbc_readdir (20) failed\n");

	/* Ensure the getdents and readdir names are the same. */
	ret = strcmp(dirent_20->name, getdentries[0].name);
	torture_assert_goto(
		tctx,
		ret == 0,
		success,
		done,
		talloc_asprintf(tctx,
				"after seek (20) readdir name missmatch "
				"file %s - got %s\n",
				dirent_20->name,
				getdentries[0].name));

	/* Seek back to 20. */
	ret = smbc_lseekdir(dhandle, telldir_20);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to seek (20) directory handle for '%s'",
			dname));
	/* Read with readdirplus. */
	direntries_20 = smbc_readdirplus(dhandle);
	torture_assert_not_null_goto(
		tctx,
		direntries_20,
		success,
		done,
		"smbc_readdirplus (20) failed\n");

	/* Ensure the readdirplus and readdir names are the same. */
	ret = strcmp(dirent_20->name, direntries_20->name);
	torture_assert_goto(
		tctx,
		ret == 0,
		success,
		done,
		talloc_asprintf(tctx,
				"after seek (20) readdirplus name missmatch "
				"file %s - got %s\n",
				dirent_20->name,
				direntries_20->name));

	/* Seek back to 20. */
	ret = smbc_lseekdir(dhandle, telldir_20);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to seek (20) directory handle for '%s'",
			dname));

	/* Read with readdirplus2. */
	direntriesplus_20 = smbc_readdirplus2(dhandle, &st2);
	torture_assert_not_null_goto(
		tctx,
		direntriesplus_20,
		success,
		done,
		"smbc_readdirplus2 (20) failed\n");

	/* Ensure the readdirplus2 and readdirplus names are the same. */
	ret = strcmp(direntries_20->name, direntriesplus_20->name);
	torture_assert_goto(
		tctx,
		ret == 0,
		success,
		done,
		talloc_asprintf(tctx,
				"after seek (20) readdirplus2 name missmatch "
				"file %s - got %s\n",
				dirent_20->name,
				direntries_20->name));

	/* Ensure doing stat gets the same data. */
	plus2_stat_path = talloc_asprintf(tctx,
				"%s/%s",
				dname,
				direntriesplus_20->name);
	torture_assert_not_null_goto(
		tctx,
		plus2_stat_path,
		success,
		done,
		"talloc fail\n");

	ret = smbc_stat(plus2_stat_path, &st);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to stat file '%s'",
			plus2_stat_path));

	torture_assert_int_equal(tctx,
		st.st_ino,
		st2.st_ino,
		talloc_asprintf(tctx,
			"file %s mismatched ino value "
			"stat got %"PRIx64" readdirplus2 got %"PRIx64"" ,
			plus2_stat_path,
			(uint64_t)st.st_ino,
			(uint64_t)st2.st_ino));

	torture_assert_int_equal(tctx,
		st.st_dev,
		st2.st_dev,
		talloc_asprintf(tctx,
			"file %s mismatched dev value "
			"stat got %"PRIx64" readdirplus2 got %"PRIx64"" ,
			plus2_stat_path,
			(uint64_t)st.st_dev,
			(uint64_t)st2.st_dev));

	ret = smbc_closedir(dhandle);
	torture_assert_int_equal(tctx,
		ret,
		0,
		talloc_asprintf(tctx,
			"failed to close directory handle for '%s'",
			dname));

	dhandle = -1;
	success = true;

  done:

	/* Clean up. */
	if (dhandle != -1) {
		smbc_closedir(dhandle);
	}
	for (i = 0; i < 100; i++) {
		if (full_filename[i] != NULL) {
			smbc_unlink(full_filename[i]);
		}
	}
	if (dname != NULL) {
		smbc_rmdir(dname);
	}

	smbc_free_context(ctx, 1);

	return success;
}

#ifndef SMBC_FILE_MODE
#define SMBC_FILE_MODE (S_IFREG | 0444)
#endif

static bool torture_libsmbclient_readdirplus2(struct torture_context *tctx)
{
	SMBCCTX *ctx = NULL;
	int dhandle = -1;
	int fhandle = -1;
	bool found = false;
	bool success = false;
	const char *filename = NULL;
	struct stat st2 = {0};
	struct stat st = {0};
	int ret;
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);

	if (smburl == NULL) {
		torture_fail(tctx,
			"option --option=torture:smburl="
			"smb://user:password@server/share missing\n");
	}

	torture_assert_goto(tctx, torture_libsmbclient_init_context(tctx, &ctx), success, done, "");
	smbc_set_context(ctx);

	filename = talloc_asprintf(tctx,
			"%s/test_readdirplus.txt",
			smburl);
	if (filename == NULL) {
		torture_fail_goto(tctx, done, "talloc fail\n");
	}

	/* Ensure the file doesn't exist. */
	smbc_unlink(filename);

	/* Create it. */
	fhandle = smbc_creat(filename, 0666);
	if (fhandle < 0) {
		torture_fail_goto(tctx,
			done,
			talloc_asprintf(tctx,
				"failed to create file '%s': %s",
				filename,
				strerror(errno)));
	}
	ret = smbc_close(fhandle);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to close handle for '%s'",
			filename));

	dhandle = smbc_opendir(smburl);
	if (dhandle < 0) {
		int saved_errno = errno;
		smbc_unlink(filename);
		torture_fail_goto(tctx,
			done,
			talloc_asprintf(tctx,
				"failed to obtain "
				"directory handle for '%s' : %s",
				smburl,
				strerror(saved_errno)));
	}

	/* readdirplus2 to ensure we see the new file. */
	for (;;) {
		const struct libsmb_file_info *exstat =
			smbc_readdirplus2(dhandle, &st2);
		if (exstat == NULL) {
			break;
		}

		if (strcmp(exstat->name, "test_readdirplus.txt") == 0) {
			found = true;
			break;
		}
	}

	if (!found) {
		smbc_unlink(filename);
		torture_fail_goto(tctx,
			done,
			talloc_asprintf(tctx,
				"failed to find file '%s'",
				filename));
	}

	/* Ensure mode is as expected. */
	/*
	 * New file gets SMBC_FILE_MODE plus
	 * archive bit -> S_IXUSR
	 * !READONLY -> S_IWUSR.
	 */
	torture_assert_int_equal_goto(tctx,
		st2.st_mode,
		SMBC_FILE_MODE|S_IXUSR|S_IWUSR,
		success,
		done,
		talloc_asprintf(tctx,
			"file %s st_mode should be 0%o, got 0%o'",
			filename,
			SMBC_FILE_MODE|S_IXUSR|S_IWUSR,
			(unsigned int)st2.st_mode));

	/* Ensure smbc_stat() gets the same data. */
	ret = smbc_stat(filename, &st);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to stat file '%s'",
			filename));

	torture_assert_int_equal_goto(tctx,
		st2.st_ino,
		st.st_ino,
		success,
		done,
		talloc_asprintf(tctx,
			"filename '%s' ino missmatch. "
			"From smbc_readdirplus2 = %"PRIx64" "
			"From smbc_stat = %"PRIx64"",
			filename,
			(uint64_t)st2.st_ino,
			(uint64_t)st.st_ino));


	/* Remove it again. */
	smbc_unlink(filename);
	ret = smbc_closedir(dhandle);
	torture_assert_int_equal_goto(tctx,
		ret,
		0,
		success,
		done,
		talloc_asprintf(tctx,
			"failed to close directory handle for '%s'",
			filename));
	success = true;

  done:
	smbc_free_context(ctx, 1);
	return success;
}

bool torture_libsmbclient_configuration(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ok = true;

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");
	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_(set|get)Debug\n");
	smbc_setDebug(ctx, DEBUGLEVEL);
	torture_assert_int_equal_goto(tctx,
				      smbc_getDebug(ctx),
				      DEBUGLEVEL,
				      ok,
				      done,
				      "failed to set DEBUGLEVEL");

	torture_comment(tctx, "Testing smbc_(set|get)NetbiosName\n");
	smbc_setNetbiosName(ctx, discard_const("torture_netbios"));
	torture_assert_str_equal_goto(tctx,
				      smbc_getNetbiosName(ctx),
				      "torture_netbios",
				      ok,
				      done,
				      "failed to set NetbiosName");

	torture_comment(tctx, "Testing smbc_(set|get)Workgroup\n");
	smbc_setWorkgroup(ctx, discard_const("torture_workgroup"));
	torture_assert_str_equal_goto(tctx,
				      smbc_getWorkgroup(ctx),
				      "torture_workgroup",
				      ok,
				      done,
				      "failed to set Workgroup");

	torture_comment(tctx, "Testing smbc_(set|get)User\n");
	smbc_setUser(ctx, "torture_user");
	torture_assert_str_equal_goto(tctx,
				      smbc_getUser(ctx),
				      "torture_user",
				      ok,
				      done,
				      "failed to set User");

	torture_comment(tctx, "Testing smbc_(set|get)Timeout\n");
	smbc_setTimeout(ctx, 12345);
	torture_assert_int_equal_goto(tctx,
				      smbc_getTimeout(ctx),
				      12345,
				      ok,
				      done,
				      "failed to set Timeout");

done:
	smbc_free_context(ctx, 1);

	return ok;
}

bool torture_libsmbclient_options(struct torture_context *tctx)
{
	SMBCCTX *ctx;
	bool ok = true;

	ctx = smbc_new_context();
	torture_assert(tctx, ctx, "failed to get new context");
	torture_assert(tctx, smbc_init_context(ctx), "failed to init context");

	torture_comment(tctx, "Testing smbc_(set|get)OptionDebugToStderr\n");
	smbc_setOptionDebugToStderr(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionDebugToStderr(ctx),
			    ok,
			    done,
			    "failed to set OptionDebugToStderr");

	torture_comment(tctx, "Testing smbc_(set|get)OptionFullTimeNames\n");
	smbc_setOptionFullTimeNames(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionFullTimeNames(ctx),
			    ok,
			    done,
			    "failed to set OptionFullTimeNames");

	torture_comment(tctx, "Testing smbc_(set|get)OptionOpenShareMode\n");
	smbc_setOptionOpenShareMode(ctx, SMBC_SHAREMODE_DENY_ALL);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionOpenShareMode(ctx),
				      SMBC_SHAREMODE_DENY_ALL,
				      ok,
				      done,
				      "failed to set OptionOpenShareMode");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUserData\n");
	smbc_setOptionUserData(ctx, (void *)discard_const("torture_user_data"));
	torture_assert_str_equal_goto(tctx,
				      (const char*)smbc_getOptionUserData(ctx),
				      "torture_user_data",
				      ok,
				      done,
				      "failed to set OptionUserData");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionSmbEncryptionLevel\n");
	smbc_setOptionSmbEncryptionLevel(ctx, SMBC_ENCRYPTLEVEL_REQUEST);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionSmbEncryptionLevel(ctx),
				      SMBC_ENCRYPTLEVEL_REQUEST,
				      ok,
				      done,
				      "failed to set OptionSmbEncryptionLevel");

	torture_comment(tctx, "Testing smbc_(set|get)OptionCaseSensitive\n");
	smbc_setOptionCaseSensitive(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionCaseSensitive(ctx),
			    ok,
			    done,
			    "failed to set OptionCaseSensitive");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionBrowseMaxLmbCount\n");
	smbc_setOptionBrowseMaxLmbCount(ctx, 2);
	torture_assert_int_equal_goto(tctx,
				      smbc_getOptionBrowseMaxLmbCount(ctx),
				      2,
				      ok,
				      done,
				      "failed to set OptionBrowseMaxLmbCount");

	torture_comment(tctx,
		       "Testing smbc_(set|get)OptionUrlEncodeReaddirEntries\n");
	smbc_setOptionUrlEncodeReaddirEntries(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionUrlEncodeReaddirEntries(ctx),
			    ok,
			    done,
			    "failed to set OptionUrlEncodeReaddirEntries");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionOneSharePerServer\n");
	smbc_setOptionOneSharePerServer(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionOneSharePerServer(ctx),
			    ok,
			    done,
			    "failed to set OptionOneSharePerServer");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUseKerberos\n");
	smbc_setOptionUseKerberos(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionUseKerberos(ctx),
			    ok,
			    done,
			    "failed to set OptionUseKerberos");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionFallbackAfterKerberos\n");
	smbc_setOptionFallbackAfterKerberos(ctx, false);
	torture_assert_goto(tctx,
			    !smbc_getOptionFallbackAfterKerberos(ctx),
			    ok,
			    done,
			    "failed to set OptionFallbackAfterKerberos");

	torture_comment(tctx,
			"Testing smbc_(set|get)OptionNoAutoAnonymousLogin\n");
	smbc_setOptionNoAutoAnonymousLogin(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionNoAutoAnonymousLogin(ctx),
			    ok,
			    done,
			    "failed to set OptionNoAutoAnonymousLogin");

	torture_comment(tctx, "Testing smbc_(set|get)OptionUseCCache\n");
	smbc_setOptionUseCCache(ctx, true);
	torture_assert_goto(tctx,
			    smbc_getOptionUseCCache(ctx),
			    ok,
			    done,
			    "failed to set OptionUseCCache");

done:
	smbc_free_context(ctx, 1);

	return ok;
}

static bool torture_libsmbclient_list_shares(struct torture_context *tctx)
{
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);
	struct smbc_dirent *dirent = NULL;
	SMBCCTX *ctx = NULL;
	int dhandle = -1;
	bool ipc_share_found = false;
	bool ok = true;

	if (smburl == NULL) {
		torture_fail(tctx,
			     "option --option=torture:smburl="
			     "smb://user:password@server missing\n");
	}

	ok = torture_libsmbclient_init_context(tctx, &ctx);
	torture_assert_goto(tctx,
			    ok,
			    ok,
			    out,
			    "Failed to init context");
	smbc_set_context(ctx);

	torture_comment(tctx, "Listing: %s\n", smburl);
	dhandle = smbc_opendir(smburl);
	torture_assert_int_not_equal_goto(tctx,
					  dhandle,
					  -1,
					  ok,
					  out,
					  "Failed to open smburl");

	while((dirent = smbc_readdir(dhandle)) != NULL) {
		torture_comment(tctx, "DIR: %s\n", dirent->name);
		torture_assert_not_null_goto(tctx,
					     dirent->name,
					     ok,
					     out,
					     "Failed to read name");

		if (strequal(dirent->name, "IPC$")) {
			ipc_share_found = true;
		}
	}

	torture_assert_goto(tctx,
			    ipc_share_found,
			    ok,
			    out,
			    "Failed to list IPC$ share");

out:
	smbc_closedir(dhandle);
	return ok;
}

static bool torture_libsmbclient_utimes(struct torture_context *tctx)
{
	const char *smburl = torture_setting_string(tctx, "smburl", NULL);
	SMBCCTX *ctx = NULL;
	struct stat st;
	int fhandle, ret;
	struct timeval tbuf[2];
	bool ok;

	if (smburl == NULL) {
		torture_fail(tctx,
			     "option --option=torture:smburl="
			     "smb://user:password@server missing\n");
	}

	ok = torture_libsmbclient_init_context(tctx, &ctx);
	torture_assert(tctx, ok, "Failed to init context");
	smbc_set_context(ctx);

	fhandle = smbc_open(smburl, O_RDWR|O_CREAT, 0644);
	torture_assert_int_not_equal(tctx, fhandle, -1, "smbc_open failed");

	ret = smbc_fstat(fhandle, &st);
	torture_assert_int_not_equal(tctx, ret, -1, "smbc_fstat failed");

	tbuf[0] = convert_timespec_to_timeval(st.st_atim);
	tbuf[1] = convert_timespec_to_timeval(st.st_mtim);

	tbuf[1] = timeval_add(&tbuf[1], 0, 100000); /* 100 msec */

	ret = smbc_utimes(smburl, tbuf);
	torture_assert_int_not_equal(tctx, ret, -1, "smbc_utimes failed");

	ret = smbc_fstat(fhandle, &st);
	torture_assert_int_not_equal(tctx, ret, -1, "smbc_fstat failed");

	torture_assert_int_equal(
		tctx,
		st.st_mtim.tv_nsec / 1000,
		tbuf[1].tv_usec,
		"smbc_utimes did not update msec");

	smbc_close(fhandle);
	smbc_unlink(smburl);
	return true;
}

NTSTATUS torture_libsmbclient_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite;

	suite = torture_suite_create(ctx, "libsmbclient");

	torture_suite_add_simple_test(suite, "version", torture_libsmbclient_version);
	torture_suite_add_simple_test(suite, "initialize", torture_libsmbclient_initialize);
	torture_suite_add_simple_test(suite, "configuration", torture_libsmbclient_configuration);
	torture_suite_add_simple_test(suite, "setConfiguration", torture_libsmbclient_setConfiguration);
	torture_suite_add_simple_test(suite, "options", torture_libsmbclient_options);
	torture_suite_add_simple_test(suite, "opendir", torture_libsmbclient_opendir);
	torture_suite_add_simple_test(suite, "list_shares", torture_libsmbclient_list_shares);
	torture_suite_add_simple_test(suite, "readdirplus",
		torture_libsmbclient_readdirplus);
	torture_suite_add_simple_test(suite, "readdirplus_seek",
		torture_libsmbclient_readdirplus_seek);
	torture_suite_add_simple_test(suite, "readdirplus2",
		torture_libsmbclient_readdirplus2);
	torture_suite_add_simple_test(
		suite, "utimes", torture_libsmbclient_utimes);

	suite->description = talloc_strdup(suite, "libsmbclient interface tests");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
