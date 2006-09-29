/* 
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005-2006
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/****************************************************************
 explode the GPO CIFS URI into their components
****************************************************************/

NTSTATUS ads_gpo_explode_filesyspath(ADS_STRUCT *ads, 
				     TALLOC_CTX *mem_ctx, 
				     const char *file_sys_path, 
				     char **server, 
				     char **service, 
				     char **nt_path,
				     char **unix_path)
{
	fstring tok;
	pstring path;

	*server = NULL;
	*service = NULL;
	*nt_path = NULL;
	*unix_path = NULL;

	if (!next_token(&file_sys_path, tok, "\\", sizeof(tok))) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((*server = talloc_strdup(mem_ctx, tok)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!next_token(&file_sys_path, tok, "\\", sizeof(tok))) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((*service = talloc_strdup(mem_ctx, tok)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if ((*nt_path = talloc_asprintf(mem_ctx, "\\%s", file_sys_path)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pstrcpy(path, lock_path(GPO_CACHE_DIR));
	pstrcat(path, "/");
	pstrcat(path, file_sys_path);
	pstring_sub(path, "\\", "/");

	if ((*unix_path = talloc_strdup(mem_ctx, path)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/****************************************************************
 prepare the local disc storage for "unix_path"
****************************************************************/

NTSTATUS ads_gpo_prepare_local_store(ADS_STRUCT *ads, 
				     TALLOC_CTX *mem_ctx, 
				     const char *unix_path)
{
	const char *top_dir = lock_path(GPO_CACHE_DIR);
	char *current_dir;
	fstring tok;

	current_dir = talloc_strdup(mem_ctx, top_dir);
	NT_STATUS_HAVE_NO_MEMORY(current_dir);

	if ((mkdir(top_dir, 0644)) < 0 && errno != EEXIST) {
		return NT_STATUS_ACCESS_DENIED;
	}

	while (next_token(&unix_path, tok, "/", sizeof(tok))) {
	
		if (strequal(tok, GPO_CACHE_DIR)) {
			break;
		}
	}

	while (next_token(&unix_path, tok, "/", sizeof(tok))) {

		current_dir = talloc_asprintf_append(current_dir, "/%s", tok);
		NT_STATUS_HAVE_NO_MEMORY(current_dir);

		if ((mkdir(current_dir, 0644)) < 0 && errno != EEXIST) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************
 download a full GPO via CIFS
****************************************************************/

NTSTATUS ads_fetch_gpo_files(ADS_STRUCT *ads, 
			    TALLOC_CTX *mem_ctx, 
			    struct cli_state *cli, 
			    struct GROUP_POLICY_OBJECT *gpo)
{
	NTSTATUS result;
	int fnum = 0;
	int fd = 0;
	char *data = NULL;
	static int io_bufsize = 64512;
	int read_size = io_bufsize;
	char *server, *service, *nt_path, *unix_path, *nt_ini_path, *unix_ini_path;
	off_t start = 0;
	off_t nread = 0;

	result = ads_gpo_explode_filesyspath(ads, mem_ctx, gpo->file_sys_path, 
					     &server, &service, &nt_path, &unix_path);
	if (!NT_STATUS_IS_OK(result)) {
		goto out;
	}

	result = ads_gpo_prepare_local_store(ads, mem_ctx, unix_path);
	if (!NT_STATUS_IS_OK(result)) {
		goto out;
	}

	unix_ini_path = talloc_asprintf(mem_ctx, "%s/%s", unix_path, GPT_INI);
	nt_ini_path = talloc_asprintf(mem_ctx, "%s\\%s", nt_path, GPT_INI);
	if (!unix_path || !nt_ini_path) {
		result = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/* open local file */

	fd = sys_open(unix_ini_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		result = map_nt_error_from_unix(errno);
		goto out;
	}
	 
	/* open remote file */

	fnum = cli_open(cli, nt_ini_path, O_RDONLY, DENY_NONE);
	if (fnum == -1) {
		result = NT_STATUS_NO_SUCH_FILE;
		goto out;
	}

	/* copy gpt.ini */

	data = (char *)SMB_MALLOC(read_size);
	if (data == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto out;
	}

	while (1) {

		int n = cli_read(cli, fnum, data, nread + start, read_size);

		if (n <= 0)
			break;

		if (write(fd, data, n) != n) {
			break;
		}

		nread += n;
	}

	result = NT_STATUS_OK;

 out:
	SAFE_FREE(data);
	if (fd) {
		close(fd);
	}
	if (fnum) {
		cli_close(cli, fnum);
	}

	return result;
}

/****************************************************************
 get the locally stored gpt.ini version number
****************************************************************/

NTSTATUS ads_gpo_get_sysvol_gpt_version(ADS_STRUCT *ads, 
					TALLOC_CTX *mem_ctx, 
					const char *unix_path, 
					uint32 *sysvol_version,
					char **display_name)
{
	NTSTATUS status;
	uint32 version;
	char *local_path = NULL;
	char *name = NULL;

	local_path = talloc_asprintf(mem_ctx, "%s/%s", unix_path, GPT_INI);
	NT_STATUS_HAVE_NO_MEMORY(local_path);

	status = parse_gpt_ini(mem_ctx, local_path, &version, &name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("ads_gpo_get_sysvol_gpt_version: failed to parse ini [%s]: %s\n", 
			unix_path, nt_errstr(status)));
		return status;
	}

	if (sysvol_version) {
		*sysvol_version = version;
	}

	if (name && *display_name) {
		*display_name = talloc_strdup(mem_ctx, name);
	}

	return NT_STATUS_OK;
}
