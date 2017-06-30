/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

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

#ifndef _VIRUSFILTER_UTILS_H
#define _VIRUSFILTER_UTILS_H

#include "modules/vfs_virusfilter_common.h"
#include "../lib/util/memcache.h"
#include "../lib/util/strv.h"

/*#define str_eq(s1, s2)		\
	((strcmp((s1), (s2)) == 0) ? true : false)
#define strn_eq(s1, s2, n)	\
	((strncmp((s1), (s2), (n)) == 0) ? true : false) */

/* "* 3" is for %-encoding */
#define VIRUSFILTER_IO_URL_MAX		(PATH_MAX * 3)
#define VIRUSFILTER_IO_BUFFER_SIZE	(VIRUSFILTER_IO_URL_MAX + 128)
#define VIRUSFILTER_IO_EOL_SIZE		2
#define VIRUSFILTER_IO_IOV_MAX		16
#define VIRUSFILTER_CACHE_BUFFER_SIZE	(PATH_MAX + 128)

typedef struct virusfilter_io_handle {
	int		socket;
	int		connect_timeout;	/* msec */
	int		io_timeout;		/* msec */

	/* end-of-line character(s) */
	char		w_eol[VIRUSFILTER_IO_EOL_SIZE];
	int		w_eol_size;

	/* end-of-line character(s) */
	char		r_eol[VIRUSFILTER_IO_EOL_SIZE];
	int		r_eol_size;
	char		*r_buffer;
	char		r_buffer_real[VIRUSFILTER_IO_BUFFER_SIZE+1];
	ssize_t		r_size;
	char		*r_rest_buffer;
	ssize_t		r_rest_size;
} virusfilter_io_handle;

typedef struct virusfilter_cache_entry {
	time_t time;
	virusfilter_result result;
	char *report;
} virusfilter_cache_entry;

typedef struct virusfilter_cache_handle {
	struct memcache *cache;
	TALLOC_CTX *ctx;
	time_t time_limit;
} virusfilter_cache_handle;

/* ====================================================================== */

char *virusfilter_string_sub(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *str);
int virusfilter_url_quote(const char *src, char *dst, int dst_size);
int virusfilter_vfs_next_move(
	vfs_handle_struct *handle,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst);

/* Line-based socket I/O */
virusfilter_io_handle *virusfilter_io_new(
	TALLOC_CTX *mem_ctx,
	int connect_timeout,
	int timeout);
int virusfilter_io_set_connect_timeout(
	virusfilter_io_handle *io_h,
	int timeout);
int virusfilter_io_set_io_timeout(virusfilter_io_handle *io_h, int timeout);
void virusfilter_io_set_writel_eol(
	virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size);
void virusfilter_io_set_readl_eol(
	virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size);
virusfilter_result virusfilter_io_connect_path(
	virusfilter_io_handle *io_h,
	const char *path);
virusfilter_result virusfilter_io_disconnect(virusfilter_io_handle *io_h);
virusfilter_result virusfilter_io_write(
	virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size);
virusfilter_result virusfilter_io_writel(
	virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size);
virusfilter_result virusfilter_io_writefl(
	virusfilter_io_handle *io_h,
	const char *data_fmt, ...);
virusfilter_result virusfilter_io_vwritefl(
	virusfilter_io_handle *io_h,
	const char *data_fmt, va_list ap);
virusfilter_result virusfilter_io_writev(virusfilter_io_handle *io_h, ...);
virusfilter_result virusfilter_io_writevl(virusfilter_io_handle *io_h, ...);
virusfilter_result virusfilter_io_readl(virusfilter_io_handle *io_h);
virusfilter_result virusfilter_io_writefl_readl(
	virusfilter_io_handle *io_h,
	const char *fmt, ...);

/* Scan result cache */
virusfilter_cache_handle *virusfilter_cache_new(
	TALLOC_CTX *ctx,
	int entry_limit,
	time_t time_limit);
int virusfilter_cache_entry_add(
	virusfilter_cache_handle *cache_h,
	const char *fname,
	virusfilter_result result,
	const char *report);
int virusfilter_cache_entry_rename(
	virusfilter_cache_handle *cache_h,
	const char *old_fname,
	const char *new_fname);
void virusfilter_cache_entry_free(virusfilter_cache_entry *cache_e);
virusfilter_cache_entry *virusfilter_cache_get(
	virusfilter_cache_handle *cache_h,
	const char *fname);
void virusfilter_cache_remove(
	virusfilter_cache_handle *cache_h,
	const char *fname);
void virusfilter_cache_purge(virusfilter_cache_handle *cache_h);

/* Shell scripting */
int virusfilter_env_set(
	TALLOC_CTX *mem_ctx,
	char **env_list,
	const char *name,
	const char *value);
int virusfilter_shell_set_conn_env(
	TALLOC_CTX *mem_ctx,
	char **env_list,
	connection_struct *conn);
int virusfilter_shell_run(
	TALLOC_CTX *mem_ctx,
	const char *cmd,
	char **env_list,
	connection_struct *conn,
	bool sanitize);

#endif /* _VIRUSFILTER_UTILS_H */

