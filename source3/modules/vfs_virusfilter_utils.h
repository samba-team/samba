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
#define VIRUSFILTER_IO_EOL_SIZE		1
#define VIRUSFILTER_IO_IOV_MAX		16
#define VIRUSFILTER_CACHE_BUFFER_SIZE	(PATH_MAX + 128)

struct virusfilter_io_handle {
	struct tstream_context *stream;
	int		connect_timeout;	/* msec */
	int		io_timeout;		/* msec */

	/* end-of-line character(s) */
	char		w_eol[VIRUSFILTER_IO_EOL_SIZE];
	int		w_eol_size;

	/* end-of-line character(s) */
	char		r_eol[VIRUSFILTER_IO_EOL_SIZE];
	int		r_eol_size;

	/* buffer */
	char		r_buffer[VIRUSFILTER_IO_BUFFER_SIZE];
	size_t		r_len;
};

struct virusfilter_cache_entry {
	time_t time;
	virusfilter_result result;
	char *report;
};

struct virusfilter_cache {
	struct memcache *cache;
	TALLOC_CTX *ctx;
	time_t time_limit;
};

/* ====================================================================== */

char *virusfilter_string_sub(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *str);
int virusfilter_vfs_next_move(
	vfs_handle_struct *handle,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst);

/* Line-based socket I/O */
struct virusfilter_io_handle *virusfilter_io_new(
	TALLOC_CTX *mem_ctx,
	int connect_timeout,
	int timeout);
int virusfilter_io_set_connect_timeout(
	struct virusfilter_io_handle *io_h,
	int timeout);
int virusfilter_io_set_io_timeout(
	struct virusfilter_io_handle *io_h, int timeout);
void virusfilter_io_set_writel_eol(
	struct virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size);
void virusfilter_io_set_readl_eol(
	struct virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size);
bool virusfilter_io_connect_path(
	struct virusfilter_io_handle *io_h,
	const char *path);
bool virusfilter_io_disconnect(
	struct virusfilter_io_handle *io_h);
bool write_data_iov_timeout(
	struct tstream_context *stream,
	const struct iovec *iov,
	size_t iovcnt,
	int ms_timeout);
bool virusfilter_io_write(
	struct virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size);
bool virusfilter_io_writel(
	struct virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size);
bool virusfilter_io_writefl(
	struct virusfilter_io_handle *io_h,
	const char *data_fmt, ...);
bool virusfilter_io_vwritefl(
	struct virusfilter_io_handle *io_h,
	const char *data_fmt, va_list ap);
bool virusfilter_io_writev(
	struct virusfilter_io_handle *io_h, ...);
bool virusfilter_io_writevl(
	struct virusfilter_io_handle *io_h, ...);
bool virusfilter_io_readl(TALLOC_CTX *ctx,
			struct virusfilter_io_handle *io_h,
			char **read_line);
bool virusfilter_io_writefl_readl(
	struct virusfilter_io_handle *io_h,
	char **read_line,
	const char *fmt, ...);

/* Scan result cache */
struct virusfilter_cache *virusfilter_cache_new(
	TALLOC_CTX *ctx,
	int entry_limit,
	time_t time_limit);
bool virusfilter_cache_entry_add(
	struct virusfilter_cache *cache,
	const char *directory,
	const char *fname,
	virusfilter_result result,
	char *report);
bool virusfilter_cache_entry_rename(
	struct virusfilter_cache *cache,
	const char *directory,
	char *old_fname,
	char *new_fname);
void virusfilter_cache_entry_free(struct virusfilter_cache_entry *cache_e);
struct virusfilter_cache_entry *virusfilter_cache_get(
	struct virusfilter_cache *cache,
	const char *directory,
	const char *fname);
void virusfilter_cache_remove(
	struct virusfilter_cache *cache,
	const char *directory,
	const char *fname);
void virusfilter_cache_purge(struct virusfilter_cache *cache);

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
