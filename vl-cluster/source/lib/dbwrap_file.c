/* 
   Unix SMB/CIFS implementation.
   Database interface using a file per record
   Copyright (C) Volker Lendecke 2005
   
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

struct db_file_ctx {
	const char *dirname;

	/* We only support one locked record at a time -- everything else
	 * would lead to a potential deadlock anyway! */
	struct db_record *locked_record;
};

struct db_locked_file {
	int fd;
	uint8 hash;
	const char *name;
	const char *path;
	struct db_file_ctx *parent;
};

/* Copy from statcache.c... */

static uint32 fsh(const char *p, int len)
{
        uint32 n = 0;
	int i;
        for (i=0; i<len; i++) {
                n = ((n << 5) + n) ^ (u32)(p[i]);
        }
        return n;
}

static int db_locked_file_destr(void *p)
{
	struct db_locked_file *data =
		talloc_get_type_abort(p, struct db_locked_file);

	data->parent->locked_record = NULL;

	if (close(data->fd) != 0) {
		DEBUG(3, ("close failed: %s\n", strerror(errno)));
		return -1;
	}

	return 0;
}

static int db_file_store(struct db_record *rec, DATA_BLOB data, int flag);
static int db_file_delete(struct db_record *rec);

static struct db_record *db_file_fetch_locked(struct db_context *db,
					      TALLOC_CTX *mem_ctx,
					      DATA_BLOB key)
{
	struct db_file_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_file_ctx);
	struct db_record *result;
	struct db_locked_file *file;
	struct flock fl;
	SMB_STRUCT_STAT statbuf;
	ssize_t nread;
	int ret;

	SMB_ASSERT(ctx->locked_record == NULL);

 again:
	result = TALLOC_P(mem_ctx, struct db_record);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->private_data = file = TALLOC_P(result, struct db_locked_file);
	result->store = db_file_store;
	result->delete_rec = db_file_delete;

	if (file == NULL) {
		DEBUG(0, ("talloc failed\n"));
		talloc_free(result);
		return NULL;
	}

	result->key = data_blob_talloc(result, key.data, key.length);
	if (result->key.data == NULL) {
		DEBUG(0, ("talloc failed\n"));
		talloc_free(result);
		return NULL;
	}

	/* Cut to 8 bits */
	file->hash = fsh(key.data, key.length);
	file->name = hex_encode(file, key.data, key.length);
	if (file->name == NULL) {
		DEBUG(0, ("hex_encode failed\n"));
		talloc_free(result);
		return NULL;
	}

	file->path = talloc_asprintf(file, "%s/%2.2X/%s", ctx->dirname,
				     file->hash, file->name);
	if (file->path == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		talloc_free(result);
		return NULL;
	}

	file->fd = open(file->path, O_RDWR|O_CREAT, 0644);
	if (file->fd < 0) {
		DEBUG(3, ("Could not open/create %s: %s\n",
			  file->path, strerror(errno)));
		talloc_free(result);
		return NULL;
	}

	talloc_set_destructor(file, db_locked_file_destr);

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_pid = 0;

	do {
		ret = fcntl(file->fd, F_SETLKW, &fl);
	} while ((ret == -1) && (errno == EINTR));

	if (ret == -1) {
		DEBUG(3, ("Could not get lock on %s: %s\n",
			  file->path, strerror(errno)));
		talloc_free(result);
		return NULL;
	}

	if (sys_fstat(file->fd, &statbuf) != 0) {
		DEBUG(3, ("Could not fstat %s: %s\n",
			  file->path, strerror(errno)));
		talloc_free(result);
		return NULL;
	}

	if (statbuf.st_nlink == 0) {
		/* Someone has deleted it under the lock, retry */
		talloc_free(result);
		goto again;
	}

	result->value.length = 0;
	result->value.data = NULL;

	if (statbuf.st_size != 0) {
		result->value.length = statbuf.st_size;
		result->value.data = TALLOC_ARRAY(result, char,
						  statbuf.st_size);
		if (result->value.data == NULL) {
			DEBUG(1, ("talloc failed\n"));
			talloc_free(result);
			return NULL;
		}

		nread = read_data(file->fd, result->value.data,
				  result->value.length);
		if (nread != result->value.length) {
			DEBUG(3, ("read_data failed: %s\n", strerror(errno)));
			talloc_free(result);
			return NULL;
		}
	}

	ctx->locked_record = result;
	file->parent = talloc_reference(file, ctx);

	return result;
}

static int db_file_store(struct db_record *rec, DATA_BLOB data, int flag)
{
	struct db_locked_file *file =
		talloc_get_type_abort(rec->private_data,
				      struct db_locked_file);

	if (sys_lseek(file->fd, 0, SEEK_SET) != 0) {
		DEBUG(0, ("sys_lseek failed: %s\n", strerror(errno)));
		return -1;
	}

	if (write_data(file->fd, data.data, data.length) != data.length) {
		DEBUG(3, ("write_data failed: %s\n", strerror(errno)));
		return -1;
	}

	if (sys_ftruncate(file->fd, data.length) != 0) {
		DEBUG(3, ("sys_ftruncate failed: %s\n", strerror(errno)));
		return -1;
	}

	return 0;
}

static int db_file_delete(struct db_record *rec)
{
	struct db_locked_file *file =
		talloc_get_type_abort(rec->private_data,
				      struct db_locked_file);

	if (unlink(file->path) != 0) {
		DEBUG(3, ("unlink(%s) failed: %s\n", file->path,
			  strerror(errno)));
		return -1;
	}

	return 0;
}

static int db_file_traverse(struct db_context *db,
			    int (*fn)(DATA_BLOB key, DATA_BLOB value,
				      void *private_data),
			    void *private_data)
{
	struct db_file_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_file_ctx);
	TALLOC_CTX *mem_ctx = talloc_init("traversal %s\n", ctx->dirname);
	
	int i;
	int count = 0;

	for (i=0; i<256; i++) {
		const char *dirname = talloc_asprintf(mem_ctx, "%s/%2.2X",
						      ctx->dirname, i);
		DIR *dir;
		struct dirent *dirent;

		if (dirname == NULL) {
			DEBUG(0, ("talloc failed\n"));
			talloc_free(mem_ctx);
			return -1;
		}

		dir = opendir(dirname);
		if (dir == NULL) {
			DEBUG(3, ("Could not open dir %s: %s\n", dirname,
				  strerror(errno)));
			talloc_free(mem_ctx);
			return -1;
		}

		while ((dirent = readdir(dir)) != NULL) {
			DATA_BLOB key, data;
			struct db_record *rec;

			if ((dirent->d_name[0] == '.') &&
			    ((dirent->d_name[1] == '\0') ||
			     ((dirent->d_name[1] == '.') &&
			      (dirent->d_name[2] == '\0')))) {
				continue;
			}

			key = strhex_to_data_blob(mem_ctx, dirent->d_name);

			if (key.data == NULL) {
				DEBUG(5, ("strhex_to_data_blob failed\n"));
				continue;
			}

			if ((ctx->locked_record != NULL) &&
			    (key.length == ctx->locked_record->key.length) &&
			    (memcmp(key.data, ctx->locked_record->key.data,
				    key.length) == 0)) {
				count += 1;
				if (fn(key, ctx->locked_record->value,
				       private_data) != 0) {
					talloc_free(mem_ctx);
					closedir(dir);
					return count;
				}
			}

			rec = db_file_fetch_locked(db, mem_ctx, key);
			if (rec == NULL) {
				/* Someone might have deleted it */
				continue;
			}

			if (rec->value.data == NULL) {
				talloc_free(rec);
				continue;
			}

			data.length = rec->value.length;
			data.data = talloc_steal(mem_ctx, rec->value.data);
			talloc_free(rec);
			count += 1;

			if (fn(key, data, private_data) != 0) {
				talloc_free(mem_ctx);
				closedir(dir);
				return count;
			}
		}

		closedir(dir);
	}

	talloc_free(mem_ctx);
	return count;
}

struct db_context *db_open_file(TALLOC_CTX *mem_ctx, const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode)
{
	struct db_context *result = NULL;
	struct db_file_ctx *ctx;

	result = TALLOC_P(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->fetch_locked = db_file_fetch_locked;
	result->traverse = db_file_traverse;

	result->private_data = ctx = TALLOC_P(result, struct db_file_ctx);
	if (ctx == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	ctx->locked_record = NULL;
	ctx->dirname = talloc_strdup(ctx, name);
	if (ctx->dirname == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	if (open_flags & O_CREAT) {
		int ret, i;

		mode |= (mode & S_IRUSR) ? S_IXUSR : 0;
		mode |= (mode & S_IRGRP) ? S_IXGRP : 0;
		mode |= (mode & S_IROTH) ? S_IXOTH : 0;

		ret = mkdir(name, mode);
		if ((ret != 0) && (errno != EEXIST)) {
			DEBUG(5, ("mkdir(%s,%o) failed: %s\n", name, mode,
				  strerror(errno)));
			goto fail;
		}

		for (i=0; i<256; i++) {
			char *path;
			path = talloc_asprintf(result, "%s/%2.2X", name, i);
			if (path == NULL) {
				DEBUG(0, ("asprintf failed\n"));
				goto fail;
			}
			ret = mkdir(path, mode);
			if ((ret != 0) && (errno != EEXIST)) {
				DEBUG(5, ("mkdir(%s,%o) failed: %s\n", path,
					  mode, strerror(errno)));
				goto fail;
			}
			talloc_free(path);
		}
	}

	return result;

 fail:
	if (result != NULL) {
		talloc_free(result);
	}
	return NULL;
}
