/*
   smbget: a wget-like utility with support for recursive downloading of
	smb:// urls
   Copyright (C) 2003-2004 Jelmer Vernooij <jelmer@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "includes.h"
#include "system/filesys.h"
#include "lib/cmdline/cmdline.h"
#include "lib/param/param.h"
#include "libsmbclient.h"
#include "cmdline_contexts.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

static int columns = 0;

static time_t total_start_time = 0;
static off_t total_bytes = 0;

#define SMB_MAXPATHLEN MAXPATHLEN

/*
 * Number of bytes to read when checking whether local and remote file
 * are really the same file
 */
#define RESUME_CHECK_SIZE 	512
#define RESUME_DOWNLOAD_OFFSET	1024
#define RESUME_CHECK_OFFSET	(RESUME_DOWNLOAD_OFFSET+RESUME_CHECK_SIZE)
/* Number of bytes to read at once */
#define SMB_DEFAULT_BLOCKSIZE 	64000

struct opt {
	char *outputfile;
	size_t blocksize;

	int quiet;
	int dots;
	int verbose;
	int send_stdout;
	int update;
	unsigned limit_rate;
};
static struct opt opt = { .blocksize = SMB_DEFAULT_BLOCKSIZE };

static bool smb_download_file(const char *base, const char *name,
			      bool recursive, bool resume, bool toplevel,
			      char *outfile);

static int get_num_cols(void)
{
#ifdef TIOCGWINSZ
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) {
		return 0;
	}
	return ws.ws_col;
#else
#warning No support for TIOCGWINSZ
	char *cols = getenv("COLUMNS");
	if (!cols) {
		return 0;
	}
	return atoi(cols);
#endif
}

static void change_columns(int sig)
{
	columns = get_num_cols();
}

static void human_readable(off_t s, char *buffer, int l)
{
	if (s > 1024 * 1024 * 1024) {
		snprintf(buffer, l, "%.2fGB", 1.0 * s / (1024 * 1024 * 1024));
	} else if (s > 1024 * 1024) {
		snprintf(buffer, l, "%.2fMB", 1.0 * s / (1024 * 1024));
	} else if (s > 1024) {
		snprintf(buffer, l, "%.2fkB", 1.0 * s / 1024);
	} else {
		snprintf(buffer, l, "%jdb", (intmax_t)s);
	}
}

/*
 * Authentication callback for libsmbclient.
 *
 * The command line parser will take care asking for a password interactively!
 */
static void get_auth_data_with_context_fn(SMBCCTX *ctx,
					  const char *srv,
					  const char *shr,
					  char *dom,
					  int dom_len,
					  char *usr,
					  int usr_len,
					  char *pwd,
					  int pwd_len)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();
	const char *username = NULL;
	const char *password = NULL;
	const char *domain = NULL;
	enum credentials_obtained obtained = CRED_UNINITIALISED;

	domain = cli_credentials_get_domain_and_obtained(creds, &obtained);
	if (domain != NULL) {
		bool overwrite = false;
		if (dom[0] == '\0') {
			overwrite = true;
		}
		if (obtained >= CRED_CALLBACK_RESULT) {
			overwrite = true;
		}
		if (overwrite) {
			strncpy(dom, domain, dom_len - 1);
		}
	}
	cli_credentials_set_domain(creds, dom, obtained);

	username = cli_credentials_get_username_and_obtained(creds, &obtained);
	if (username != NULL) {
		bool overwrite = false;
		if (usr[0] == '\0') {
			overwrite = true;
		}
		if (obtained >= CRED_CALLBACK_RESULT) {
			overwrite = true;
		}
		if (overwrite) {
			strncpy(usr, username, usr_len - 1);
		}
	}
	cli_credentials_set_username(creds, usr, obtained);

	password = cli_credentials_get_password_and_obtained(creds, &obtained);
	if (password != NULL) {
		bool overwrite = false;
		if (pwd[0] == '\0') {
			overwrite = true;
		}
		if (obtained >= CRED_CALLBACK_RESULT) {
			overwrite = true;
		}
		if (overwrite) {
			strncpy(pwd, password, pwd_len - 1);
		}
	}
	cli_credentials_set_password(creds, pwd, obtained);

	smbc_set_credentials_with_fallback(ctx, dom, usr, pwd);

	if (!opt.quiet) {
		if (usr[0] == '\0') {
			printf("Using guest user\n");
		} else if (dom[0] == '\0') {
			printf("Using user: %s\n", usr);
		} else {
			printf("Using domain: %s, user: %s\n", dom, usr);
		}
	}
}

static bool smb_download_dir(const char *base, const char *name, int resume)
{
	char path[SMB_MAXPATHLEN];
	int dirhandle;
	struct smbc_dirent *dirent;
	const char *relname = name;
	char *tmpname;
	bool ok = false;

	snprintf(path, SMB_MAXPATHLEN-1, "%s%s%s", base,
		 (base[0] && name[0] && name[0] != '/' &&
		  base[strlen(base)-1] != '/') ? "/" : "",
		 name);

	/* List files in directory and call smb_download_file on them */
	dirhandle = smbc_opendir(path);
	if (dirhandle < 1) {
		if (errno == ENOTDIR) {
			return smb_download_file(base, name, true, resume,
						 false, NULL);
		}
		fprintf(stderr, "Can't open directory %s: %s\n", path,
			strerror(errno));
		return false;
	}

	while (*relname == '/') {
		relname++;
	}

	if (strlen(relname) > 0) {
		int rc = mkdir(relname, 0755);
		if (rc == -1 && errno != EEXIST) {
			fprintf(stderr, "Can't create directory %s: %s\n",
				relname, strerror(errno));
			return false;
		}
	}

	tmpname = SMB_STRDUP(name);

	while ((dirent = smbc_readdir(dirhandle))) {
		char *newname;
		if (!strcmp(dirent->name, ".") || !strcmp(dirent->name, "..")) {
			ok = true;
			continue;
		}
		if (asprintf(&newname, "%s/%s", tmpname, dirent->name) == -1) {
			free(tmpname);
			return false;
		}
		switch (dirent->smbc_type) {
		case SMBC_DIR:
			ok = smb_download_dir(base, newname, resume);
			break;

		case SMBC_WORKGROUP:
			ok = smb_download_dir("smb://", dirent->name, resume);
			break;

		case SMBC_SERVER:
			ok = smb_download_dir("smb://", dirent->name, resume);
			break;

		case SMBC_FILE:
			ok = smb_download_file(base, newname, true, resume,
						false, NULL);
			break;

		case SMBC_FILE_SHARE:
			ok = smb_download_dir(base, newname, resume);
			break;

		case SMBC_PRINTER_SHARE:
			if (!opt.quiet) {
				printf("Ignoring printer share %s\n",
				       dirent->name);
			}
			break;

		case SMBC_COMMS_SHARE:
			if (!opt.quiet) {
				printf("Ignoring comms share %s\n",
				       dirent->name);
			}
			break;

		case SMBC_IPC_SHARE:
			if (!opt.quiet) {
				printf("Ignoring ipc$ share %s\n",
				       dirent->name);
			}
			break;

		default:
			fprintf(stderr, "Ignoring file '%s' of type '%d'\n",
				newname, dirent->smbc_type);
			break;
		}

		if (!ok) {
			fprintf(stderr, "Failed to download %s: %s\n",
				newname, strerror(errno));
			free(newname);
			free(tmpname);
			return false;
		}
		free(newname);
	}
	free(tmpname);

	smbc_closedir(dirhandle);
	return ok;
}

static char *print_time(long t)
{
	static char buffer[100];
	int secs, mins, hours;
	if (t < -1) {
		strncpy(buffer, "Unknown", sizeof(buffer));
		return buffer;
	}

	secs = (int)t % 60;
	mins = (int)t / 60 % 60;
	hours = (int)t / (60 * 60);
	snprintf(buffer, sizeof(buffer) - 1, "%02d:%02d:%02d", hours, mins,
		 secs);
	return buffer;
}

static void print_progress(const char *name, time_t start, time_t now,
			   off_t start_pos, off_t pos, off_t total)
{
	double avg = 0.0;
	long eta = -1;
	double prcnt = 0.0;
	char hpos[22], htotal[22], havg[22];
	char *status, *filename;
	int len;

	if (now == start || pos == start_pos) {
		fprintf(stderr, "\r[%s] No progress yet", name);
		return;
	}
	avg = 1.0 * (pos - start_pos) / (now - start);
	eta = (total - pos) / avg;
	if (total) {
		prcnt = 100.0 * pos / total;
	}

	human_readable(pos, hpos, sizeof(hpos));
	human_readable(total, htotal, sizeof(htotal));
	human_readable(avg, havg, sizeof(havg));

	len = asprintf(&status, "%s of %s (%.2f%%) at %s/s ETA: %s", hpos,
		       htotal, prcnt, havg, print_time(eta));
	if (len == -1) {
		return;
	}

	if (columns) {
		int required = strlen(name),
		    available = columns - len - strlen("[] ");
		if (required > available) {
			if (asprintf(&filename, "...%s",
				     name + required - available + 3) == -1) {
				return;
			}
		} else {
			filename = SMB_STRNDUP(name, available);
		}
	} else {
		filename = SMB_STRDUP(name);
	}

	fprintf(stderr, "\r[%s] %s", filename, status);

	free(filename);
	free(status);
}

/* Return false on error, true on success. */

static bool smb_download_file(const char *base, const char *name,
			      bool recursive, bool resume, bool toplevel,
			      char *outfile)
{
	int remotehandle, localhandle;
	time_t start_time = time_mono(NULL);
	const char *newpath;
	char path[SMB_MAXPATHLEN];
	char checkbuf[2][RESUME_CHECK_SIZE];
	char *readbuf = NULL;
	off_t offset_download = 0, offset_check = 0, curpos = 0,
	      start_offset = 0;
	struct stat localstat, remotestat;
	clock_t start_of_bucket_ticks = 0;
	size_t bytes_in_bucket = 0;
	size_t bucket_size = 0;
	clock_t ticks_to_fill_bucket = 0;

	snprintf(path, SMB_MAXPATHLEN-1, "%s%s%s", base,
		 (*base && *name && name[0] != '/' &&
		  base[strlen(base)-1] != '/') ? "/" : "",
		 name);

	remotehandle = smbc_open(path, O_RDONLY, 0755);

	if (remotehandle < 0) {
		switch (errno) {
		case EISDIR:
			if (!recursive) {
				fprintf(stderr,
					"%s is a directory. Specify -R "
					"to download recursively\n",
					path);
				return false;
			}
			return smb_download_dir(base, name, resume);

		case ENOENT:
			fprintf(stderr,
				"%s can't be found on the remote server\n",
				path);
			return false;

		case ENOMEM:
			fprintf(stderr, "Not enough memory\n");
			return false;

		case ENODEV:
			fprintf(stderr,
				"The share name used in %s does not exist\n",
				path);
			return false;

		case EACCES:
			fprintf(stderr, "You don't have enough permissions "
				"to access %s\n",
				path);
			return false;

		default:
			perror("smbc_open");
			return false;
		}
	}

	if (smbc_fstat(remotehandle, &remotestat) < 0) {
		fprintf(stderr, "Can't stat %s: %s\n", path, strerror(errno));
		return false;
	}

	if (outfile) {
		newpath = outfile;
	} else if (!name[0]) {
		newpath = strrchr(base, '/');
		if (newpath) {
			newpath++;
		} else {
			newpath = base;
		}
	} else {
		newpath = name;
	}

	if (!toplevel && (newpath[0] == '/')) {
		newpath++;
	}

	/* Open local file according to the mode */
	if (opt.update) {
		/* if it is up-to-date, skip */
		if (stat(newpath, &localstat) == 0 &&
		    localstat.st_mtime >= remotestat.st_mtime) {
			if (opt.verbose) {
				printf("%s is up-to-date, skipping\n", newpath);
			}
			smbc_close(remotehandle);
			return true;
		}
		/* else open it for writing and truncate if it exists */
		localhandle = open(
		    newpath, O_CREAT | O_NONBLOCK | O_RDWR | O_TRUNC, 0775);
		if (localhandle < 0) {
			fprintf(stderr, "Can't open %s : %s\n", newpath,
				strerror(errno));
			smbc_close(remotehandle);
			return false;
		}
		/* no offset */
	} else if (!opt.send_stdout) {
		localhandle = open(newpath, O_CREAT | O_NONBLOCK | O_RDWR |
						(!resume ? O_EXCL : 0),
				   0755);
		if (localhandle < 0) {
			fprintf(stderr, "Can't open %s: %s\n", newpath,
				strerror(errno));
			smbc_close(remotehandle);
			return false;
		}

		if (fstat(localhandle, &localstat) != 0) {
			fprintf(stderr, "Can't fstat %s: %s\n", newpath,
				strerror(errno));
			smbc_close(remotehandle);
			close(localhandle);
			return false;
		}

		start_offset = localstat.st_size;

		if (localstat.st_size &&
		    localstat.st_size == remotestat.st_size) {
			if (opt.verbose) {
				fprintf(stderr, "%s is already downloaded "
					"completely.\n",
					path);
			} else if (!opt.quiet) {
				fprintf(stderr, "%s\n", path);
			}
			smbc_close(remotehandle);
			close(localhandle);
			return true;
		}

		if (localstat.st_size > RESUME_CHECK_OFFSET &&
		    remotestat.st_size > RESUME_CHECK_OFFSET) {
			offset_download =
			    localstat.st_size - RESUME_DOWNLOAD_OFFSET;
			offset_check = localstat.st_size - RESUME_CHECK_OFFSET;
			if (opt.verbose) {
				printf("Trying to start resume of %s at %jd\n"
				       "At the moment %jd of %jd bytes have "
				       "been retrieved\n",
				       newpath, (intmax_t)offset_check,
				       (intmax_t)localstat.st_size,
				       (intmax_t)remotestat.st_size);
			}
		}

		if (offset_check) {
			off_t off1, off2;
			/* First, check all bytes from offset_check to
			 * offset_download */
			off1 = lseek(localhandle, offset_check, SEEK_SET);
			if (off1 < 0) {
				fprintf(stderr,
					"Can't seek to %jd in local file %s\n",
					(intmax_t)offset_check, newpath);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}

			off2 = smbc_lseek(remotehandle, offset_check, SEEK_SET);
			if (off2 < 0) {
				fprintf(stderr,
					"Can't seek to %jd in remote file %s\n",
					(intmax_t)offset_check, newpath);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}

			if (off1 != off2) {
				fprintf(stderr, "Offset in local and remote "
					"files are different "
					"(local: %jd, remote: %jd)\n",
					(intmax_t)off1, (intmax_t)off2);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}

			if (smbc_read(remotehandle, checkbuf[0],
				      RESUME_CHECK_SIZE) != RESUME_CHECK_SIZE) {
				fprintf(stderr, "Can't read %d bytes from "
					"remote file %s\n",
					RESUME_CHECK_SIZE, path);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}

			if (read(localhandle, checkbuf[1], RESUME_CHECK_SIZE) !=
			    RESUME_CHECK_SIZE) {
				fprintf(stderr, "Can't read %d bytes from "
					"local file %s\n",
					RESUME_CHECK_SIZE, name);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}

			if (memcmp(checkbuf[0], checkbuf[1],
				   RESUME_CHECK_SIZE) == 0) {
				if (opt.verbose) {
					printf("Current local and remote file "
					       "appear to be the same. "
					       "Starting download from "
					       "offset %jd\n",
					       (intmax_t)offset_download);
				}
			} else {
				fprintf(stderr, "Local and remote file appear "
					"to be different, not "
					"doing resume for %s\n",
					path);
				smbc_close(remotehandle);
				close(localhandle);
				return false;
			}
		}
	} else {
		localhandle = STDOUT_FILENO;
		start_offset = 0;
		offset_download = 0;
		offset_check = 0;
	}

	/* We implement rate limiting by filling up a bucket with bytes and
	 * checking, once the bucket is filled, if it was filled too fast.
	 * If so, we sleep for some time to get an average transfer rate that
	 * equals to the one set by the user.
	 *
	 * The bucket size directly affects the traffic characteristics.
	 * The smaller the bucket the more frequent the pause/resume cycle.
	 * A large bucket can result in burst of high speed traffic and large
	 * pauses. A cycle of 100ms looks like a good value. This value (in
	 * ticks) is held in `ticks_to_fill_bucket`. The `bucket_size` is
	 * calculated as:
	 * `limit_rate * 1024 * / (CLOCKS_PER_SEC / ticks_to_fill_bucket)`
	 *
	 * After selecting the bucket size we also need to check the blocksize
	 * of the transfer, since this is the minimum unit of traffic that we
	 * can observe. Achieving a ~10% precision requires a blocksize with a
	 * maximum size of `bucket_size / 10`.
	 */
	if (opt.limit_rate > 0) {
		unsigned max_block_size;
		/* This is the time that the bucket should take to fill. */
		ticks_to_fill_bucket = 100 /*ms*/ * CLOCKS_PER_SEC / 1000;
		/* This is the size of the bucket in bytes.
		 * If we fill the bucket too quickly we should pause */
		bucket_size = opt.limit_rate * 1024 / (CLOCKS_PER_SEC / ticks_to_fill_bucket);
		max_block_size = bucket_size / 10;
		max_block_size = max_block_size > 0 ? max_block_size : 1;
		if (opt.blocksize > max_block_size) {
			if (opt.blocksize != SMB_DEFAULT_BLOCKSIZE) {
				fprintf(stderr,
				        "Warning: Overriding block size to %d "
					"due to limit-rate", max_block_size);
			}
			opt.blocksize = max_block_size;
		}
		start_of_bucket_ticks = clock();
	}

	readbuf = (char *)SMB_MALLOC(opt.blocksize);
	if (!readbuf) {
		fprintf(stderr, "Failed to allocate %zu bytes for read "
				"buffer (%s)", opt.blocksize, strerror(errno));
		if (localhandle != STDOUT_FILENO) {
			close(localhandle);
		}
		return false;
	}

	/* Now, download all bytes from offset_download to the end */
	for (curpos = offset_download; curpos < remotestat.st_size;
	     curpos += opt.blocksize) {
		ssize_t bytesread;
		ssize_t byteswritten;

		/* Rate limiting. This pauses the transfer to limit traffic. */
		if (opt.limit_rate > 0) {
			if (bytes_in_bucket > bucket_size) {
				clock_t now_ticks = clock();
				clock_t diff_ticks = now_ticks
				                     - start_of_bucket_ticks;
				/* Check if the bucket filled up too fast. */
				if (diff_ticks < ticks_to_fill_bucket) {
					/* Pause until `ticks_to_fill_bucket` */
					double sleep_us
					 = (ticks_to_fill_bucket - diff_ticks)
					  * 1000000.0 / CLOCKS_PER_SEC;
					usleep(sleep_us);
				}
				/* Reset the byte counter and the ticks. */
				bytes_in_bucket = 0;
				start_of_bucket_ticks = clock();
			}
		}

		bytesread = smbc_read(remotehandle, readbuf, opt.blocksize);
		if (opt.limit_rate > 0) {
			bytes_in_bucket += bytesread;
		}
		if(bytesread < 0) {
			fprintf(stderr,
				"Can't read %zu bytes at offset %jd, file %s\n",
				opt.blocksize, (intmax_t)curpos, path);
			smbc_close(remotehandle);
			if (localhandle != STDOUT_FILENO) {
				close(localhandle);
			}
			free(readbuf);
			return false;
		}

		total_bytes += bytesread;

		byteswritten = write(localhandle, readbuf, bytesread);
		if (byteswritten != bytesread) {
			fprintf(stderr,
				"Can't write %zd bytes to local file %s at "
				"offset %jd\n", bytesread, path,
				(intmax_t)curpos);
			free(readbuf);
			smbc_close(remotehandle);
			if (localhandle != STDOUT_FILENO) {
				close(localhandle);
			}
			return false;
		}

		if (opt.dots) {
			fputc('.', stderr);
		} else if (!opt.quiet) {
			print_progress(newpath, start_time, time_mono(NULL),
				       start_offset, curpos,
				       remotestat.st_size);
		}
	}

	free(readbuf);

	if (opt.dots) {
		fputc('\n', stderr);
		printf("%s downloaded\n", path);
	} else if (!opt.quiet) {
		int i;
		fprintf(stderr, "\r%s", path);
		if (columns) {
			for (i = strlen(path); i < columns; i++) {
				fputc(' ', stderr);
			}
		}
		fputc('\n', stderr);
	}

	smbc_close(remotehandle);
	if (localhandle != STDOUT_FILENO) {
		close(localhandle);
	}
	return true;
}

static void clean_exit(void)
{
	char bs[100];
	human_readable(total_bytes, bs, sizeof(bs));
	if (!opt.quiet) {
		fprintf(stderr, "Downloaded %s in %lu seconds\n", bs,
			(unsigned long)(time_mono(NULL) - total_start_time));
	}
	exit(0);
}

static void signal_quit(int v)
{
	clean_exit();
}

int main(int argc, char **argv)
{
	int c = 0;
	const char *file = NULL;
	int smb_encrypt = false;
	int resume = 0, recursive = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok = false;
	const char **argv_const = discard_const_p(const char *, argv);
	struct poptOption long_options[] = {
		POPT_AUTOHELP

		{
			.longName   = "guest",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'a',
			.descrip    = "Work as user guest"
		},
		{
			.longName   = "encrypt",
			.shortName  = 'e',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &smb_encrypt,
			.val        = 1,
			.descrip    = "Encrypt SMB transport"
		},
		{
			.longName   = "resume",
			.shortName  = 'r',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &resume,
			.val        = 1,
			.descrip    = "Automatically resume aborted files"
		},
		{
			.longName   = "update",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt.update,
			.val        = 1,
			.descrip    = "Download only when remote file is "
				      "newer than local file or local file "
				      "is missing"
		},
		{
			.longName   = "recursive",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &recursive,
			.val        = true,
			.descrip    = "Recursively download files"
		},
		{
			.longName   = "blocksize",
			.shortName  = 'b',
			.argInfo    = POPT_ARG_INT,
			.arg        = &opt.blocksize,
			.val        = 'b',
			.descrip    = "Change number of bytes in a block"
		},

		{
			.longName   = "outputfile",
			.shortName  = 'o',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt.outputfile,
			.val        = 'o',
			.descrip    = "Write downloaded data to specified file"
		},
		{
			.longName   = "stdout",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt.send_stdout,
			.val        = true,
			.descrip    = "Write data to stdout"
		},
		{
			.longName   = "dots",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt.dots,
			.val        = 1,
			.descrip    = "Show dots as progress indication"
		},
		{
			.longName   = "quiet",
			.shortName  = 'q',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt.quiet,
			.val        = 1,
			.descrip    = "Be quiet"
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &opt.verbose,
			.val        = 1,
			.descrip    = "Be verbose"
		},
		{
			.longName   = "limit-rate",
			.shortName  = 0,
			.argInfo    = POPT_ARG_INT,
			.arg        = &opt.limit_rate,
			.val        = 'l',
			.descrip    = "Limit download speed to this many KB/s"
		},

		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_LEGACY_S3
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};
	poptContext pc = NULL;
	struct cli_credentials *creds = NULL;
	enum smb_encryption_setting encryption_state = SMB_ENCRYPTION_DEFAULT;
	enum credentials_use_kerberos use_kerberos = CRED_USE_KERBEROS_DESIRED;
	smbc_smb_encrypt_level encrypt_level = SMBC_ENCRYPTLEVEL_DEFAULT;
#if 0
	enum smb_signing_setting signing_state = SMB_SIGNING_DEFAULT;
	const char *use_signing = "auto";
#endif
	bool is_nt_hash = false;
	uint32_t gensec_features;
	bool use_wbccache = false;
	SMBCCTX *smb_ctx = NULL;
	int dbg_lvl = -1;
	int rc;

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false);
	if (!ok) {
		goto done;
	}

#ifdef SIGWINCH
	signal(SIGWINCH, change_columns);
#endif
	signal(SIGINT, signal_quit);
	signal(SIGTERM, signal_quit);

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options,
				    0);
	if (pc == NULL) {
		ok = false;
		goto done;
	}

	creds = samba_cmdline_get_creds();

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 'a':
			cli_credentials_set_anonymous(creds);
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(c));
			poptPrintUsage(pc, stderr, 0);
			ok = false;
			goto done;
		}

		if (c < -1) {
			fprintf(stderr, "%s: %s\n",
				poptBadOption(pc, POPT_BADOPTION_NOALIAS),
				poptStrerror(c));
			ok = false;
			goto done;
		}
	}

	if ((opt.send_stdout || resume || opt.outputfile) && opt.update) {
		fprintf(stderr, "The -o, -R or -O and -U options can not be "
			"used together.\n");
		ok = true;
		goto done;
	}
	if ((opt.send_stdout || opt.outputfile) && recursive) {
		fprintf(stderr, "The -o or -O and -R options can not be "
			"used together.\n");
		ok = true;
		goto done;
	}

	if (opt.outputfile && opt.send_stdout) {
		fprintf(stderr, "The -o and -O options can not be "
			"used together.\n");
		ok = true;
		goto done;
	}

	samba_cmdline_burn(argc, argv);

	/* smbc_new_context() will set the log level to 0 */
	dbg_lvl = debuglevel_get();

	smb_ctx = smbc_new_context();
	if (smb_ctx == NULL) {
		fprintf(stderr, "Unable to initialize libsmbclient\n");
		ok = false;
		goto done;
	}
	smbc_setDebug(smb_ctx, dbg_lvl);

	rc = smbc_setConfiguration(smb_ctx, lp_default_path());
	if (rc < 0) {
		ok = false;
		goto done;
	}

	smbc_setFunctionAuthDataWithContext(smb_ctx,
					    get_auth_data_with_context_fn);

	ok = smbc_init_context(smb_ctx);
	if (!ok) {
		goto done;
	}
	smbc_set_context(smb_ctx);

	encryption_state = cli_credentials_get_smb_encryption(creds);
	switch (encryption_state) {
	case SMB_ENCRYPTION_REQUIRED:
		encrypt_level = SMBC_ENCRYPTLEVEL_REQUIRE;
		break;
	case SMB_ENCRYPTION_DESIRED:
	case SMB_ENCRYPTION_IF_REQUIRED:
		encrypt_level = SMBC_ENCRYPTLEVEL_REQUEST;
		break;
	case SMB_ENCRYPTION_OFF:
		encrypt_level = SMBC_ENCRYPTLEVEL_NONE;
		break;
	case SMB_ENCRYPTION_DEFAULT:
		encrypt_level = SMBC_ENCRYPTLEVEL_DEFAULT;
		break;
	}
	if (smb_encrypt) {
		encrypt_level = SMBC_ENCRYPTLEVEL_REQUIRE;
	}
	smbc_setOptionSmbEncryptionLevel(smb_ctx, encrypt_level);

#if 0
	signing_state = cli_credentials_get_smb_signing(creds);
	if (encryption_state >= SMB_ENCRYPTION_DESIRED) {
		signing_state = SMB_SIGNING_REQUIRED;
	}
	switch (signing_state) {
	case SMB_SIGNING_REQUIRED:
		use_signing = "required";
		break;
	case SMB_SIGNING_DEFAULT:
	case SMB_SIGNING_DESIRED:
	case SMB_SIGNING_IF_REQUIRED:
		use_signing = "yes";
		break;
	case SMB_SIGNING_OFF:
		use_signing = "off";
		break;
	default:
		use_signing = "auto";
		break;
	}
	/* FIXME: There is no libsmbclient function to set signing state */
#endif

	use_kerberos = cli_credentials_get_kerberos_state(creds);
	switch (use_kerberos) {
	case CRED_USE_KERBEROS_REQUIRED:
		smbc_setOptionUseKerberos(smb_ctx, true);
		smbc_setOptionFallbackAfterKerberos(smb_ctx, false);
		break;
	case CRED_USE_KERBEROS_DESIRED:
		smbc_setOptionUseKerberos(smb_ctx, true);
		smbc_setOptionFallbackAfterKerberos(smb_ctx, true);
		break;
	case CRED_USE_KERBEROS_DISABLED:
		smbc_setOptionUseKerberos(smb_ctx, false);
		break;
	}

	/* Check if the password supplied is an NT hash */
	is_nt_hash = cli_credentials_is_password_nt_hash(creds);
	smbc_setOptionUseNTHash(smb_ctx, is_nt_hash);

	/* Check if we should use the winbind ccache */
	gensec_features = cli_credentials_get_gensec_features(creds);
	use_wbccache = (gensec_features & GENSEC_FEATURE_NTLM_CCACHE);
	smbc_setOptionUseCCache(smb_ctx, use_wbccache);

	columns = get_num_cols();

	total_start_time = time_mono(NULL);

	while ((file = poptGetArg(pc))) {
		if (!recursive) {
			ok = smb_download_file(file, "", recursive, resume,
						true, opt.outputfile);
		} else {
			ok = smb_download_dir(file, "", resume);
		}
	}

done:
	gfree_all();
	poptFreeContext(pc);
	TALLOC_FREE(frame);
	if (ok) {
		clean_exit();
	}
	return ok ? 0 : 1;
}
