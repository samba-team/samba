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
#include "popt_common_cmdline.h"
#include "libsmbclient.h"
#include "cmdline_contexts.h"

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
	char *workgroup;
	bool username_specified;
	char *username;
	bool password_specified;
	char *password;

	char *outputfile;
	size_t blocksize;

	bool nonprompt;
	bool quiet;
	bool dots;
	bool verbose;
	bool send_stdout;
	bool update;
	int debuglevel;
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

static void get_auth_data(const char *srv, const char *shr, char *wg, int wglen,
			  char *un, int unlen, char *pw, int pwlen)
{
	static bool hasasked = false;
	static char *savedwg;
	static char *savedun;
	static char *savedpw;

	if (hasasked) {
		strncpy(wg, savedwg, wglen - 1);
		strncpy(un, savedun, unlen - 1);
		strncpy(pw, savedpw, pwlen - 1);
		return;
	}
	hasasked = true;

	/*
	 * If no user has been specified un is initialized with the current
	 * username of the user who started smbget.
	 */
	if (opt.username_specified) {
		strncpy(un, opt.username, unlen - 1);
	}

	if (!opt.nonprompt && !opt.password_specified && pw[0] == '\0') {
		char *prompt;
		int rc;

		rc = asprintf(&prompt,
			      "Password for [%s] connecting to //%s/%s: ",
			      un, shr, srv);
		if (rc == -1) {
			return;
		}
		(void)samba_getpass(prompt, pw, pwlen, false, false);
		free(prompt);
	} else if (opt.password != NULL) {
		strncpy(pw, opt.password, pwlen-1);
	}

	if (opt.workgroup != NULL) {
		strncpy(wg, opt.workgroup, wglen-1);
	}

	/* save the values found for later */
	savedwg = SMB_STRDUP(wg);
	savedun = SMB_STRDUP(un);
	savedpw = SMB_STRDUP(pw);

	if (!opt.quiet) {
		char *wgtmp, *usertmp;
		wgtmp = SMB_STRNDUP(wg, wglen);
		usertmp = SMB_STRNDUP(un, unlen);
		printf("Using workgroup %s, %s%s\n",
		       wgtmp,
		       *usertmp ? "user " : "guest user",
		       usertmp);
		free(wgtmp);
		free(usertmp);
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
	if (now - start) {
		avg = 1.0 * (pos - start_pos) / (now - start);
	}
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

		bytesread = smbc_read(remotehandle, readbuf, opt.blocksize);
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

static int readrcfile(const char *name, const struct poptOption long_options[])
{
	FILE *fd = fopen(name, "r");
	int lineno = 0, i;
	char var[101], val[101];
	bool found;
	int *intdata;
	char **stringdata;
	if (!fd) {
		fprintf(stderr, "Can't open RC file %s\n", name);
		return 1;
	}

	while (!feof(fd)) {
		lineno++;
		if (fscanf(fd, "%100s %100s\n", var, val) < 2) {
			fprintf(stderr,
				"Can't parse line %d of %s, ignoring.\n",
				lineno, name);
			continue;
		}

		found = false;

		for (i = 0; long_options[i].argInfo; i++) {
			if (!long_options[i].longName) {
				continue;
			}
			if (strcmp(long_options[i].longName, var)) {
				continue;
			}
			if (!long_options[i].arg) {
				continue;
			}

			switch (long_options[i].argInfo) {
			case POPT_ARG_NONE:
				intdata = (int *)long_options[i].arg;
				if (!strcmp(val, "on")) {
					*intdata = 1;
				} else if (!strcmp(val, "off")) {
					*intdata = 0;
				} else {
					fprintf(stderr, "Illegal value %s for "
						"%s at line %d in %s\n",
						val, var, lineno, name);
				}
				break;
			case POPT_ARG_INT:
				intdata = (int *)long_options[i].arg;
				*intdata = atoi(val);
				break;
			case POPT_ARG_STRING:
				stringdata = (char **)long_options[i].arg;
				*stringdata = SMB_STRDUP(val);
				if (long_options[i].shortName == 'U') {
					char *p;
					opt.username_specified = true;
					p = strchr(*stringdata, '%');
					if (p != NULL) {
						*p = '\0';
						opt.password = p + 1;
						opt.password_specified = true;
					}
				}
				break;
			default:
				fprintf(stderr, "Invalid variable %s at "
					"line %d in %s\n",
					var, lineno, name);
				break;
			}

			found = true;
		}
		if (!found) {
			fprintf(stderr,
				"Invalid variable %s at line %d in %s\n", var,
				lineno, name);
		}
	}

	fclose(fd);
	return 0;
}

int main(int argc, char **argv)
{
	int c = 0;
	const char *file = NULL;
	char *rcfile = NULL;
	bool smb_encrypt = false;
	int resume = 0, recursive = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ret = true;
	char *p;
	const char **argv_const = discard_const_p(const char *, argv);
	struct poptOption long_options[] = {
		POPT_AUTOHELP

		{
			.longName   = "workgroup",
			.shortName  = 'w',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt.workgroup,
			.val        = 'w',
			.descrip    = "Workgroup to use (optional)"
		},
		{
			.longName   = "user",
			.shortName  = 'U',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &opt.username,
			.val        = 'U',
			.descrip    = "Username to use"
		},
		{
			.longName   = "guest",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'a',
			.descrip    = "Work as user guest"
		},

		{
			.longName   = "nonprompt",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'n',
			.descrip    = "Don't ask anything (non-interactive)"
		},
		{
			.longName   = "debuglevel",
			.shortName  = 'd',
			.argInfo    = POPT_ARG_INT,
			.arg        = &opt.debuglevel,
			.val        = 'd',
			.descrip    = "Debuglevel to use"
		},

		{
			.longName   = "encrypt",
			.shortName  = 'e',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'e',
			.descrip    = "Encrypt SMB transport"
		},
		{
			.longName   = "resume",
			.shortName  = 'r',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'r',
			.descrip    = "Automatically resume aborted files"
		},
		{
			.longName   = "update",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'u',
			.descrip    = "Download only when remote file is "
				      "newer than local file or local file "
				      "is missing"
		},
		{
			.longName   = "recursive",
			.shortName  = 'R',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'R',
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
			.shortName  = 'O',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'O',
			.descrip    = "Write data to stdout"
		},
		{
			.longName   = "dots",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'D',
			.descrip    = "Show dots as progress indication"
		},
		{
			.longName   = "quiet",
			.shortName  = 'q',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'q',
			.descrip    = "Be quiet"
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'v',
			.descrip    = "Be verbose"
		},
		{
			.longName   = "rcfile",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'f',
			.descrip    = "Use specified rc file"
		},

		POPT_TABLEEND
	};
	poptContext pc;

	smb_init_locale();

	/* only read rcfile if it exists */
	if (asprintf(&rcfile, "%s/.smbgetrc", getenv("HOME")) == -1) {
		return 1;
	}
	if (access(rcfile, F_OK) == 0) {
		readrcfile(rcfile, long_options);
	}
	free(rcfile);

#ifdef SIGWINCH
	signal(SIGWINCH, change_columns);
#endif
	signal(SIGINT, signal_quit);
	signal(SIGTERM, signal_quit);

	pc = poptGetContext(argv[0], argc, argv_const, long_options, 0);

	while ((c = poptGetNextOpt(pc)) > 0) {
		switch (c) {
		case 'f':
			readrcfile(poptGetOptArg(pc), long_options);
			break;
		case 'a':
			opt.username_specified = true;
			opt.username = talloc_strdup(frame, "");
			opt.password_specified = true;
			opt.password = talloc_strdup(frame, "");
			break;
		case 'e':
			smb_encrypt = true;
			break;
		case 'U':
			opt.username_specified = true;
			opt.username = talloc_strdup(frame, opt.username);
			p = strchr(opt.username,'%');
			if (p != NULL) {
				*p = '\0';
				opt.password = p + 1;
				opt.password_specified = true;
			}
			break;
		case 'n':
			opt.nonprompt = true;
			break;
		case 'r':
			resume = true;
			break;
		case 'u':
			opt.update = true;
			break;
		case 'R':
			recursive = true;
			break;
		case 'O':
			opt.send_stdout = true;
			break;
		case 'D':
			opt.dots = true;
			break;
		case 'q':
			opt.quiet = true;
			break;
		case 'v':
			opt.verbose = true;
			break;
		}
	}

	if (c < -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(pc, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		ret = 1;
		goto done;
	}

	if ((opt.send_stdout || resume || opt.outputfile) && opt.update) {
		fprintf(stderr, "The -o, -R or -O and -U options can not be "
			"used together.\n");
		ret = 1;
		goto done;
	}
	if ((opt.send_stdout || opt.outputfile) && recursive) {
		fprintf(stderr, "The -o or -O and -R options can not be "
			"used together.\n");
		ret = 1;
		goto done;
	}

	if (opt.outputfile && opt.send_stdout) {
		fprintf(stderr, "The -o and -O options can not be "
			"used together.\n");
		ret = 1;
		goto done;
	}

	popt_burn_cmdline_password(argc, argv);

	if (smbc_init(get_auth_data, opt.debuglevel) < 0) {
		fprintf(stderr, "Unable to initialize libsmbclient\n");
		ret= 1;
		goto done;
	}

	if (smb_encrypt) {
		SMBCCTX *smb_ctx = smbc_set_context(NULL);
		smbc_option_set(smb_ctx,
				discard_const_p(char, "smb_encrypt_level"),
				"require");
	}

	columns = get_num_cols();

	total_start_time = time_mono(NULL);

	while ((file = poptGetArg(pc))) {
		if (!recursive) {
			ret = smb_download_file(file, "", recursive, resume,
						true, opt.outputfile);
		} else {
			ret = smb_download_dir(file, "", resume);
		}
	}

done:
	poptFreeContext(pc);
	TALLOC_FREE(frame);
	if (ret) {
		clean_exit();
	}
	return ret?0:1;
}
