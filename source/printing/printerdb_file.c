#include "includes.h"

#define FORMS_PREFIX "FORMS"
#define DRIVERS_PREFIX "DRIVERS"
#define DRIVERSINIT_PREFIX "DRIVERSINIT"
#define PRINTERS_PREFIX "PRINTERS"
#define SECDESC_PREFIX "SECDESC"
#define GLOBALS_PREFIX "GLOBALS"


static const char *file_root = NULL;

struct table_node {
	const char *long_archi;
	const char *short_archi;
	int version;
};

static const struct table_node archi_table[]= {

	{"Windows 4.0",          "WIN40",	0 },
	{"Windows NT x86",       "W32X86",	2 },
	{"Windows NT x86",       "W32X86",	3 },
	{"Windows NT R4000",     "W32MIPS",	2 },
	{"Windows NT Alpha_AXP", "W32ALPHA",	2 },
	{"Windows NT PowerPC",   "W32PPC",	2 },
	{"Windows IA64",         "IA64",	3 },
	{"Windows x64",          "x64",		3 },
	{NULL,                   "",		-1 }
};

struct file_list {
	struct file_list *prev, *next;
	char *file_path;
	char *file;
};

static BOOL file_find(TALLOC_CTX *mem_ctx, struct file_list **list,
		      const char *directory) 
{
	DIR *dir;
	struct file_list *entry;
	char *path, *filename;
	const char *dname;
	int num_files = 0;

	*list = TALLOC_ZERO_P(mem_ctx, struct file_list);
	if (*list == NULL)
		return False;

	dir = opendir(directory);
	if (!dir)
		return False;

        while ((dname = readdirname(dir))) {

		if (!strcmp("..", dname))
			continue;
		if (!strcmp(".", dname))
			continue;

		path = talloc_asprintf(mem_ctx, "%s/%s", directory, dname);
		filename = talloc_strdup(mem_ctx, dname);
		
		if ((path == NULL) || (filename == NULL))
			return False;

		entry = TALLOC_ZERO_P(mem_ctx, struct file_list);
		if (!entry) {
			DEBUG(0,("Out of memory in file_find\n"));
			closedir(dir);
			return False;
		}
		entry->file_path = path;
		entry->file = filename;
		DLIST_ADD(*list, entry);

		++num_files;
        }

	closedir(dir);

	if (num_files == 0)
		return False;

	DEBUG(0,("found: %d files\n", num_files));

	return True;
}

static BOOL check_dir(const char *directory, BOOL create_dir)
{
	struct stat st;
	mode_t old_umask;
	int dir_perms = 0777;
/*	int dir_perms = 0755; FIXME: become_root() blocks...*/

	old_umask = umask(0);
        
	if (lstat(directory, &st) == -1) {
		if (errno == ENOENT) {
			/* Create directory */
			if (create_dir) {
				if (mkdir(directory, dir_perms) == -1) {
					DEBUG(0, ("error creating printerdb directory "
						"%s: %s\n", directory, 
						strerror(errno)));
					goto out_umask;
				} else {
					goto out_umask;
				}
			} else {
				DEBUG(0, ("dir %s does not exist\n", directory));
				umask(old_umask);
				return False;
			}
		} else {
			DEBUG(0, ("lstat failed on printerdb directory %s: %s\n",
				directory, strerror(errno)));
			goto out_umask;
		}
	} else {
		/* Check ownership and permission on existing directory */
		if (!S_ISDIR(st.st_mode)) {
			DEBUG(0, ("printerdb directory %s isn't a directory\n",
				directory));
			goto out_umask;
		}
		if ((st.st_uid != sec_initial_uid()) || 
				((st.st_mode & dir_perms) != dir_perms)) {
			DEBUG(0, ("invalid permissions on printerdb directory "
				"%s\n", directory));
			goto out_umask;
		}
	}

out_umask:
	umask(old_umask);
	return True;

}

static BOOL create_prefix_dir(const char *prefix)
{
	char *dirname;

	if (asprintf(&dirname, "%s/%s", file_root, prefix) < 0) {
		return False;
	}

	if (!check_dir(dirname, True)) {
		DEBUG(0,("create_prefix_dir: failed call check_dir()\n"));
		SAFE_FREE(dirname);
		return False;
	}

	SAFE_FREE(dirname);

	return True;
}

static BOOL create_dir_with_parents(const char *root, const char *dirname)
{
	const char *p;
	fstring tok, cur_dir;

	p = dirname;
	fstrcpy(cur_dir, root);
	fstrcat(cur_dir, "/");

	while (next_token(&p, tok, "/", sizeof(tok))) {

		fstrcat(cur_dir, tok);
		fstrcat(cur_dir, "/");

		if (!check_dir(cur_dir, True)) {
			DEBUG(0,("create_dir_with_parents: "
				 "failed call check_file_root()\n"));
			return False;
		}
	}

	return True;
}

BOOL file_printerdb_init(char *param)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_printerdb_init");
	int i;
	BOOL result = False;

	if (mem_ctx == NULL)
		goto done;

	file_root = "/var/lib/samba/printerdb";

	if ((param != NULL) && (param[0] != '\0')) {
		file_root = SMB_STRDUP(param);
	}

	if (file_root == NULL) {
		DEBUG(0, ("SMB_STRDUP failed\n"));
		goto done;
	}

	if (!check_dir(file_root, True)) {
		DEBUG(0,("file_printerdb_init: failed call "
			 "check_file_root()\n"));
		goto done;
	}

	if (!create_prefix_dir(PRINTERS_PREFIX))
		goto done;

	if (!create_prefix_dir(FORMS_PREFIX))
		goto done;

	if (!create_prefix_dir(DRIVERS_PREFIX))
		goto done;

	if (!create_prefix_dir(DRIVERSINIT_PREFIX))
		goto done;

	if (!create_prefix_dir(GLOBALS_PREFIX))
		goto done;

	if (!create_prefix_dir(SECDESC_PREFIX))
		goto done;

	for (i=0; archi_table[i].long_archi!=NULL; i++) {

		char *dirname = talloc_asprintf(mem_ctx, "%s/%s/%d",
						DRIVERS_PREFIX, 
						archi_table[i].short_archi, 
						archi_table[i].version);

		if (dirname == NULL)
			goto done;

		if (!create_dir_with_parents(file_root, dirname))
			goto done;

	}

	result = True;

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return result;
}

static BOOL read_complete_file(TALLOC_CTX *mem_ctx, const char *filename,
			       uint8_t **buf, size_t *len)
{
	int fd;
	SMB_STRUCT_STAT statbuf;

	fd = sys_open(filename, O_RDONLY, 0);
	if (fd <= 0)
		return False;

	if (sys_fstat(fd, &statbuf) != 0) {
		close(fd);
		return False;
	}

	*buf = TALLOC_ARRAY(mem_ctx, char, statbuf.st_size);
	if (*buf == NULL) {
		close(fd);
		return False;
	}

	if (read_data(fd, *buf, statbuf.st_size) != statbuf.st_size) {
		close(fd);
		free(*buf);
		return False;
	}

	close(fd);
	*len = statbuf.st_size;
	return True;
}

static BOOL write_complete_file(const char *filename,
				int open_flags, mode_t open_mode,
				const uint8_t *buf, size_t len)
{
	int fd;

	fd = sys_open(filename, open_flags, open_mode);
	if (fd < 0)
		return False;

	if (write_data(fd, buf, len) != len) {
		close(fd);
		return False;
	}

	close(fd);
	return True;
}

uint32 file_get_c_setprinter(void)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_get_c_setprinter");
	int ret;
	char *filename;
	uint8 *buf;
	size_t len;
	uint32 result = 0;

	if (mem_ctx == NULL)
		return 0;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root, GLOBALS_PREFIX,
				   "c_setprinter");
	if (filename == NULL)
		goto done;

	if (!read_complete_file(mem_ctx, filename, &buf, &len))
		goto done;

	ret = tdb_unpack(buf, len, "d", &result);

	if (ret != len)
		goto done;

	DEBUG(0,("file_get_c_setprinter: will return %d\n", result));

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return result;
}

uint32 file_update_c_setprinter(BOOL initialize) 
{
	TALLOC_CTX *mem_ctx = talloc_init("file_update_c_setprinter");
	char *filename;
	int len;
	uint8_t *buf;
	uint32 result = 0;
	uint32 c_setprinter;
	uint32 printer_count = 23;

	if (mem_ctx == NULL)
		goto done;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root, GLOBALS_PREFIX,
				   "c_setprinter");
	if (filename == NULL)
		goto done;

	/* FIXME */

	if (!initialize)
		c_setprinter = file_get_c_setprinter() + printer_count;
	else
		c_setprinter = printer_count;

	buf = NULL;
	len = 0;

	if (!tdb_pack_append(mem_ctx, &buf, &len, "d", c_setprinter))
		goto done;

	if (!write_complete_file(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644,
				 buf, len))
		goto done;

	result = c_setprinter;

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return result;
}

int file_get_forms(nt_forms_struct **list)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_get_forms");
	nt_forms_struct *tl;
	nt_forms_struct form;
	int i;
	int n = 0;
	char *dirname;
	struct file_list *file_list, *temp_list;

	if (mem_ctx == NULL)
		goto done;

	dirname = talloc_asprintf(mem_ctx, "%s/%s", file_root, FORMS_PREFIX);
	if (dirname == NULL)
		goto done;

	file_list = NULL;

	if (!file_find(mem_ctx, &file_list, dirname))
		goto done;
		
	for (temp_list = file_list; temp_list; temp_list = temp_list->next) {

		uint8_t *buf;
		size_t len;

		if (!read_complete_file(mem_ctx, temp_list->file_path,
					&buf, &len))
			goto done;

		if (tdb_unpack(buf, len, "dddddddd",
			       &i, &form.flag, &form.width, &form.length,
			       &form.left, &form.top,
			       &form.right, &form.bottom) < 0)
			goto done;

		tl = SMB_REALLOC_ARRAY(*list, nt_forms_struct, n+1);
		if (!tl) {
			DEBUG(0,("file_get_forms: Realloc fail.\n"));
			goto done;
		}
		*list = tl;
		(*list)[n] = form;
		n++;
	}

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	DEBUG(0,("file_get_forms: found %d forms\n", n));
	return n;
}

int file_write_forms(nt_forms_struct **list, int number)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_write_forms");
	char *filename;
	int i = -1;

	if (mem_ctx == NULL)
		goto done;

	filename = talloc_asprintf(mem_ctx, "%s/%s", file_root, FORMS_PREFIX);
	if (filename == NULL)
		goto done;

	if (!check_dir(filename, False)) {
		DEBUG(0,("file_write_forms: failed call check_dir()\n"));
		goto done;
	}

	for (i=0;i<number;i++) {

		uint8_t *buf = NULL;
		size_t len = 0;

		filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root,
					   FORMS_PREFIX, (*list)[i].name);

		if (filename == NULL)
			goto done;

		/* save index, so list is rebuilt in correct order */
		/* probably this has no meaning - gd */

		if (!tdb_pack_append(mem_ctx, &buf, &len, "dddddddd",
				     i, (*list)[i].flag, (*list)[i].width,
				     (*list)[i].length,
				     (*list)[i].left, (*list)[i].top,
				     (*list)[i].right, (*list)[i].bottom))
			goto done;

		if (!write_complete_file(filename,
					 O_WRONLY|O_CREAT|O_TRUNC, 0644,
					 buf, len))
			goto done;
	}

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return i;
}

/* FIXME */
static time_t file_get_last_update(int tdb)
{
	return time(NULL);
}

/* FIXME */
static BOOL file_set_last_update(time_t update, int tdb)
{
	return True;
}

static BOOL del_file(const char *filename)
{
	int ret;
	struct stat st;

	ret = lstat(filename, &st);
	if (ret == 0) {
		unlink(filename);
	} else {
		DEBUG(0,("del_file: cannot stat file %s\n", filename));
		return False;
	}

	return True;
}

static BOOL file_del_form(char *del_name, WERROR *err)
{
	char *filename;

	*err = WERR_OK;

	if (asprintf(&filename, "%s/%s/%s", file_root, FORMS_PREFIX, del_name) < 0) {
		*err = WERR_NOMEM;
		return False;
	}

	if (!del_file(filename)) {
		SAFE_FREE(filename);
		*err = WERR_BADFILE;
		return False;
	}

	SAFE_FREE(filename);
	return True;
}

int file_get_drivers(fstring **list, const char *short_archi, uint32 version)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_get_drivers");
	char *filename;
	struct file_list *file_list, *temp_list;
	int n = 0;
	fstring *loc_list;

	/* never return -1 */

	if (mem_ctx == NULL)
		goto done;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s/%d", file_root,
				   DRIVERS_PREFIX, short_archi, version);
	if (filename == NULL)
		goto done;
	
	if (!check_dir(filename, False)) {
		DEBUG(0,("file_get_drivers: failed call check_dir()\n"));
		goto done;
	}

	file_list = NULL;

	if (!file_find(mem_ctx, &file_list, filename)) {
		goto done;
	}

	for (temp_list = file_list; temp_list; temp_list = temp_list->next) {

		loc_list = SMB_REALLOC_ARRAY(*list, fstring, n+1);

		if (loc_list == NULL) {
			DEBUG(0,("get_ntdrivers: failed to enlarge list!\n"));
			n = 0;
			goto done;
		}
		
		*list = loc_list;

		if (temp_list->file == NULL)
			continue;
	
		fstrcpy((*list)[n], temp_list->file);
		++n;

	}

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return n;
}

uint32 file_add_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver,
		       const char *short_archi)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_add_driver");
	char *filename;
	int len;
	uint8_t *buf;
	int result = -1;

	if (mem_ctx == NULL)
		goto done;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s/%d/%s", file_root,
				   DRIVERS_PREFIX, short_archi,
				   driver->cversion, driver->name);
	if (filename == NULL)
		goto done;

	buf = NULL;
	len = 0;

	if (!tdb_pack_append(mem_ctx, &buf, &len, "dffffffff",
			     driver->cversion,
			     driver->name,
			     driver->environment,
			     driver->driverpath,
			     driver->datafile,
			     driver->configfile,
			     driver->helpfile,
			     driver->monitorname,
			     driver->defaultdatatype))
		goto done;

        if (driver->dependentfiles) {
		int i;
		
		for (i=0; *driver->dependentfiles[i]; i++) {
			if (!tdb_pack_append(mem_ctx, &buf, &len,
					     "f", driver->dependentfiles[i]))
				goto done;
		}
	}

	if (!write_complete_file(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644,
				 buf, len))
		goto done;

	DEBUGADD(10,("added driver [%s] to [%s]\n", driver->name, filename));

	result = 0;
done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return result;
}

WERROR file_get_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, 
		       fstring drivername, 
		       const char *short_archi, 
		       uint32 version)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_get_driver");
	char *filename;
	uint8_t *buf;
	int len;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 driver;
	WERROR result = WERR_NOMEM;

	ZERO_STRUCT(driver);

	if (mem_ctx == NULL)
		goto done;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s/%d/%s",
				   file_root, DRIVERS_PREFIX, short_archi, 
				   version, drivername);
	if (filename == NULL)
		goto done;

	if (!read_complete_file(mem_ctx, filename, &buf, &len)) {
		result = WERR_UNKNOWN_PRINTER_DRIVER;
		goto done;
	}

	tdb_unpack(buf, len, "dffffffff",
		   &driver.cversion,
		   driver.name,
		   driver.environment,
		   driver.driverpath,
		   driver.datafile,
		   driver.configfile,
		   driver.helpfile,
		   driver.monitorname,
		   driver.defaultdatatype);

	*info_ptr = (NT_PRINTER_DRIVER_INFO_LEVEL_3 *)memdup(&driver, sizeof(driver));

	result = WERR_OK;

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);
	return result;
}

BOOL file_printerdb_close(void)
{
	return True;
}

static BOOL file_del_driver(const char *short_archi, int version, const char *drivername)
{
	char *filename;

	if (asprintf(&filename, "%s/%s/%s/%d/%s", file_root, DRIVERS_PREFIX, 
				short_archi, version, drivername) < 0)
		return False;

	if (!del_file(filename)) {
		SAFE_FREE(filename);
		return False;
	}

	SAFE_FREE(filename);
	return True;
}

static BOOL file_del_driver_init(const char *drivername)
{
	char *filename;

	if (asprintf(&filename, "%s/%s/%s", file_root, DRIVERSINIT_PREFIX, drivername) < 0)
		return False;

	if (!del_file(filename)) {
		SAFE_FREE(filename);
		return False;
	}

	SAFE_FREE(filename);
	return True;
}

static WERROR file_del_printer(const char *printername)
{
	char *filename;

	if (asprintf(&filename, "%s/%s/%s", file_root, PRINTERS_PREFIX, printername) < 0)
		return WERR_NOMEM;

	if (!del_file(filename)) {
		SAFE_FREE(filename);
		return WERR_BADFILE;
	}

	SAFE_FREE(filename);
	return WERR_OK;

}

static WERROR file_get_secdesc(TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	char *filename;
	uint8_t *buf;
	int len;
	prs_struct ps;
	WERROR result = WERR_OK;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root,
				   SECDESC_PREFIX, printername);

	if (filename == NULL)
		return WERR_NOMEM;

	if (!read_complete_file(mem_ctx, filename, &buf, &len))
		return WERR_INVALID_SECURITY_DESCRIPTOR;

	if (!prs_init(&ps, 0, mem_ctx, UNMARSHALL))
		return WERR_NOMEM;

	prs_give_memory(&ps, buf, len, True);

	result = sec_io_desc_buf("file_get_secdesc", secdesc_ctr, &ps, 1) ?
		WERR_OK : WERR_NOMEM;

	prs_mem_free(&ps);
	return result;
}

WERROR file_set_secdesc(TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF *secdesc_ctr)
{
	prs_struct ps;
	char *filename;
	WERROR result = WERR_OK;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root,
				   SECDESC_PREFIX, printername);

	if (filename == NULL)
		return WERR_NOMEM;

	prs_init(&ps, (uint32)sec_desc_size(secdesc_ctr->sec) +
		sizeof(SEC_DESC_BUF), mem_ctx, MARSHALL);

	if (!sec_io_desc_buf("file_set_secdesc", &secdesc_ctr, &ps, 1)) {
		result = WERR_NOMEM;
		goto done;
	}

	if (!write_complete_file(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644,
				 ps.data_p, ps.data_offset)) {
		result = WERR_GENERAL_FAILURE;
		goto done;
	}

done:
	prs_mem_free(&ps);
	return result;
}

WERROR file_get_printer(NT_PRINTER_INFO_LEVEL_2 **info_ptr, const char *sharename)
{
	TALLOC_CTX *mem_ctx = talloc_init("file_get_printer");
	NT_PRINTER_INFO_LEVEL_2 info;
	char *filename;
	uint8_t *buf;
	int len;
	WERROR result = WERR_OK;

	ZERO_STRUCT(info);

	if (mem_ctx == NULL)
		return WERR_NOMEM;

	filename = talloc_asprintf(mem_ctx, "%s/%s/%s", file_root, PRINTERS_PREFIX,
				   sharename);
	if (filename == NULL)
		return WERR_NOMEM;

	if (!read_complete_file(mem_ctx, filename, &buf, &len)) {
		result = WERR_INVALID_PRINTER_NAME;
		goto done;
	}

	len += tdb_unpack(buf, len, "dddddddddddfffffPfffff",
			&info.attributes,
			&info.priority,
			&info.default_priority,
			&info.starttime,
			&info.untiltime,
			&info.status,
			&info.cjobs,
			&info.averageppm,
			&info.changeid,
			&info.c_setprinter,
			&info.setuptime,
			info.servername,
			info.printername,
			info.sharename,
			info.portname,
			info.drivername,
			info.comment,
			info.location,
			info.sepfile,
			info.printprocessor,
			info.datatype,
			info.parameters);

#if 0
	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);

	len += unpack_values( &info.data, dbuf.dptr+len, dbuf.dsize-len );
#endif
	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));

 done:
	if (mem_ctx != NULL)
		talloc_destroy(mem_ctx);

	return result;
}

WERROR file_update_printer(NT_PRINTER_INFO_LEVEL_2 *info)
{
	char *filename;
	int len;
	uint8_t *buf;
	WERROR result;
	int buflen;

	if (asprintf(&filename, "%s/%s/%s", file_root, PRINTERS_PREFIX, info->sharename) < 0)
		return WERR_NOMEM;

	buf = NULL;
	buflen = 0;

 again:	
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dddddddddddfffffPfffff",
			info->attributes,
			info->priority,
			info->default_priority,
			info->starttime,
			info->untiltime,
			info->status,
			info->cjobs,
			info->averageppm,
			info->changeid,
			info->c_setprinter,
			info->setuptime,
			info->servername,
			info->printername,
			info->sharename,
			info->portname,
			info->drivername,
			info->comment,
			info->location,
			info->sepfile,
			info->printprocessor,
			info->datatype,
			info->parameters);

	len += pack_devicemode(info->devmode, buf+len, buflen-len);
	
	len += pack_values( &info->data, buf+len, buflen-len );

	if (buflen != len) {
		char *tb;

		tb = (char *)SMB_REALLOC(buf, len);
		if (!tb) {
			DEBUG(0,("update_a_printer_2: failed to enlarge buffer!\n"));
			result = WERR_NOMEM;
			goto done;
		}
		else buf = tb;
		buflen = len;
		goto again;
	}
	
	if (!write_complete_file(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644,
				 buf, len)) {
		result = WERR_NOMEM;
		goto done;
	}

	result = WERR_OK;

	DEBUG(8,("packed printer [%s] with driver [%s] portname=[%s] len=%d\n",
		 info->sharename, info->drivername, info->portname, len));

done:

	SAFE_FREE(buf);

	return result;
}

static struct printerdb_methods file_methods = {

	file_get_last_update,
	file_set_last_update,
	file_printerdb_init,
	file_get_c_setprinter, 
	file_update_c_setprinter, 
	file_get_forms, 
	file_write_forms,
	file_del_form,
	file_get_drivers,
	file_add_driver,
	file_get_driver,
	file_del_driver,
	file_del_driver_init,
	file_get_printer,
	file_update_printer,
	file_del_printer,
	file_get_secdesc,
	file_set_secdesc /*
	file_printerdb_close,
+       db_set_driver_init_2,
+       db_update_driver_init_2, */
};


NTSTATUS printerdb_file_init(void)
{
	return smb_register_printerdb(SMB_PRINTERDB_INTERFACE_VERSION, "file", &file_methods);
}
