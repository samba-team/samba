#define OLD_NTDOMAIN 1
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
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

extern int DEBUGLEVEL;
extern pstring global_myname;
extern DOM_SID global_sid_World; 

static TDB_CONTEXT *tdb; /* used for driver files */

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define PRINTERS_PREFIX "PRINTERS/"

#define DATABASE_VERSION 1

/* We need one default form to support our default printer. Msoft adds the
forms it wants and in the ORDER it wants them (note: DEVMODE papersize is an
array index). Letter is always first, so (for the current code) additions
always put things in the correct order. */
static nt_forms_struct default_forms[] = {
	{"Letter", 0x2, 0x34b5b, 0x44367, 0x0, 0x0, 0x34b5b, 0x44367},
};


/****************************************************************************
open the NT printing tdb
****************************************************************************/
BOOL nt_printing_init(void)
{
	static pid_t local_pid;
	char *vstring = "INFO/version";

	if (tdb && local_pid == sys_getpid()) return True;
	tdb = tdb_open(lock_path("ntdrivers.tdb"), 0, 0, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open nt drivers database\n"));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring);
	if (tdb_fetch_int(tdb, vstring) != DATABASE_VERSION) {
		tdb_traverse(tdb, (tdb_traverse_func)tdb_delete, NULL);
		tdb_store_int(tdb, vstring, DATABASE_VERSION);
	}
	tdb_unlock_bystring(tdb, vstring);

	return True;
}

  
/****************************************************************************
get a form struct list
****************************************************************************/
int get_ntforms(nt_forms_struct **list)
{
	TDB_DATA kbuf, newkey, dbuf;
	nt_forms_struct form;
	int ret;
	int i;
	int n = 0;

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr) continue;

		fstrcpy(form.name, kbuf.dptr+strlen(FORMS_PREFIX));
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "dddddddd",
				 &i, &form.flag, &form.width, &form.length, &form.left,
				 &form.top, &form.right, &form.bottom);
		safe_free(dbuf.dptr);
		if (ret != dbuf.dsize) continue;

		/* allocate space and populate the list in correct order */
		if (i+1 > n) {
			*list = Realloc(*list, sizeof(nt_forms_struct)*(i+1));
			n = i+1;
		}
		(*list)[i] = form;
	}

	/* we should never return a null forms list or NT gets unhappy */
	if (n == 0) {
		*list = (nt_forms_struct *)memdup(&default_forms[0], sizeof(default_forms));
		n = sizeof(default_forms) / sizeof(default_forms[0]);
	}
	

	return n;
}

/****************************************************************************
write a form struct list
****************************************************************************/
int write_ntforms(nt_forms_struct **list, int number)
{
	pstring buf, key;
	int len;
	TDB_DATA kbuf,dbuf;
	int i;

	for (i=0;i<number;i++) {
		/* save index, so list is rebuilt in correct order */
		len = tdb_pack(buf, sizeof(buf), "dddddddd",
			       i, (*list)[i].flag, (*list)[i].width, (*list)[i].length,
			       (*list)[i].left, (*list)[i].top, (*list)[i].right, 
			       (*list)[i].bottom);
		if (len > sizeof(buf)) break;
		slprintf(key, sizeof(key), "%s%s", FORMS_PREFIX, (*list)[i].name);
		kbuf.dsize = strlen(key)+1;
		kbuf.dptr = key;
		dbuf.dsize = len;
		dbuf.dptr = buf;
		if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) break;
       }

       return i;
}

/****************************************************************************
add a form struct at the end of the list
****************************************************************************/
BOOL add_a_form(nt_forms_struct **list, const FORM *form, int *count)
{
	int n=0;
	BOOL update;
	fstring form_name;

	/* 
	 * NT tries to add forms even when 
	 * they are already in the base
	 * only update the values if already present
	 */

	update=False;
	
	unistr2_to_ascii(form_name, &form->name, sizeof(form_name)-1);
	for (n=0; n<*count && update==False; n++)
	{
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
		{
			DEBUG(103, ("NT workaround, [%s] already exists\n", form_name));
			update=True;
		}
	}

	if (update==False)
	{
		if((*list=Realloc(*list, (n+1)*sizeof(nt_forms_struct))) == NULL)
			return False;
		unistr2_to_ascii((*list)[n].name, &form->name, sizeof((*list)[n].name)-1);
		(*count)++;
	}
	
	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;

	return True;
}

/****************************************************************************
 delete a named form struct 
****************************************************************************/
BOOL delete_a_form(nt_forms_struct **list, UNISTR2 *del_name, int *count, uint32 *ret)
{
	pstring key;
	TDB_DATA kbuf;
	int n=0;
	fstring form_name;

	*ret = 0;

	if (*count == 1) {
		/*
		 * Don't delete the last form (no empty lists).
		 * CHECKME ! Is this correct ? JRA.
		 */
		*ret = ERROR_INVALID_PARAMETER;
		return False;
	}

	unistr2_to_ascii(form_name, del_name, sizeof(form_name)-1);

	for (n=0; n<*count; n++) {
		if (!strncmp((*list)[n].name, form_name, strlen(form_name))) {
			DEBUG(103, ("delete_a_form, [%s] in list\n", form_name));
			break;
		}
	}

	if (n == *count) {
		DEBUG(10,("delete_a_form, [%s] not found\n", form_name));
		*ret = ERROR_INVALID_PARAMETER;
		return False;
	}

	slprintf(key, sizeof(key), "%s%s", FORMS_PREFIX, (*list)[n].name);
	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;
	if (tdb_delete(tdb, kbuf) != 0) {
		*ret = ERROR_NOT_ENOUGH_MEMORY;
		return False;
	}

	return True;
}

/****************************************************************************
update a form struct 
****************************************************************************/
void update_a_form(nt_forms_struct **list, const FORM *form, int count)
{
	int n=0;
	fstring form_name;
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);

	DEBUG(106, ("[%s]\n", form_name));
	for (n=0; n<count; n++)
	{
		DEBUGADD(106, ("n [%d]:[%s]\n", n, (*list)[n].name));
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
			break;
	}

	if (n==count) return;

	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;
}
 
/****************************************************************************
get the nt drivers list

traverse the database and look-up the matching names
****************************************************************************/
int get_ntdrivers(fstring **list, char *architecture, uint32 version)
{
	int total=0;
	fstring short_archi;
	pstring key;
	TDB_DATA kbuf, newkey;

	get_short_archi(short_archi, architecture);
	slprintf(key, sizeof(key), "%s%s/%d/", DRIVERS_PREFIX, short_archi, version);

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, key, strlen(key)) != 0) continue;
		
		if((*list = Realloc(*list, sizeof(fstring)*(total+1))) == NULL)
			return -1;

		fstrcpy((*list)[total], kbuf.dptr+strlen(key));
		total++;
	}

	return(total);
}

/****************************************************************************
function to do the mapping between the long architecture name and
the short one.
****************************************************************************/
BOOL get_short_archi(char *short_archi, char *long_archi)
{
	struct table {
		char *long_archi;
		char *short_archi;
	};
	
	struct table archi_table[]=
	{
		{"Windows 4.0",          "WIN40"    },
		{"Windows NT x86",       "W32X86"   },
		{"Windows NT R4000",     "W32MIPS"  },
		{"Windows NT Alpha_AXP", "W32ALPHA" },
		{"Windows NT PowerPC",   "W32PPC"   },
		{NULL,                   ""         }
	};
	
	int i=-1;

	DEBUG(107,("Getting architecture dependant directory\n"));
	do {
		i++;
	} while ( (archi_table[i].long_archi!=NULL ) && 
	          StrCaseCmp(long_archi, archi_table[i].long_archi) );

	if (archi_table[i].long_archi==NULL) {
		DEBUGADD(107,("Unknown architecture [%s] !\n", long_archi));
		return FALSE;
	}

	StrnCpy (short_archi, archi_table[i].short_archi, strlen(archi_table[i].short_archi));

	DEBUGADD(108,("index: [%d]\n", i));
	DEBUGADD(108,("long architecture: [%s]\n", long_archi));
	DEBUGADD(108,("short architecture: [%s]\n", short_archi));
	
	return TRUE;
}

/****************************************************************************
Determine the correct cVersion associated with an architecture and driver
****************************************************************************/
static uint32 get_correct_cversion(fstring architecture, fstring driverpath_in)
{
	int  fd = -1;
	int  service;
	int  cversion;
	ssize_t  byte_count;
	char buf[PE_HEADER_SIZE];
	pstring driverpath;

	/* If architecture is Windows 95/98, the version is always 0. */
	if (strcmp(architecture, "WIN40") == 0) {
		DEBUG(10,("get_correct_cversion: Driver is Win9x, cversion = 0\n"));
		return 0;
	}
	
	/* Open the driver file (Portable Executable format) and determine the
	 * deriver the cversion.
	 */
	if ((service = find_service("print$")) == -1) {
		DEBUG(3,("get_correct_cversion: Can't find print$ service\n"));
		goto error_exit;
	}

	slprintf(driverpath, sizeof(driverpath), "%s/%s/%s",
			 lp_pathname(service), architecture, driverpath_in);

	dos_to_unix(driverpath, True);

	if ((fd = sys_open(driverpath, O_RDONLY, 0)) == -1) {
		DEBUG(3,("get_correct_cversion: Can't open file [%s], errno = %d\n",
				driverpath, errno));
		goto error_exit;
	}
	 
	if ((byte_count = read(fd, buf, DOS_HEADER_SIZE)) < DOS_HEADER_SIZE) {
		DEBUG(3,("get_correct_cversion: File [%s] DOS header too short, bytes read = %d\n",
				driverpath, byte_count));
		goto error_exit;
	}

	/* Is this really a DOS header? */
	if (SVAL(buf,DOS_HEADER_MAGIC_OFFSET) != DOS_HEADER_MAGIC) {
		DEBUG(6,("get_correct_cversion: File [%s] bad DOS magic = 0x%x\n",
				driverpath, SVAL(buf,DOS_HEADER_MAGIC_OFFSET)));
		goto error_exit;
	}

	/* Skip OEM header (if any) and the DOS stub to start of Windows header */
	if (sys_lseek(fd, SVAL(buf,DOS_HEADER_LFANEW_OFFSET), SEEK_SET) == (SMB_OFF_T)-1) {
		DEBUG(3,("get_correct_cversion: File [%s] too short, errno = %d\n",
				driverpath, errno));
		goto error_exit;
	}

	if ((byte_count = read(fd, buf, PE_HEADER_SIZE)) < PE_HEADER_SIZE) {
		DEBUG(3,("get_correct_cversion: File [%s] Windows header too short, bytes read = %d\n",
				driverpath, byte_count));
		goto error_exit;
	}
	close(fd);

	/* The header may be a PE (Portable Executable) or an NE (New Executable) */
	if (IVAL(buf,PE_HEADER_SIGNATURE_OFFSET) == PE_HEADER_SIGNATURE) {
		if (SVAL(buf,PE_HEADER_MACHINE_OFFSET) == PE_HEADER_MACHINE_I386) {

			switch (SVAL(buf,PE_HEADER_MAJOR_OS_VER_OFFSET)) {
				case 4: cversion = 2; break;	/* Win NT 4 */
				case 5: cversion = 3; break;	/* Win 2000 */
				default:
					DEBUG(6,("get_correct_cversion: PE formated file [%s] bad version = %d\n",
							driverpath, SVAL(buf,PE_HEADER_MAJOR_OS_VER_OFFSET)));
					goto error_exit;
			}
		} else {
			DEBUG(6,("get_correct_cversion: PE formatted file [%s] wrong machine = 0x%x\n",
					driverpath, SVAL(buf,PE_HEADER_MACHINE_OFFSET)));
			goto error_exit;
		}

	} else if (SVAL(buf,NE_HEADER_SIGNATURE_OFFSET) == NE_HEADER_SIGNATURE) {
		if (CVAL(buf,NE_HEADER_TARGET_OS_OFFSET) == NE_HEADER_TARGOS_WIN ) {

			switch (CVAL(buf,NE_HEADER_MAJOR_VER_OFFSET)) {
				case 3: cversion = 0; break;	/* Win 3.x / Win 9x / Win ME */
			/*	case ?: cversion = 1; break;*/ 	/* Win NT 3.51 ... needs research JRR */
				default:
					DEBUG(6,("get_correct_cversion: NE formated file [%s] bad version = %d\n",
							driverpath, CVAL(buf,NE_HEADER_MAJOR_VER_OFFSET)));
					goto error_exit;
			}
		} else {
			DEBUG(6,("get_correct_cversion: NE formatted file [%s] wrong target OS = 0x%x\n",
					driverpath, CVAL(buf,NE_HEADER_TARGET_OS_OFFSET)));
			goto error_exit;
		}

	} else {
		DEBUG(6,("get_correct_cversion: Unknown file format [%s], signature = 0x%x\n",
				driverpath, IVAL(buf,PE_HEADER_SIGNATURE_OFFSET)));
		goto error_exit;
	}

	DEBUG(10,("get_correct_cversion: Driver file [%s] cversion = %d\n",
			driverpath, cversion));
	return cversion;


	error_exit:
		if(fd != -1)
			close(fd);
		return -1;
}

/****************************************************************************
****************************************************************************/
static uint32 clean_up_driver_struct_level_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	fstring architecture;
	fstring new_name;
	char *p;
	int i;

	/* clean up the driver name.
	 * we can get .\driver.dll
	 * or worse c:\windows\system\driver.dll !
	 */
	/* using an intermediate string to not have overlaping memcpy()'s */
	if ((p = strrchr(driver->driverpath,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->driverpath, new_name);
	}

	if ((p = strrchr(driver->datafile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->datafile, new_name);
	}

	if ((p = strrchr(driver->configfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->configfile, new_name);
	}

	if ((p = strrchr(driver->helpfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->helpfile, new_name);
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if ((p = strrchr(driver->dependentfiles[i],'\\')) != NULL) {
				fstrcpy(new_name, p+1);
				fstrcpy(driver->dependentfiles[i], new_name);
			}
		}
	}

	get_short_archi(architecture, driver->environment);
	
	/* jfm:7/16/2000 the client always sends the cversion=0.
	 * The server should check which version the driver is by reading
	 * the PE header of driver->driverpath.
	 *
	 * For Windows 95/98 the version is 0 (so the value sent is correct)
	 * For Windows NT (the architecture doesn't matter)
	 *	NT 3.1: cversion=0
	 *	NT 3.5/3.51: cversion=1
	 *	NT 4: cversion=2
	 *	NT2K: cversion=3
	 */
	if ((driver->cversion = get_correct_cversion(architecture,
											driver->driverpath)) == -1)
		return NT_STATUS_FILE_INVALID;     /* Not the best error. Fix JRR */

	return NT_STATUS_NO_PROBLEMO;
}
	 
/****************************************************************************
****************************************************************************/
static uint32 clean_up_driver_struct_level_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	fstring architecture;
	fstring new_name;
	char *p;
	int i;

	/* clean up the driver name.
	 * we can get .\driver.dll
	 * or worse c:\windows\system\driver.dll !
	 */
	/* using an intermediate string to not have overlaping memcpy()'s */
	if ((p = strrchr(driver->driverpath,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->driverpath, new_name);
	}

	if ((p = strrchr(driver->datafile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->datafile, new_name);
	}

	if ((p = strrchr(driver->configfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->configfile, new_name);
	}

	if ((p = strrchr(driver->helpfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->helpfile, new_name);
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if ((p = strrchr(driver->dependentfiles[i],'\\')) != NULL) {
				fstrcpy(new_name, p+1);
				fstrcpy(driver->dependentfiles[i], new_name);
			}
		}
	}

	get_short_archi(architecture, driver->environment);

	/* jfm:7/16/2000 the client always sends the cversion=0.
	 * The server should check which version the driver is by reading
	 * the PE header of driver->driverpath.
	 *
	 * For Windows 95/98 the version is 0 (so the value sent is correct)
	 * For Windows NT (the architecture doesn't matter)
	 *	NT 3.1: cversion=0
	 *	NT 3.5/3.51: cversion=1
	 *	NT 4: cversion=2
	 *	NT2K: cversion=3
	 */
	if ((driver->version = get_correct_cversion(architecture,
											driver->driverpath)) == -1)
		return NT_STATUS_FILE_INVALID;     /* Not the best error. Fix JRR */

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 clean_up_driver_struct(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract, uint32 level)
{
	switch (level) {
		case 3:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver;
			driver=driver_abstract.info_3;
			return clean_up_driver_struct_level_3(driver);
			break;
		}
		case 6:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver;
			driver=driver_abstract.info_6;
			return clean_up_driver_struct_level_6(driver);
			break;
		}
		default:
			return ERROR_INVALID_PARAMETER;
	}
}

/****************************************************************************
 This function sucks and should be replaced. JRA.
****************************************************************************/

static void convert_level_6_to_level3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *dst, NT_PRINTER_DRIVER_INFO_LEVEL_6 *src)
{
    dst->cversion  = src->version;

    fstrcpy( dst->name, src->name);
    fstrcpy( dst->environment, src->environment);
    fstrcpy( dst->driverpath, src->driverpath);
    fstrcpy( dst->datafile, src->datafile);
    fstrcpy( dst->configfile, src->configfile);
    fstrcpy( dst->helpfile, src->helpfile);
    fstrcpy( dst->monitorname, src->monitorname);
    fstrcpy( dst->defaultdatatype, src->defaultdatatype);
    dst->dependentfiles = src->dependentfiles;
}


/****************************************************************************
****************************************************************************/
BOOL move_driver_to_download_area(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract, uint32 level, struct current_user *user, uint32 *perr)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 converted_driver;
	fstring architecture;
	pstring new_dir;
	pstring old_name;
	pstring new_name;
	fstring user_name;
	fstring null_pw;
	connection_struct *conn;
	pstring inbuf;
	pstring outbuf;
	struct smb_passwd *smb_pass;
	int ecode;
	int outsize = 0;
	int i;

	*perr = 0;
	memset(inbuf, '\0', sizeof(inbuf));
	memset(outbuf, '\0', sizeof(outbuf));

	if (level==3)
		driver=driver_abstract.info_3;
	else if (level==6) {
		convert_level_6_to_level3(&converted_driver, driver_abstract.info_6);
		driver = &converted_driver;
	} else {
		DEBUG(0,("move_driver_to_download_area: Unknown info level (%u)\n", (unsigned int)level ));
		return False;
	}

	get_short_archi(architecture, driver->environment);

	become_root();
	smb_pass = getsmbpwuid(user->uid);
	if(smb_pass == NULL) {
		DEBUG(0,("move_driver_to_download_area: Unable to get smbpasswd entry for uid %u\n",
				(unsigned int)user->uid ));
		unbecome_root();
		return False;
	}
	unbecome_root();

	/* connect to the print$ share under the same account as the user connected to the rpc pipe */	
	fstrcpy(user_name, smb_pass->smb_name );
	DEBUG(10,("move_driver_to_download_area: uid %d -> user %s\n", (int)user->uid, user_name));

	/* Null password is ok - we are already an authenticated user... */
	*null_pw = '\0';
	conn = make_connection("print$", user_name, null_pw, 0, "A:", user->vuid, &ecode);

	if (conn == NULL) {
		DEBUG(0,("move_driver_to_download_area: Unable to connect\n"));
		*perr = (uint32)ecode;
		return False;
	}

	/*
	 * Save who we are - we are temporarily becoming the connection user.
	 */

	push_sec_ctx();

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("move_driver_to_download_area: Can't become user %s\n", user_name ));
		pop_sec_ctx();
		return False;
	}

	/* 
	 * make the directories version and version\driver_name 
	 * under the architecture directory.
	 */
	DEBUG(5,("Creating first directory\n"));
	slprintf(new_dir, sizeof(new_dir), "%s\\%d", architecture, driver->cversion);
	mkdir_internal(conn, inbuf, outbuf, new_dir);

	/* move all the files, one by one, 
	 * from archi\filexxx.yyy to
	 * archi\version\filexxx.yyy
	 *
	 * Note: drivers may list the same file name in several places. This
	 * causes problems on a second attempt to move the file. JRR
	 *
	 * Note: use the replace flag on rename_internals() call, otherwise it
	 * is very difficult to change previously installed drivers... the Windows
	 * GUI offers the user the choice to replace or keep exisitng driver. JRR
	 */

	DEBUG(5,("Moving file now !\n"));

	if (driver->driverpath && strlen(driver->driverpath)) {
	slprintf(old_name, sizeof(old_name), "%s\\%s", architecture, driver->driverpath);	
	slprintf(new_name, sizeof(new_name), "%s\\%s", new_dir, driver->driverpath);	
	if ((outsize = rename_internals(conn, inbuf, outbuf, old_name, new_name, True)) != 0) {
		DEBUG(0,("move_driver_to_download_area: Unable to rename %s to %s\n",
				old_name, new_name ));
		close_cnum(conn, user->vuid);
		pop_sec_ctx();
		*perr = (uint32)SVAL(outbuf,smb_err);
		return False;
	}
	}

	if (driver->datafile && strlen(driver->datafile)) {
	if (!strequal(driver->datafile, driver->driverpath)) {
		slprintf(old_name, sizeof(old_name), "%s\\%s", architecture, driver->datafile);	
		slprintf(new_name, sizeof(new_name), "%s\\%s", new_dir, driver->datafile);	
		if ((outsize = rename_internals(conn, inbuf, outbuf, old_name, new_name, True)) != 0) {
			DEBUG(0,("move_driver_to_download_area: Unable to rename %s to %s\n",
					old_name, new_name ));
			close_cnum(conn, user->vuid);
			pop_sec_ctx();
			*perr = (uint32)SVAL(outbuf,smb_err);
			return False;
		}
	}
	}

	if (driver->configfile && strlen(driver->configfile)) {
	if (!strequal(driver->configfile, driver->driverpath) &&
		!strequal(driver->configfile, driver->datafile)) {
		slprintf(old_name, sizeof(old_name), "%s\\%s", architecture, driver->configfile);	
		slprintf(new_name, sizeof(new_name), "%s\\%s", new_dir, driver->configfile);	
		if ((outsize = rename_internals(conn, inbuf, outbuf, old_name, new_name, True)) != 0) {
			DEBUG(0,("move_driver_to_download_area: Unable to rename %s to %s\n",
				old_name, new_name ));
			close_cnum(conn, user->vuid);
			pop_sec_ctx();
			*perr = (uint32)SVAL(outbuf,smb_err);
			return False;
		}
	}
	}

	if (driver->helpfile && strlen(driver->helpfile)) {
	if (!strequal(driver->helpfile, driver->driverpath) &&
			!strequal(driver->helpfile, driver->datafile) &&
			!strequal(driver->helpfile, driver->configfile)) {
		slprintf(old_name, sizeof(old_name), "%s\\%s", architecture, driver->helpfile);	
		slprintf(new_name, sizeof(new_name), "%s\\%s", new_dir, driver->helpfile);	
		if ((outsize = rename_internals(conn, inbuf, outbuf, old_name, new_name, True)) != 0) {
			DEBUG(0,("move_driver_to_download_area: Unable to rename %s to %s\n",
				old_name, new_name ));
			close_cnum(conn, user->vuid);
			pop_sec_ctx();
			*perr = (uint32)SVAL(outbuf,smb_err);
			return False;
		}
	}
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if (!strequal(driver->dependentfiles[i], driver->driverpath) &&
					!strequal(driver->dependentfiles[i], driver->datafile) &&
					!strequal(driver->dependentfiles[i], driver->configfile) &&
					!strequal(driver->dependentfiles[i], driver->helpfile)) {
				int j;
				for (j=0; j < i; j++) {
					if (strequal(driver->dependentfiles[i], driver->dependentfiles[j])) {
						goto NextDriver;
					}
				}

				slprintf(old_name, sizeof(old_name), "%s\\%s", architecture, driver->dependentfiles[i]);	
				slprintf(new_name, sizeof(new_name), "%s\\%s", new_dir, driver->dependentfiles[i]);	
				if ((outsize = rename_internals(conn, inbuf, outbuf, old_name, new_name, True)) != 0) {
					DEBUG(0,("move_driver_to_download_area: Unable to rename %s to %s\n",
						old_name, new_name ));
					close_cnum(conn, user->vuid);
					pop_sec_ctx();
					*perr = (uint32)SVAL(outbuf,smb_err);
					return False;
				}
			}
		NextDriver: ;
		}
	}

	close_cnum(conn, user->vuid);
	pop_sec_ctx();

	return True;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	int len, buflen;
	fstring architecture;
	pstring directory;
	pstring temp_name;
	pstring key;
	char *buf;
	int i, ret;
	TDB_DATA kbuf, dbuf;

	get_short_archi(architecture, driver->environment);

	/* The names are relative. We store them in the form: \print$\arch\version\driver.xxx
	 * \\server is added in the rpc server layer.
	 * It does make sense to NOT store the server's name in the printer TDB.
	 */

	slprintf(directory, sizeof(directory), "\\print$\\%s\\%d\\", architecture, driver->cversion);

	
	fstrcpy(temp_name, driver->driverpath);
	slprintf(driver->driverpath, sizeof(driver->driverpath), "%s%s", directory, temp_name);

	fstrcpy(temp_name, driver->datafile);
	slprintf(driver->datafile, sizeof(driver->datafile), "%s%s", directory, temp_name);

	fstrcpy(temp_name, driver->configfile);
	slprintf(driver->configfile, sizeof(driver->configfile), "%s%s", directory, temp_name);

	fstrcpy(temp_name, driver->helpfile);
	slprintf(driver->helpfile, sizeof(driver->helpfile), "%s%s", directory, temp_name);

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			fstrcpy(temp_name, driver->dependentfiles[i]);
			slprintf(driver->dependentfiles[i], sizeof(driver->dependentfiles[i]), "%s%s", directory, temp_name);
		}
	}

	slprintf(key, sizeof(key), "%s%s/%d/%s", DRIVERS_PREFIX, architecture, driver->cversion, driver->name);

	DEBUG(5,("add_a_printer_driver_3: Adding driver with key %s\n", key ));

	buf = NULL;
	len = buflen = 0;

 again:
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dffffffff", 
			driver->cversion,
			driver->name,
			driver->environment,
			driver->driverpath,
			driver->datafile,
			driver->configfile,
			driver->helpfile,
			driver->monitorname,
			driver->defaultdatatype);

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			len += tdb_pack(buf+len, buflen-len, "f", 
					driver->dependentfiles[i]);
		}
	}

	if (len != buflen) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}


	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;
	
	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	if (ret)
		DEBUG(0,("add_a_printer_driver_3: Adding driver with key %s failed.\n", key ));

	safe_free(buf);
	return ret;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info3;

	ZERO_STRUCT(info3);
	info3.cversion = driver->version;
	fstrcpy(info3.name,driver->name);
	fstrcpy(info3.environment,driver->environment);
	fstrcpy(info3.driverpath,driver->driverpath);
	fstrcpy(info3.datafile,driver->datafile);
	fstrcpy(info3.configfile,driver->configfile);
	fstrcpy(info3.helpfile,driver->helpfile);
	fstrcpy(info3.monitorname,driver->monitorname);
	fstrcpy(info3.defaultdatatype,driver->defaultdatatype);
	info3.dependentfiles = driver->dependentfiles;

	return add_a_printer_driver_3(&info3);
}


/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3_default(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info;

	ZERO_STRUCT(info);

	fstrcpy(info.name, in_prt);
	fstrcpy(info.defaultdatatype, "RAW");
	
	fstrcpy(info.driverpath, "");
	fstrcpy(info.datafile, "");
	fstrcpy(info.configfile, "");
	fstrcpy(info.helpfile, "");

	if ((info.dependentfiles=(fstring *)malloc(2*sizeof(fstring))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	memset(info.dependentfiles, '\0', 2*sizeof(fstring));
	fstrcpy(info.dependentfiles[0], "");

	*info_ptr = memdup(&info, sizeof(info));
	
	return 0;	
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch, uint32 version)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 driver;
	TDB_DATA kbuf, dbuf;
	fstring architecture;
	int len = 0;
	int i;
	pstring key;

	ZERO_STRUCT(driver);

	get_short_archi(architecture, in_arch);

	DEBUG(8,("get_a_printer_driver_3: [%s%s/%d/%s]\n", DRIVERS_PREFIX, architecture, version, in_prt));

	slprintf(key, sizeof(key), "%s%s/%d/%s", DRIVERS_PREFIX, architecture, version, in_prt);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	
	dbuf = tdb_fetch(tdb, kbuf);
#if 0
	if (!dbuf.dptr) return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);
#else
	if (!dbuf.dptr) return 5;
#endif
	len += tdb_unpack(dbuf.dptr, dbuf.dsize, "dffffffff", 
			  &driver.cversion,
			  driver.name,
			  driver.environment,
			  driver.driverpath,
			  driver.datafile,
			  driver.configfile,
			  driver.helpfile,
			  driver.monitorname,
			  driver.defaultdatatype);

	i=0;
	while (len < dbuf.dsize) {
		driver.dependentfiles = (fstring *)Realloc(driver.dependentfiles,
							 sizeof(fstring)*(i+2));
		if (driver.dependentfiles == NULL)
			break;

		len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "f", 
				  &driver.dependentfiles[i]);
		i++;
	}
	if (driver.dependentfiles != NULL)
		fstrcpy(driver.dependentfiles[i], "");

	safe_free(dbuf.dptr);

	if (len != dbuf.dsize) {
		if (driver.dependentfiles != NULL)
			safe_free(driver.dependentfiles);

		return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);
	}

	*info_ptr = (NT_PRINTER_DRIVER_INFO_LEVEL_3 *)memdup(&driver, sizeof(driver));

	return 0;
}

/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver_9x_compatible(pstring line, fstring model)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	TDB_DATA kbuf;
	pstring key;
	int i;
	line[0] = '\0';

	slprintf(key, sizeof(key), "%s%s/%d/%s", DRIVERS_PREFIX, "WIN40", 0, model);
	DEBUG(10,("driver key: [%s]\n", key));
	
	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	if (!tdb_exists(tdb, kbuf)) return False;

	ZERO_STRUCT(info3);
	get_a_printer_driver_3(&info3, model, "Windows 4.0", 0);
	
    DEBUGADD(10,("info3->name            [%s]\n", info3->name));
    DEBUGADD(10,("info3->datafile        [%s]\n", info3->datafile));
    DEBUGADD(10,("info3->helpfile        [%s]\n", info3->helpfile));
    DEBUGADD(10,("info3->monitorname     [%s]\n", info3->monitorname));
    DEBUGADD(10,("info3->defaultdatatype [%s]\n", info3->defaultdatatype));
	for (i=0; info3->dependentfiles && *info3->dependentfiles[i]; i++) {
    DEBUGADD(10,("info3->dependentfiles  [%s]\n", info3->dependentfiles[i]));
    }
    DEBUGADD(10,("info3->environment     [%s]\n", info3->environment));
    DEBUGADD(10,("info3->driverpath      [%s]\n", info3->driverpath));
    DEBUGADD(10,("info3->configfile      [%s]\n", info3->configfile));

	/*pstrcat(line, info3->name);             pstrcat(line, ":");*/
	trim_string(info3->configfile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->configfile);
    pstrcat(line, ":");
	trim_string(info3->datafile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->datafile);
    pstrcat(line, ":");
	trim_string(info3->helpfile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->helpfile);
    pstrcat(line, ":");
	trim_string(info3->monitorname, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->monitorname);
    pstrcat(line, ":");
	pstrcat(line, "RAW");                /*info3->defaultdatatype);*/
    pstrcat(line, ":");

	for (i=0; info3->dependentfiles &&
		 *info3->dependentfiles[i]; i++) {
		if (i) pstrcat(line, ",");               /* don't end in a "," */
		trim_string(info3->dependentfiles[i], "\\print$\\WIN40\\0\\", 0);
		pstrcat(line, info3->dependentfiles[i]);
	}
	
	free(info3);

	return True;	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	int i;
	
	DEBUG(106,("Dumping printer driver at level [%d]\n", level));
	
	switch (level)
	{
		case 3: 
		{
			if (driver.info_3 == NULL)
				success=5;
			else {
				info3=driver.info_3;
			
				DEBUGADD(106,("version:[%d]\n",         info3->cversion));
				DEBUGADD(106,("name:[%s]\n",            info3->name));
				DEBUGADD(106,("environment:[%s]\n",     info3->environment));
				DEBUGADD(106,("driverpath:[%s]\n",      info3->driverpath));
				DEBUGADD(106,("datafile:[%s]\n",        info3->datafile));
				DEBUGADD(106,("configfile:[%s]\n",      info3->configfile));
				DEBUGADD(106,("helpfile:[%s]\n",        info3->helpfile));
				DEBUGADD(106,("monitorname:[%s]\n",     info3->monitorname));
				DEBUGADD(106,("defaultdatatype:[%s]\n", info3->defaultdatatype));
				
				for (i=0; info3->dependentfiles &&
					  *info3->dependentfiles[i]; i++) {
					DEBUGADD(106,("dependentfile:[%s]\n", 
						      info3->dependentfiles[i]));
				}
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
****************************************************************************/
static int pack_devicemode(NT_DEVICEMODE *nt_devmode, char *buf, int buflen)
{
	int len = 0;

	len += tdb_pack(buf+len, buflen-len, "p", nt_devmode);

	if (!nt_devmode) return len;

	len += tdb_pack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			nt_devmode->devicename,
			nt_devmode->formname,

			nt_devmode->specversion,
			nt_devmode->driverversion,
			nt_devmode->size,
			nt_devmode->driverextra,
			nt_devmode->orientation,
			nt_devmode->papersize,
			nt_devmode->paperlength,
			nt_devmode->paperwidth,
			nt_devmode->scale,
			nt_devmode->copies,
			nt_devmode->defaultsource,
			nt_devmode->printquality,
			nt_devmode->color,
			nt_devmode->duplex,
			nt_devmode->yresolution,
			nt_devmode->ttoption,
			nt_devmode->collate,
			nt_devmode->logpixels,
			
			nt_devmode->fields,
			nt_devmode->bitsperpel,
			nt_devmode->pelswidth,
			nt_devmode->pelsheight,
			nt_devmode->displayflags,
			nt_devmode->displayfrequency,
			nt_devmode->icmmethod,
			nt_devmode->icmintent,
			nt_devmode->mediatype,
			nt_devmode->dithertype,
			nt_devmode->reserved1,
			nt_devmode->reserved2,
			nt_devmode->panningwidth,
			nt_devmode->panningheight,
			nt_devmode->private);

	
	if (nt_devmode->private) {
		len += tdb_pack(buf+len, buflen-len, "B",
				nt_devmode->driverextra,
				nt_devmode->private);
	}

	DEBUG(8,("Packed devicemode [%s]\n", nt_devmode->formname));

	return len;
}

/****************************************************************************
****************************************************************************/
static int pack_specifics(NT_PRINTER_PARAM *param, char *buf, int buflen)
{
	int len = 0;

	while (param != NULL) {
		len += tdb_pack(buf+len, buflen-len, "pfdB",
				param,
				param->value, 
				param->type, 
				param->data_len,
				param->data);
		param=param->next;	
	}

	len += tdb_pack(buf+len, buflen-len, "p", param);

	return len;
}


/****************************************************************************
delete a printer - this just deletes the printer info file, any open
handles are not affected
****************************************************************************/
uint32 del_a_printer(char *sharename)
{
	pstring key;
	TDB_DATA kbuf;

	slprintf(key, sizeof(key), "%s%s",
		 PRINTERS_PREFIX, sharename);

	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;

	tdb_delete(tdb, kbuf);
	return 0;
}

/****************************************************************************
****************************************************************************/
static uint32 update_a_printer_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len, ret;
	TDB_DATA kbuf, dbuf;
	
	/* 
	 * in addprinter: no servername and the printer is the name
	 * in setprinter: servername is \\server
	 *                and printer is \\server\\printer
	 *
	 * Samba manages only local printers.
	 * we currently don't support things like path=\\other_server\printer
	 */

	if (info->servername[0]!='\0') {
		trim_string(info->printername, info->servername, NULL);
		trim_string(info->printername, "\\", NULL);
		info->servername[0]='\0';
	}

	/*
	 * JFM: one day I'll forget.
	 * below that's info->portname because that's the SAMBA sharename
	 * and I made NT 'thinks' it's the portname
	 * the info->sharename is the thing you can name when you add a printer
	 * that's the short-name when you create shared printer for 95/98
	 * So I've made a limitation in SAMBA: you can only have 1 printer model
	 * behind a SAMBA share.
	 */

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
	len += pack_specifics(info->specific, buf+len, buflen-len);

	if (buflen != len) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}
	

	slprintf(key, sizeof(key), "%s%s",
		 PRINTERS_PREFIX, info->sharename);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	if (ret == -1)
		DEBUG(8, ("error updating printer to tdb on disk\n"));

	safe_free(buf);

	DEBUG(8,("packed printer [%s] with driver [%s] portname=[%s] len=%d\n", 
		 info->sharename, info->drivername, info->portname, len));

	return ret;
}


/****************************************************************************
****************************************************************************/
BOOL add_a_specific_param(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	
	DEBUG(108,("add_a_specific_param\n"));	

	param->next=NULL;
	
	if (info_2->specific == NULL)
	{
		info_2->specific=param;
	}
	else
	{
		current=info_2->specific;		
		while (current->next != NULL) {
			current=current->next;
		}		
		current->next=param;
	}
	return (True);
}

/****************************************************************************
****************************************************************************/
BOOL unlink_specific_param_if_exist(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	NT_PRINTER_PARAM *previous;
	
	current=info_2->specific;
	previous=current;
	
	if (current==NULL) return (False);
	
	if ( !strcmp(current->value, param->value) && 
	    (strlen(current->value)==strlen(param->value)) ) {
		DEBUG(109,("deleting first value\n"));
		info_2->specific=current->next;
		safe_free(current->data);
		safe_free(current);
		DEBUG(109,("deleted first value\n"));
		return (True);
	}

	current=previous->next;
		
	while ( current!=NULL ) {
		if (!strcmp(current->value, param->value) &&
		    strlen(current->value)==strlen(param->value) ) {
			DEBUG(109,("deleting current value\n"));
			previous->next=current->next;
			safe_free(current->data);
			safe_free(current);
			DEBUG(109,("deleted current value\n"));
			return(True);
		}
		
		previous=previous->next;
		current=current->next;
	}
	return (False);
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_PARAM.
****************************************************************************/
static void free_nt_printer_param(NT_PRINTER_PARAM **param_ptr)
{
	NT_PRINTER_PARAM *param = *param_ptr;

	if(param == NULL)
		return;

	DEBUG(106,("free_nt_printer_param: deleting param [%s]\n", param->value));

	if(param->data)
		safe_free(param->data);

	safe_free(param);
	*param_ptr = NULL;
}

/****************************************************************************
 Malloc and return an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *construct_nt_devicemode(const fstring default_devicename)
{
/*
 * should I init this ones ???
	nt_devmode->devicename
*/

	char adevice[32];
	NT_DEVICEMODE *nt_devmode = (NT_DEVICEMODE *)malloc(sizeof(NT_DEVICEMODE));

	if (nt_devmode == NULL) {
		DEBUG(0,("construct_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	ZERO_STRUCTP(nt_devmode);

	snprintf(adevice, sizeof(adevice), "\\\\%s\\%s", global_myname, default_devicename);
	fstrcpy(nt_devmode->devicename, adevice);
	
	
	fstrcpy(nt_devmode->formname, "Letter");

	nt_devmode->specversion      = 0x0401;
	nt_devmode->driverversion    = 0x0400;
	nt_devmode->size             = 0x00DC;
	nt_devmode->driverextra      = 0x0000;
	nt_devmode->fields           = FORMNAME | TTOPTION | PRINTQUALITY | 
				       DEFAULTSOURCE | COPIES | SCALE | 
				       PAPERSIZE | ORIENTATION;
	nt_devmode->orientation      = 1;
	nt_devmode->papersize        = PAPER_LETTER;
	nt_devmode->paperlength      = 0;
	nt_devmode->paperwidth       = 0;
	nt_devmode->scale            = 0x64;
	nt_devmode->copies           = 01;
	nt_devmode->defaultsource    = BIN_FORMSOURCE;
	nt_devmode->printquality     = RES_HIGH;           /* 0x0258 */
	nt_devmode->color            = COLOR_MONOCHROME;
	nt_devmode->duplex           = DUP_SIMPLEX;
	nt_devmode->yresolution      = 0;
	nt_devmode->ttoption         = TT_SUBDEV;
	nt_devmode->collate          = COLLATE_FALSE;
	nt_devmode->icmmethod        = 0;
	nt_devmode->icmintent        = 0;
	nt_devmode->mediatype        = 0;
	nt_devmode->dithertype       = 0;

	/* non utilisés par un driver d'imprimante */
	nt_devmode->logpixels        = 0;
	nt_devmode->bitsperpel       = 0;
	nt_devmode->pelswidth        = 0;
	nt_devmode->pelsheight       = 0;
	nt_devmode->displayflags     = 0;
	nt_devmode->displayfrequency = 0;
	nt_devmode->reserved1        = 0;
	nt_devmode->reserved2        = 0;
	nt_devmode->panningwidth     = 0;
	nt_devmode->panningheight    = 0;
	
	nt_devmode->private=NULL;

	return nt_devmode;
}

/****************************************************************************
 Deepcopy an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *dup_nt_devicemode(NT_DEVICEMODE *nt_devicemode)
{
	NT_DEVICEMODE *new_nt_devicemode = NULL;

	if ((new_nt_devicemode = (NT_DEVICEMODE *)memdup(nt_devicemode, sizeof(NT_DEVICEMODE))) == NULL) {
		DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	new_nt_devicemode->private = NULL;
	if (nt_devicemode->private != NULL) {
		if ((new_nt_devicemode->private = memdup(nt_devicemode->private, nt_devicemode->driverextra)) == NULL) {
			safe_free(new_nt_devicemode);
			DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
			return NULL;
        }
	}

	return new_nt_devicemode;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_DEVICEMODE.
****************************************************************************/

void free_nt_devicemode(NT_DEVICEMODE **devmode_ptr)
{
	NT_DEVICEMODE *nt_devmode = *devmode_ptr;

	if(nt_devmode == NULL)
		return;

	DEBUG(106,("free_nt_devicemode: deleting DEVMODE\n"));

	if(nt_devmode->private)
		safe_free(nt_devmode->private);

	safe_free(nt_devmode);
	*devmode_ptr = NULL;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_INFO_LEVEL_2.
****************************************************************************/
static void free_nt_printer_info_level_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr)
{
	NT_PRINTER_INFO_LEVEL_2 *info = *info_ptr;
	NT_PRINTER_PARAM *param_ptr;

	if(info == NULL)
		return;

	DEBUG(106,("free_nt_printer_info_level_2: deleting info\n"));

	free_nt_devicemode(&info->devmode);
	free_sec_desc_buf(&info->secdesc_buf);

	for(param_ptr = info->specific; param_ptr; ) {
		NT_PRINTER_PARAM *tofree = param_ptr;

		param_ptr = param_ptr->next;
		free_nt_printer_param(&tofree);
	}

	safe_free(*info_ptr);
	*info_ptr = NULL;
}


/****************************************************************************
****************************************************************************/
static int unpack_devicemode(NT_DEVICEMODE **nt_devmode, char *buf, int buflen)
{
	int len = 0;
	int extra_len = 0;
	NT_DEVICEMODE devmode;

	ZERO_STRUCT(devmode);

	len += tdb_unpack(buf+len, buflen-len, "p", nt_devmode);

	if (!*nt_devmode) return len;

	len += tdb_unpack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			  devmode.devicename,
			  devmode.formname,

			  &devmode.specversion,
			  &devmode.driverversion,
			  &devmode.size,
			  &devmode.driverextra,
			  &devmode.orientation,
			  &devmode.papersize,
			  &devmode.paperlength,
			  &devmode.paperwidth,
			  &devmode.scale,
			  &devmode.copies,
			  &devmode.defaultsource,
			  &devmode.printquality,
			  &devmode.color,
			  &devmode.duplex,
			  &devmode.yresolution,
			  &devmode.ttoption,
			  &devmode.collate,
			  &devmode.logpixels,
			  
			  &devmode.fields,
			  &devmode.bitsperpel,
			  &devmode.pelswidth,
			  &devmode.pelsheight,
			  &devmode.displayflags,
			  &devmode.displayfrequency,
			  &devmode.icmmethod,
			  &devmode.icmintent,
			  &devmode.mediatype,
			  &devmode.dithertype,
			  &devmode.reserved1,
			  &devmode.reserved2,
			  &devmode.panningwidth,
			  &devmode.panningheight,
			  &devmode.private);
	
	if (devmode.private) {
		/* the len in tdb_unpack is an int value and
		 * devmoce.driverextra is only a short
		 */
		len += tdb_unpack(buf+len, buflen-len, "B", &extra_len, &devmode.private);
		devmode.driverextra=(uint16)extra_len;
	}

	*nt_devmode = (NT_DEVICEMODE *)memdup(&devmode, sizeof(devmode));

	DEBUG(8,("Unpacked devicemode [%s](%s)\n", devmode.devicename, devmode.formname));
	if (devmode.private)
		DEBUG(8,("with a private section of %d bytes\n", devmode.driverextra));

	return len;
}

/****************************************************************************
****************************************************************************/
static int unpack_specifics(NT_PRINTER_PARAM **list, char *buf, int buflen)
{
	int len = 0;
	NT_PRINTER_PARAM param, *p;

	*list = NULL;

	while (1) {
		len += tdb_unpack(buf+len, buflen-len, "p", &p);
		if (!p) break;

		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  param.value, 
				  &param.type, 
				  &param.data_len,
				  &param.data);
		param.next = *list;
		*list = memdup(&param, sizeof(param));

		DEBUG(8,("specific: [%s], len: %d\n", param.value, param.data_len));
	}

	return len;
}


/****************************************************************************
get a default printer info 2 struct
****************************************************************************/
static uint32 get_a_printer_2_default(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	extern pstring global_myname;
	int snum;
	NT_PRINTER_INFO_LEVEL_2 info;

	ZERO_STRUCT(info);

	snum = lp_servicenumber(sharename);

	fstrcpy(info.servername, global_myname);
	fstrcpy(info.printername, sharename);
	fstrcpy(info.portname, SAMBA_PRINTER_PORT_NAME);
	fstrcpy(info.drivername, lp_printerdriver(snum));
	pstrcpy(info.comment, "");
	fstrcpy(info.printprocessor, "winprint");
	fstrcpy(info.datatype, "RAW");

	info.attributes = PRINTER_ATTRIBUTE_SHARED   \
			 | PRINTER_ATTRIBUTE_LOCAL  \
			 | PRINTER_ATTRIBUTE_RAW_ONLY \
			 | PRINTER_ATTRIBUTE_QUEUED ;            /* attributes */

	info.starttime = 0; /* Minutes since 12:00am GMT */
	info.untiltime = 0; /* Minutes since 12:00am GMT */
	info.priority = 1;
	info.default_priority = 1;
	info.setuptime = (uint32)time(NULL);

	if ((info.devmode = construct_nt_devicemode(info.printername)) == NULL)
		goto fail;

	if (!nt_printing_getsec(sharename, &info.secdesc_buf))
		goto fail;

	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));
	if (! *info_ptr) {
		DEBUG(0,("get_a_printer_2_default: malloc fail.\n"));
		goto fail;
	}

	return (0);	

  fail:

	if (info.devmode)
		free_nt_devicemode(&info.devmode);
	if (info.secdesc_buf)
		free_sec_desc_buf(&info.secdesc_buf);
	return 2;
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	pstring key;
	NT_PRINTER_INFO_LEVEL_2 info;
	int len = 0;
	TDB_DATA kbuf, dbuf;
		
	ZERO_STRUCT(info);

	slprintf(key, sizeof(key), "%s%s", PRINTERS_PREFIX, sharename);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return get_a_printer_2_default(info_ptr, sharename);

	len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "dddddddddddfffffPfffff",
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

	/* Samba has to have shared raw drivers. */
	info.attributes |= (PRINTER_ATTRIBUTE_SHARED|PRINTER_ATTRIBUTE_RAW_ONLY);

	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);
	len += unpack_specifics(&info.specific,dbuf.dptr+len, dbuf.dsize-len);

	nt_printing_getsec(sharename, &info.secdesc_buf);

	safe_free(dbuf.dptr);
	*info_ptr=memdup(&info, sizeof(info));

	DEBUG(9,("Unpacked printer [%s] running driver [%s]\n",
		 sharename, info.drivername));

	
	return 0;	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL_2	*info2;
	
	DEBUG(106,("Dumping printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2: 
		{
			if (printer.info_2 == NULL)
				success=5;
			else
			{
				info2=printer.info_2;
			
				DEBUGADD(106,("attributes:[%d]\n", info2->attributes));
				DEBUGADD(106,("priority:[%d]\n", info2->priority));
				DEBUGADD(106,("default_priority:[%d]\n", info2->default_priority));
				DEBUGADD(106,("starttime:[%d]\n", info2->starttime));
				DEBUGADD(106,("untiltime:[%d]\n", info2->untiltime));
				DEBUGADD(106,("status:[%d]\n", info2->status));
				DEBUGADD(106,("cjobs:[%d]\n", info2->cjobs));
				DEBUGADD(106,("averageppm:[%d]\n", info2->averageppm));
				DEBUGADD(106,("changeid:[%d]\n", info2->changeid));
				DEBUGADD(106,("c_setprinter:[%d]\n", info2->c_setprinter));
				DEBUGADD(106,("setuptime:[%d]\n", info2->setuptime));

				DEBUGADD(106,("servername:[%s]\n", info2->servername));
				DEBUGADD(106,("printername:[%s]\n", info2->printername));
				DEBUGADD(106,("sharename:[%s]\n", info2->sharename));
				DEBUGADD(106,("portname:[%s]\n", info2->portname));
				DEBUGADD(106,("drivername:[%s]\n", info2->drivername));
				DEBUGADD(106,("comment:[%s]\n", info2->comment));
				DEBUGADD(106,("location:[%s]\n", info2->location));
				DEBUGADD(106,("sepfile:[%s]\n", info2->sepfile));
				DEBUGADD(106,("printprocessor:[%s]\n", info2->printprocessor));
				DEBUGADD(106,("datatype:[%s]\n", info2->datatype));
				DEBUGADD(106,("parameters:[%s]\n", info2->parameters));
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
 Get the parameters we can substitute in an NT print job.
****************************************************************************/

void get_printer_subst_params(int snum, fstring *printername, fstring *sharename, fstring *portname)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;

	**printername = **sharename = **portname = '\0';

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
		return;

	fstrcpy(*printername, printer->info_2->printername);
	fstrcpy(*sharename, printer->info_2->sharename);
	fstrcpy(*portname, printer->info_2->portname);

	free_a_printer(&printer, 2);
}

/*
 * The function below are the high level ones.
 * only those ones must be called from the spoolss code.
 * JFM.
 */

/****************************************************************************
 Modify a printer. This is called from SETPRINTERDATA/DELETEPRINTERDATA.
****************************************************************************/

uint32 mod_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2:
		{
			printer.info_2->c_setprinter++;
			success=update_a_printer_2(printer.info_2);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
 Add a printer. This is called from ADDPRINTER(EX) and also SETPRINTER.
 We split this out from mod_a_printer as it updates the id's and timestamps.
****************************************************************************/

uint32 add_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2: 
		{
			/*
			 * Update the changestamp.
			 * Note we must *not* do this in mod_a_printer().
			 */
			NTTIME time_nt;
			time_t time_unix = time(NULL);
			unix_to_nt_time(&time_nt, time_unix);
			printer.info_2->changeid=time_nt.low;

			printer.info_2->c_setprinter++;
			success=update_a_printer_2(printer.info_2);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
 Get a NT_PRINTER_INFO_LEVEL struct. It returns malloced memory.
****************************************************************************/

uint32 get_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level, fstring sharename)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	
	*pp_printer = NULL;

	DEBUG(10,("get_a_printer: [%s] level %u\n", sharename, (unsigned int)level));

	switch (level)
	{
		case 2: 
		{
			if ((printer = (NT_PRINTER_INFO_LEVEL *)malloc(sizeof(NT_PRINTER_INFO_LEVEL))) == NULL) {
				DEBUG(0,("get_a_printer: malloc fail.\n"));
				return 1;
			}
			ZERO_STRUCTP(printer);
			success=get_a_printer_2(&printer->info_2, sharename);
			if (success == 0) {
				dump_a_printer(*printer, level);
				*pp_printer = printer;
			} else {
				safe_free(printer);
			}
			break;
		}
		default:
			success=1;
			break;
	}
	
	DEBUG(10,("get_a_printer: [%s] level %u returning %u\n", sharename, (unsigned int)level, (unsigned int)success));

	return (success);
}

/****************************************************************************
 Deletes a NT_PRINTER_INFO_LEVEL struct.
****************************************************************************/

uint32 free_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL *printer = *pp_printer;

	DEBUG(104,("freeing a printer at level [%d]\n", level));

	if (printer == NULL)
		return 0;
	
	switch (level)
	{
		case 2: 
		{
			if (printer->info_2 != NULL)
			{
				free_nt_printer_info_level_2(&printer->info_2);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}

	safe_free(printer);
	*pp_printer = NULL;
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 add_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	DEBUG(104,("adding a printer at level [%d]\n", level));
	dump_a_printer_driver(driver, level);
	
	switch (level)
	{
		case 3: 
		{
			success=add_a_printer_driver_3(driver.info_3);
			break;
		}

		case 6: 
		{
			success=add_a_printer_driver_6(driver.info_6);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}
/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level, 
                            fstring printername, fstring architecture, uint32 version)
{
	uint32 success;
	
	switch (level)
	{
		case 3: 
		{
			success=get_a_printer_driver_3(&driver->info_3, printername, architecture, version);
			break;
		}
		default:
			success=1;
			break;
	}
	
	if (success == 0)
		dump_a_printer_driver(*driver, level);
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	
	switch (level)
	{
		case 3: 
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
			if (driver.info_3 != NULL)
			{
				info3=driver.info_3;
				safe_free(info3->dependentfiles);
				ZERO_STRUCTP(info3);
				safe_free(info3);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		case 6: 
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *info6;
			if (driver.info_6 != NULL)
			{
				info6=driver.info_6;
				safe_free(info6->dependentfiles);
				safe_free(info6->previousnames);
				ZERO_STRUCTP(info6);
				safe_free(info6);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}
	return (success);
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param_by_index(NT_PRINTER_INFO_LEVEL printer, uint32 level, uint32 param_index,
                                 fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	int i=0;
	
	param=printer.info_2->specific;
	
	while (param != NULL && i < param_index) {
		param=param->next;
		i++;
	}
	
	if (param == NULL)
		return False;

	/* exited because it exist */
	*type=param->type;		
	StrnCpy(value, param->value, sizeof(fstring)-1);
	*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
	if(*data == NULL)
		return False;
	ZERO_STRUCTP(*data);
	memcpy(*data, param->data, param->data_len);
	*len=param->data_len;
	return True;
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param(NT_PRINTER_INFO_LEVEL printer, uint32 level, 
                        fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	
	DEBUG(105, ("get_specific_param\n"));
	
	param=printer.info_2->specific;
		
	while (param != NULL)
	{
#if 1 /* JRA - I think this should be case insensitive.... */
		if ( strequal(value, param->value) 
#else
		if ( !strcmp(value, param->value) 
#endif
		    && strlen(value)==strlen(param->value))
			break;
			
		param=param->next;
	}
	
	DEBUG(106, ("found one param\n"));
	if (param != NULL)
	{
		/* exited because it exist */
		*type=param->type;	
		
		*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
		if(*data == NULL)
			return False;
		memcpy(*data, param->data, param->data_len);
		*len=param->data_len;

		DEBUG(106, ("exit of get_specific_param:true\n"));
		return (True);
	}
	DEBUG(106, ("exit of get_specific_param:false\n"));
	return (False);
}

/****************************************************************************
 Store a security desc for a printer.
****************************************************************************/

uint32 nt_printing_setsec(char *printername, SEC_DESC_BUF *secdesc_ctr)
{
	prs_struct ps;
	TALLOC_CTX *mem_ctx = NULL;
	fstring key;
	uint32 status;

	mem_ctx = talloc_init();
	if (mem_ctx == NULL) return False;

	/* Store the security descriptor in a tdb */

	prs_init(&ps, (uint32)sec_desc_size(secdesc_ctr->sec) + 
		 sizeof(SEC_DESC_BUF), 4, mem_ctx, MARSHALL);

	if (!sec_io_desc_buf("nt_printing_setsec", &secdesc_ctr, &ps, 1)) {
		status = ERROR_INVALID_FUNCTION;
		goto done;
	}

	slprintf(key, sizeof(key), "SECDESC/%s", printername);

	if (tdb_prs_store(tdb, key, &ps)==0) {
		status = 0;
	} else {
		DEBUG(1,("Failed to store secdesc for %s\n", printername));
		status = ERROR_INVALID_FUNCTION;
	}

	/* Free mallocated memory */

 done:
	prs_mem_free(&ps);

	if (mem_ctx) talloc_destroy(mem_ctx);

	return status;
}

/****************************************************************************
 Construct a default security descriptor buffer for a printer.
****************************************************************************/

static SEC_DESC_BUF *construct_default_printer_sdb(void)
{
	SEC_ACE ace[2];
	SEC_ACCESS sa;
	SEC_ACL *psa = NULL;
	SEC_DESC_BUF *sdb = NULL;
	SEC_DESC *psd = NULL;
	DOM_SID owner_sid;
	size_t sd_size;
	enum SID_NAME_USE name_type;

	/* Create an ACE where Everyone is allowed to print */

	init_sec_access(&sa, PRINTER_ACE_PRINT);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_CONTAINER_INHERIT);


	/* Make the security descriptor owned by the Administrators group
	   on the PDC of the domain. */

	if (winbind_lookup_name(lp_workgroup(), &owner_sid, &name_type)) {
		sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN);
	} else {

		/* Backup plan - make printer owned by admins or root.  This should
		   emulate a lanman printer as security settings can't be
		   changed. */

		if (!lookup_name( "Printer Administrators", &owner_sid, &name_type) &&
			!lookup_name( "Administrators", &owner_sid, &name_type) &&
			!lookup_name( "Administrator", &owner_sid, &name_type) &&
			!lookup_name("root", &owner_sid, &name_type)) {
						sid_copy(&owner_sid, &global_sid_World);
		}
	}

	init_sec_access(&sa, PRINTER_ACE_MANAGE_DOCUMENTS | PRINTER_ACE_PRINT);
	init_sec_ace(&ace[1], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_CONTAINER_INHERIT);

	/* The ACL revision number in rpc_secdesc.h differs from the one
	   created by NT when setting ACE entries in printer
	   descriptors.  NT4 complains about the property being edited by a
	   NT5 machine. */

#define NT4_ACL_REVISION 0x2

	if ((psa = make_sec_acl(NT4_ACL_REVISION, 2, ace)) != NULL) {
		psd = make_sec_desc(SEC_DESC_REVISION, 
				    SEC_DESC_SELF_RELATIVE | 
				    SEC_DESC_DACL_PRESENT,
				    &owner_sid, NULL,
				    NULL, psa, &sd_size);
		free_sec_acl(&psa);
	}

	if (!psd) {
		DEBUG(0,("construct_default_printer_sd: Failed to make SEC_DESC.\n"));
		return NULL;
	}

	sdb = make_sec_desc_buf(sd_size, psd);

	DEBUG(4,("construct_default_printer_sdb: size = %u.\n", 
		 (unsigned int)sd_size));

	free_sec_desc(&psd);
	return sdb;
}

/****************************************************************************
 Get a security desc for a printer.
****************************************************************************/

BOOL nt_printing_getsec(char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	prs_struct ps;
	TALLOC_CTX *mem_ctx = NULL;
	fstring key;

	mem_ctx = talloc_init();
	if (mem_ctx == NULL)
		return False;

	/* Fetch security descriptor from tdb */

	slprintf(key, sizeof(key), "SECDESC/%s", printername);

	if (tdb_prs_fetch(tdb, key, &ps, mem_ctx)!=0 ||
	    !sec_io_desc_buf("nt_printing_getsec", secdesc_ctr, &ps, 1)) {

		DEBUG(4,("using default secdesc for %s\n", printername));

		if (!(*secdesc_ctr = construct_default_printer_sdb())) {
			talloc_destroy(mem_ctx);
			return False;
		}

		talloc_destroy(mem_ctx);
		return True;
	}

	/* If security descriptor is owned by S-1-1-0 and winbindd is up,
	   this security descriptor has been created when winbindd was
	   down.  Take ownership of security descriptor. */

	if (sid_equal((*secdesc_ctr)->sec->owner_sid, &global_sid_World)) {
		DOM_SID owner_sid;
		enum SID_NAME_USE name_type;

		/* Change sd owner to workgroup administrator */

		if (winbind_lookup_name(lp_workgroup(), &owner_sid,
					&name_type)) {
			SEC_DESC_BUF *new_secdesc_ctr = NULL;
			SEC_DESC *psd = NULL;
			size_t size;

			/* Create new sd */

			sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN);

			psd = make_sec_desc((*secdesc_ctr)->sec->revision,
					    (*secdesc_ctr)->sec->type,
					    &owner_sid,
					    (*secdesc_ctr)->sec->grp_sid,
					    (*secdesc_ctr)->sec->sacl,
					    (*secdesc_ctr)->sec->dacl,
					    &size);

			new_secdesc_ctr = make_sec_desc_buf(size, psd);

			free_sec_desc(&psd);

			/* Swap with other one */

			free_sec_desc_buf(secdesc_ctr);
			*secdesc_ctr = new_secdesc_ctr;

			/* Set it */

			nt_printing_setsec(printername, *secdesc_ctr);
		}
	}

	prs_mem_free(&ps);
	talloc_destroy(mem_ctx);
	return True;
}

/* error code:
	0: everything OK
	1: level not implemented
	2: file doesn't exist
	3: can't allocate memory
	4: can't free memory
	5: non existant struct
*/

/*
	A printer and a printer driver are 2 different things.
	NT manages them separatelly, Samba does the same.
	Why ? Simply because it's easier and it makes sense !
	
	Now explanation: You have 3 printers behind your samba server,
	2 of them are the same make and model (laser A and B). But laser B 
	has an 3000 sheet feeder and laser A doesn't such an option.
	Your third printer is an old dot-matrix model for the accounting :-).
	
	If the /usr/local/samba/lib directory (default dir), you will have
	5 files to describe all of this.
	
	3 files for the printers (1 by printer):
		NTprinter_laser A
		NTprinter_laser B
		NTprinter_accounting
	2 files for the drivers (1 for the laser and 1 for the dot matrix)
		NTdriver_printer model X
		NTdriver_printer model Y

jfm: I should use this comment for the text file to explain 
	same thing for the forms BTW.
	Je devrais mettre mes commentaires en francais, ca serait mieux :-)

*/

/****************************************************************************
 Check a user has permissions to perform the given operation.  We use some
 constants defined in include/rpc_spoolss.h that look relevant to check
 the various actions we perform when checking printer access.

   PRINTER_ACCESS_ADMINISTER:
       print_queue_pause, print_queue_resume, update_printer_sec,
       update_printer, spoolss_addprinterex_level_2,
       _spoolss_setprinterdata
        
   PRINTER_ACCESS_USE:
       print_job_start

   JOB_ACCESS_ADMINISTER:
       print_job_delete, print_job_pause, print_job_resume,
       print_queue_purge

 ****************************************************************************/
BOOL print_access_check(struct current_user *user, int snum, int access_type)
{
	SEC_DESC_BUF *secdesc = NULL;
	uint32 access_granted, status, required_access = 0;
	BOOL result;
	char *pname;
	int i;
	extern struct current_user current_user;
	
	/* If user is NULL then use the current_user structure */

	if (!user) user = &current_user;

	/* Always allow root or printer admins to do anything */

	if (user->uid == 0 ||
	    user_in_list(uidtoname(user->uid), lp_printer_admin(snum))) {
		return True;
	}

	/* Get printer name */

	pname = PRINTERNAME(snum);

	if (!pname || !*pname)
		pname = SERVICE(snum);

	if (!pname || !*pname) {
		errno = EACCES;
		return False;
	}

	/* Get printer security descriptor */

	nt_printing_getsec(pname, &secdesc);

	/* Check against NT4 ACE mask values.  From observation these
	   values are:

	       Access Type       ACE Mask    Constant
	       -------------------------------------
	       Full Control      0x10000000  PRINTER_ACE_FULL_CONTROL
	       Print             0xe0000000  PRINTER_ACE_PRINT
	       Manage Documents  0x00020000  PRINTER_ACE_MANAGE_DOCUMENTS
	*/

	switch (access_type) {
	case PRINTER_ACCESS_USE:
		required_access = PRINTER_ACE_PRINT;
		break;
	case PRINTER_ACCESS_ADMINISTER:
		required_access = PRINTER_ACE_MANAGE_DOCUMENTS | 
			PRINTER_ACE_PRINT;
		break;
	case JOB_ACCESS_ADMINISTER:
		required_access = PRINTER_ACE_MANAGE_DOCUMENTS;
		break;
	default:
		DEBUG(0, ("invalid value passed to print_access_check()\n"));
		result = False;
		goto done;
	}	

	/* The ACE for Full Control in a printer security descriptor
	   doesn't seem to map properly to the access checking model.  For
	   it to work properly it should be the logical OR of all the other
	   values, i.e PRINTER_ACE_MANAGE_DOCUMENTS | PRINTER_ACE_PRINT.
	   This would cause the access check to simply fall out when we
	   check against any subset of these bits.  To get things to work,
	   change every ACE mask of PRINTER_ACE_FULL_CONTROL to 
	   PRINTER_ACE_MANAGE_DOCUMENTS | PRINTER_ACE_PRINT before
	   performing the access check.  I'm sure there is a better way to
	   do this! */

	if (secdesc && secdesc->sec && secdesc->sec->dacl &&
	    secdesc->sec->dacl->ace) {
		for(i = 0; i < secdesc->sec->dacl->num_aces; i++) {
			if (secdesc->sec->dacl->ace[i].info.mask ==
			    PRINTER_ACE_FULL_CONTROL) {
				secdesc->sec->dacl->ace[i].info.mask =
					PRINTER_ACE_MANAGE_DOCUMENTS | 
					PRINTER_ACE_PRINT;
			}
		}
	}

	if ((result = se_access_check(secdesc->sec, user, required_access, 
				      &access_granted, &status))) {
		goto done;
	}

	/* Check against NT5 ACE mask values.  From observation these
	   values are:

	       Access Type       ACE Mask    Constant
	       -------------------------------------
	       Full Control      0x000f000c  PRINTER_ACE_NT5_FULL_CONTROL
	       Print             0x00020008  PRINTER_ACE_NT5_PRINT
	       Manage Documents  0x00020000  PRINTER_ACE_NT5_MANAGE_DOCUMENTS

	   NT5 likes to rewrite the security descriptor and change the ACE
	   masks from NT4 format to NT5 format making them unreadable by
	   NT4 clients. */

	switch (access_type) {
	case PRINTER_ACCESS_USE:
		required_access = PRINTER_ACE_NT5_PRINT;
		break;
	case PRINTER_ACCESS_ADMINISTER:
		required_access = PRINTER_ACE_NT5_FULL_CONTROL;
		break;
	case JOB_ACCESS_ADMINISTER:
		required_access = PRINTER_ACE_NT5_MANAGE_DOCUMENTS;
		break;
	}	

	result = se_access_check(secdesc->sec, user, required_access, 
				 &access_granted, &status);

	/* Check access */
	
 done:
	DEBUG(4, ("access check was %s\n", result ? "SUCCESS" : "FAILURE"));
	
	/* Free mallocated memory */

	free_sec_desc_buf(&secdesc);

	if (!result)
		errno = EACCES;

	return result;
}

/****************************************************************************
 Check the time parameters allow a print operation.
*****************************************************************************/

BOOL print_time_access_check(int snum)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	BOOL ok = False;
	time_t now = time(NULL);
	struct tm *t;
	uint32 mins;

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
		return False;

	if (printer->info_2->starttime == 0 && printer->info_2->untiltime == 0)
		ok = True;

	t = gmtime(&now);
	mins = (uint32)t->tm_hour*60 + (uint32)t->tm_min;

	if (mins >= printer->info_2->starttime && mins <= printer->info_2->untiltime)
		ok = True;

	free_a_printer(&printer, 2);

	if (!ok)
		errno = EACCES;

	return ok;
}


#undef OLD_NTDOMAIN
