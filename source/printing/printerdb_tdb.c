#include "includes.h"

static TDB_CONTEXT *tdb_forms; /* used for forms files */
static TDB_CONTEXT *tdb_drivers; /* used for driver files */
static TDB_CONTEXT *tdb_printers; /* used for printers files */

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define DRIVER_INIT_PREFIX "DRIVER_INIT/"
#define PRINTERS_PREFIX "PRINTERS/"
#define SECDESC_PREFIX "SECDESC/"
#define GLOBAL_C_SETPRINTER "GLOBALS/c_setprinter"
 
#define NTDRIVERS_DATABASE_VERSION_1 1
#define NTDRIVERS_DATABASE_VERSION_2 2
#define NTDRIVERS_DATABASE_VERSION_3 3 /* little endian version of v2 */
 
#define NTDRIVERS_DATABASE_VERSION NTDRIVERS_DATABASE_VERSION_3


struct tdb_printerdb_struct {
	time_t lastmod_forms;
	time_t lastmod_printers;
	time_t lastmod_drivers;
};

static struct tdb_printerdb_struct tdb_printerdb;


static BOOL upgrade_to_version_3(void)
{
	TDB_DATA kbuf, newkey, dbuf;
 
	DEBUG(0,("upgrade_to_version_3: upgrading print tdb's to version 3\n"));
 
	for (kbuf = tdb_firstkey(tdb_drivers); kbuf.dptr;
			newkey = tdb_nextkey(tdb_drivers, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		dbuf = tdb_fetch(tdb_drivers, kbuf);

		if (strncmp(kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) == 0) {
			DEBUG(0,("upgrade_to_version_3:moving form\n"));
			if (tdb_store(tdb_forms, kbuf, dbuf, TDB_REPLACE) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to move form. Error (%s).\n", tdb_errorstr(tdb_forms)));
				return False;
			}
			if (tdb_delete(tdb_drivers, kbuf) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to delete form. Error (%s)\n", tdb_errorstr(tdb_drivers)));
				return False;
			}
		}
 
		if (strncmp(kbuf.dptr, PRINTERS_PREFIX, strlen(PRINTERS_PREFIX)) == 0) {
			DEBUG(0,("upgrade_to_version_3:moving printer\n"));
			if (tdb_store(tdb_printers, kbuf, dbuf, TDB_REPLACE) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to move printer. Error (%s)\n", tdb_errorstr(tdb_printers)));
				return False;
			}
			if (tdb_delete(tdb_drivers, kbuf) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to delete printer. Error (%s)\n", tdb_errorstr(tdb_drivers)));
				return False;
			}
		}
 
		if (strncmp(kbuf.dptr, SECDESC_PREFIX, strlen(SECDESC_PREFIX)) == 0) {
			DEBUG(0,("upgrade_to_version_3:moving secdesc\n"));
			if (tdb_store(tdb_printers, kbuf, dbuf, TDB_REPLACE) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to move secdesc. Error (%s)\n", tdb_errorstr(tdb_printers)));
				return False;
			}
			if (tdb_delete(tdb_drivers, kbuf) != 0) {
				SAFE_FREE(dbuf.dptr);
				DEBUG(0,("upgrade_to_version_3: failed to delete secdesc. Error (%s)\n", tdb_errorstr(tdb_drivers)));
				return False;
			}
		}
 
		SAFE_FREE(dbuf.dptr);
	}

	return True;
}

/*******************************************************************
 tdb traversal function for counting printers.
********************************************************************/

static int traverse_counting_printers(TDB_CONTEXT *t, TDB_DATA key,
                                      TDB_DATA data, void *context)
{
	int *printer_count = (int*)context;
 
	if (memcmp(PRINTERS_PREFIX, key.dptr, sizeof(PRINTERS_PREFIX)-1) == 0) {
		(*printer_count)++;
		DEBUG(10,("traverse_counting_printers: printer = [%s]  printer_count = %d\n", key.dptr, *printer_count));
	}
 
	return 0;
}

/****************************************************************************
 Allocate and initialize a new slot.
***************************************************************************/
 
int add_new_printer_key( NT_PRINTER_DATA *data, const char *name )
{
	NT_PRINTER_KEY	*d;
	int		key_index;
	
	if ( !data || !name )
		return -1;
	
	/* allocate another slot in the NT_PRINTER_KEY array */
	
	d = SMB_REALLOC_ARRAY( data->keys, NT_PRINTER_KEY, data->num_keys+1);
	if ( d )
		data->keys = d;
	
	key_index = data->num_keys;
	
	/* initialze new key */
	
	data->num_keys++;
	data->keys[key_index].name = SMB_STRDUP( name );
	
	ZERO_STRUCTP( &data->keys[key_index].values );
	
	regval_ctr_init( &data->keys[key_index].values );
	
	DEBUG(10,("add_new_printer_key: Inserted new data key [%s]\n", name ));
	
	return key_index;
}

/****************************************************************************
 search for a registry key name in the existing printer data
 ***************************************************************************/
 
int lookup_printerkey( NT_PRINTER_DATA *data, const char *name )
{
	int		key_index = -1;
	int		i;
	
	if ( !data || !name )
		return -1;

	DEBUG(12,("lookup_printerkey: Looking for [%s]\n", name));

	/* loop over all existing keys */
	
	for ( i=0; i<data->num_keys; i++ ) {
		if ( strequal(data->keys[i].name, name) ) {
			DEBUG(12,("lookup_printerkey: Found [%s]!\n", name));
			key_index = i;
			break;
		
		}
	}
	
	return key_index;
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/
 
int unpack_values(NT_PRINTER_DATA *printer_data, char *buf, int buflen)
{
	int 		len = 0;
	uint32		type;
	pstring		string, valuename, keyname;
	char		*str;
	int		size;
	uint8		*data_p;
	REGISTRY_VALUE 	*regval_p;
	int		key_index;
	
	/* add the "PrinterDriverData" key first for performance reasons */
	
	add_new_printer_key( printer_data, SPOOL_PRINTERDATA_KEY );

	/* loop and unpack the rest of the registry values */
	
	while ( True ) {
	
		/* check to see if there are any more registry values */
		
		regval_p = NULL;
		len += tdb_unpack(buf+len, buflen-len, "p", &regval_p);		
		if ( !regval_p ) 
			break;

		/* unpack the next regval */
		
		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  string,
				  &type,
				  &size,
				  &data_p);
	
		/*
		 * break of the keyname from the value name.  
		 * Valuenames can have embedded '\'s so be careful.
		 * only support one level of keys.  See the 
		 * "Konica Fiery S300 50C-K v1.1. enu" 2k driver.
		 * -- jerry
		 */	
		 
		str = strchr_m( string, '\\');
		
		/* Put in "PrinterDriverData" is no key specified */
		
		if ( !str ) {
			pstrcpy( keyname, SPOOL_PRINTERDATA_KEY );
			pstrcpy( valuename, string );
		}
		else {
			*str = '\0';
			pstrcpy( keyname, string );
			pstrcpy( valuename, str+1 );
		}
			
		/* see if we need a new key */
		
		if ( (key_index=lookup_printerkey( printer_data, keyname )) == -1 )
			key_index = add_new_printer_key( printer_data, keyname );
			
		if ( key_index == -1 ) {
			DEBUG(0,("unpack_values: Failed to allocate a new key [%s]!\n",
				keyname));
			break;
		}
		
		/* add the new value */
		
		regval_ctr_addvalue( &printer_data->keys[key_index].values, valuename, type, (const char *)data_p, size );

		SAFE_FREE(data_p); /* 'B' option to tdbpack does a malloc() */

		DEBUG(8,("specific: [%s:%s], len: %d\n", keyname, valuename, size));
	}

	return len;
}

/****************************************************************************
****************************************************************************/
int unpack_devicemode(NT_DEVICEMODE **nt_devmode, char *buf, int buflen)
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
		 * devmode.driverextra is only a short
		 */
		len += tdb_unpack(buf+len, buflen-len, "B", &extra_len, &devmode.private);
		devmode.driverextra=(uint16)extra_len;
		
		/* check to catch an invalid TDB entry so we don't segfault */
		if (devmode.driverextra == 0) {
			devmode.private = NULL;
		}
	}

	*nt_devmode = (NT_DEVICEMODE *)memdup(&devmode, sizeof(devmode));

	DEBUG(8,("Unpacked devicemode [%s](%s)\n", devmode.devicename, devmode.formname));
	if (devmode.private)
		DEBUG(8,("with a private section of %d bytes\n", devmode.driverextra));

	return len;
}

/****************************************************************************
****************************************************************************/
int pack_devicemode(NT_DEVICEMODE *nt_devmode, char *buf, int buflen)
{
	int len = 0;

	len += tdb_pack(buf+len, buflen-len, "p", nt_devmode);

	if (!nt_devmode)
		return len;

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
 Pack all values in all printer keys
 ***************************************************************************/
 
int pack_values(NT_PRINTER_DATA *data, char *buf, int buflen)
{
	int 		len = 0;
	int 		i, j;
	REGISTRY_VALUE	*val;
	REGVAL_CTR	*val_ctr;
	pstring		path;
	int		num_values;

	if ( !data )
		return 0;

	/* loop over all keys */
		
	for ( i=0; i<data->num_keys; i++ ) {	
		val_ctr = &data->keys[i].values;
		num_values = regval_ctr_numvals( val_ctr );
		
		/* loop over all values */
		
		for ( j=0; j<num_values; j++ ) {
			/* pathname should be stored as <key>\<value> */
			
			val = regval_ctr_specific_value( val_ctr, j );
			pstrcpy( path, data->keys[i].name );
			pstrcat( path, "\\" );
			pstrcat( path, regval_name(val) );
			
			len += tdb_pack(buf+len, buflen-len, "pPdB",
					val,
					path,
					regval_type(val),
					regval_size(val),
					regval_data_p(val) );
		}
	
	}

	/* terminator */
	
	len += tdb_pack(buf+len, buflen-len, "p", NULL);

	return len;
}

/****************************************************************************
 Open the NT printing tdbs. Done once before fork().
****************************************************************************/
static BOOL tdb_init(void)
{
	static pid_t local_pid;
	const char *vstring = "INFO/version";

	if (tdb_drivers && tdb_printers && tdb_forms && local_pid == sys_getpid())
		return True;
 
	if (tdb_drivers)
		tdb_close(tdb_drivers);
	tdb_drivers = tdb_open_log(lock_path("ntdrivers.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb_drivers) {
		DEBUG(0,("nt_printing_init: Failed to open nt drivers database %s (%s)\n",
			lock_path("ntdrivers.tdb"), strerror(errno) ));
		return False;
	}
 
	if (tdb_printers)
		tdb_close(tdb_printers);
	tdb_printers = tdb_open_log(lock_path("ntprinters.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb_printers) {
		DEBUG(0,("nt_printing_init: Failed to open nt printers database %s (%s)\n",
			lock_path("ntprinters.tdb"), strerror(errno) ));
		return False;
	}
 
	if (tdb_forms)
		tdb_close(tdb_forms);
	tdb_forms = tdb_open_log(lock_path("ntforms.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb_forms) {
		DEBUG(0,("nt_printing_init: Failed to open nt forms database %s (%s)\n",
			lock_path("ntforms.tdb"), strerror(errno) ));
		return False;
	}
 
	local_pid = sys_getpid();
 
	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb_drivers, vstring, 0);
	{
		int32 vers_id;

		/* Cope with byte-reversed older versions of the db. */
		vers_id = tdb_fetch_int32(tdb_drivers, vstring);
		if ((vers_id == NTDRIVERS_DATABASE_VERSION_2) || (IREV(vers_id) == NTDRIVERS_DATABASE_VERSION_2)) {
			/* Written on a bigendian machine with old fetch_int code. Save as le. */
			/* The only upgrade between V2 and V3 is to save the version in little-endian. */
			tdb_store_int32(tdb_drivers, vstring, NTDRIVERS_DATABASE_VERSION);
			vers_id = NTDRIVERS_DATABASE_VERSION;
		}

		if (vers_id != NTDRIVERS_DATABASE_VERSION) {

			if ((vers_id == NTDRIVERS_DATABASE_VERSION_1) || (IREV(vers_id) == NTDRIVERS_DATABASE_VERSION_1)) { 
				if (!upgrade_to_version_3())
					return False;
			} else
				tdb_traverse(tdb_drivers, tdb_traverse_delete_fn, NULL);
			 
			tdb_store_int32(tdb_drivers, vstring, NTDRIVERS_DATABASE_VERSION);
		}
	}
	tdb_unlock_bystring(tdb_drivers, vstring);

	return True;
}

BOOL tdb_printerdb_init(char *param)
{
	if (!tdb_init())
		return False;

	/* invalidate cache tdb upon init */
	tdb_printerdb.lastmod_forms = -1;
	tdb_printerdb.lastmod_printers = -1;
	tdb_printerdb.lastmod_drivers = -1;
	
	return True;
}

time_t tdb_get_last_update(int tdb)
{
	switch (tdb) {
	case TDB_DRIVERS:
		return tdb_printerdb.lastmod_drivers;
	case TDB_FORMS:
		return tdb_printerdb.lastmod_forms;
	case TDB_PRINTERS:
		return tdb_printerdb.lastmod_printers;
	case TDB_SECDESC:
		return tdb_printerdb.lastmod_printers;
	case TDB_DRIVERSINIT:
		return tdb_printerdb.lastmod_printers;
	default:
		DEBUG(0,("unknown query: %d\n", tdb));
		return time(NULL);
	} 
}

BOOL tdb_set_last_update(time_t update, int tdb)
{
	time_t now = time(NULL);

	switch (tdb) {
	case TDB_DRIVERS:
		tdb_printerdb.lastmod_drivers = now;
	case TDB_FORMS:
		tdb_printerdb.lastmod_forms = now;
	case TDB_PRINTERS:
		tdb_printerdb.lastmod_printers = now;
	default:
		DEBUG(0,("unknown query: %d\n", tdb));
		return False;
	} 

	return True;
}

uint32 tdb_update_c_setprinter(BOOL initialize)
{
	int32 c_setprinter;
	int32 printer_count = 0;
 
	tdb_lock_bystring(tdb_printers, GLOBAL_C_SETPRINTER, 0);
 
	/* Traverse the tdb, counting the printers */
	tdb_traverse(tdb_printers, traverse_counting_printers, (void *)&printer_count);
 
	/* If initializing, set c_setprinter to current printers count
	 * otherwise, bump it by the current printer count
	 */
	if (!initialize)
		c_setprinter = tdb_fetch_int32(tdb_printers, GLOBAL_C_SETPRINTER) + printer_count;
	else
		c_setprinter = printer_count;
 
	DEBUG(10,("update_c_setprinter: c_setprinter = %u\n", (unsigned int)c_setprinter));
	tdb_store_int32(tdb_printers, GLOBAL_C_SETPRINTER, c_setprinter);
 
	tdb_unlock_bystring(tdb_printers, GLOBAL_C_SETPRINTER);
 
	return (uint32)c_setprinter;
}

/*******************************************************************
 Get the spooler global c_setprinter, accounting for initialization.
********************************************************************/

uint32 tdb_get_c_setprinter(void)
{
	return file_get_c_setprinter();
	int32 c_setprinter = tdb_fetch_int32(tdb_printers, GLOBAL_C_SETPRINTER);
	file_get_c_setprinter(); 
	if (c_setprinter == (int32)-1)
		c_setprinter = update_c_setprinter(True);
 
	DEBUG(10,("get_c_setprinter: c_setprinter = %d\n", c_setprinter));
 
	return (uint32)c_setprinter;
}

int tdb_get_forms(nt_forms_struct **list)
{
	TDB_DATA kbuf, newkey, dbuf;
	nt_forms_struct *tl;
	nt_forms_struct form;
	int ret;
	int i;
	int n = 0;

	for (kbuf = tdb_firstkey(tdb_forms);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb_forms, kbuf), safe_free(kbuf.dptr), kbuf=newkey) 
	{
		if (strncmp(kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) != 0) 
			continue;
		
		dbuf = tdb_fetch(tdb_forms, kbuf);
		if (!dbuf.dptr) 
			continue;

		fstrcpy(form.name, kbuf.dptr+strlen(FORMS_PREFIX));
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "dddddddd",
				 &i, &form.flag, &form.width, &form.length, &form.left,
				 &form.top, &form.right, &form.bottom);
		SAFE_FREE(dbuf.dptr);
		if (ret != dbuf.dsize) 
			continue;

		tl = SMB_REALLOC_ARRAY(*list, nt_forms_struct, n+1);
		if (!tl) {
			DEBUG(0,("get_ntforms: Realloc fail.\n"));
			return 0;
		}
		*list = tl;
		(*list)[n] = form;
		n++;
	}
	
	return n;
}

int tdb_write_forms(nt_forms_struct **list, int number)
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
		slprintf(key, sizeof(key)-1, "%s%s", FORMS_PREFIX, (*list)[i].name);
		kbuf.dsize = strlen(key)+1;
		kbuf.dptr = key;
		dbuf.dsize = len;
		dbuf.dptr = buf;
		if (tdb_store(tdb_forms, kbuf, dbuf, TDB_REPLACE) != 0) break;
	}

	tdb_printerdb.lastmod_forms = time(NULL);
	
	return i;
}	

BOOL tdb_del_form(char *del_name, WERROR *ret)
{
	pstring key;
	TDB_DATA kbuf;
	fstring form_name;

	*ret = WERR_OK;

	slprintf(key, sizeof(key)-1, "%s%s", FORMS_PREFIX, form_name);
	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;
	if (tdb_delete(tdb_forms, kbuf) != 0) {
		*ret = WERR_NOMEM;
		return False;
	}

	return True;
}

static WERROR tdb_del_printer(const char *sharename)
{
	pstring key;
	TDB_DATA kbuf;

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, sharename);
	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;
	tdb_delete(tdb_printers, kbuf);

	slprintf(key, sizeof(key)-1, "%s%s", SECDESC_PREFIX, sharename);
	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;
	tdb_delete(tdb_printers, kbuf);

	return WERR_OK;
}

int tdb_get_drivers(fstring **list, const char *short_archi, uint32 version)
{
	int total=0;
	fstring *fl;
	pstring key;
	TDB_DATA kbuf, newkey;

	slprintf(key, sizeof(key)-1, "%s%s/%d/", DRIVERS_PREFIX, short_archi, version);

	for (kbuf = tdb_firstkey(tdb_drivers);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb_drivers, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, key, strlen(key)) != 0)
			continue;
		
		if((fl = SMB_REALLOC_ARRAY(*list, fstring, total+1)) == NULL) {
			DEBUG(0,("get_ntdrivers: failed to enlarge list!\n"));
			return -1;
		}
		else *list = fl;

		fstrcpy((*list)[total], kbuf.dptr+strlen(key));
		total++;
	}

	return(total);
}

uint32 tdb_add_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver, const char *short_archi)
{

	int len, buflen;
	pstring key;
	char *buf;
	int i, ret;
	TDB_DATA kbuf, dbuf;

	slprintf(key, sizeof(key)-1, "%s%s/%d/%s", DRIVERS_PREFIX, short_archi, driver->cversion, driver->name);

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
		char *tb;

		tb = (char *)SMB_REALLOC(buf, len);
		if (!tb) {
			DEBUG(0,("add_a_printer_driver_3: failed to enlarge buffer\n!"));
			ret = -1;
			goto done;
		}
		else buf = tb;
		buflen = len;
		goto again;
	}


	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;
	
	ret = tdb_store(tdb_drivers, kbuf, dbuf, TDB_REPLACE);

done:
	if (ret)
		DEBUG(0,("add_a_printer_driver_3: Adding driver with key %s failed.\n", key ));

	SAFE_FREE(buf);
	return ret;
}

WERROR tdb_get_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, 
		     fstring drivername, 
		     const char *short_archi, 
		     uint32 version)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 driver;
	TDB_DATA kbuf, dbuf;
	int len = 0;
	int i;
	pstring key;

	ZERO_STRUCT(driver);

	slprintf(key, sizeof(key)-1, "%s%s/%d/%s", DRIVERS_PREFIX, short_archi, version, drivername);

	DEBUG(8,("get_a_printer_driver_3: [%s]\n", key));

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	
	dbuf = tdb_fetch(tdb_drivers, kbuf);
	if (!dbuf.dptr) 
		return WERR_UNKNOWN_PRINTER_DRIVER;

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
		fstring *tddfs;

		tddfs = SMB_REALLOC_ARRAY(driver.dependentfiles, fstring, i+2);
		if (tddfs == NULL) {
			DEBUG(0,("get_a_printer_driver_3: failed to enlarge buffer!\n"));
			break;
		}
		else driver.dependentfiles = tddfs;

		len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "f",
				  &driver.dependentfiles[i]);
		i++;
	}
	
	if (driver.dependentfiles != NULL)
		fstrcpy(driver.dependentfiles[i], "");

	SAFE_FREE(dbuf.dptr);

	if (len != dbuf.dsize) {
		SAFE_FREE(driver.dependentfiles);
		return WERR_UNKNOWN_PRINTER_DRIVER;
	}

	*info_ptr = (NT_PRINTER_DRIVER_INFO_LEVEL_3 *)memdup(&driver, sizeof(driver));

	return WERR_OK;
}

static BOOL tdb_del_driver(const char *short_archi, int version, const char *drivername)
{
	pstring 	key;
	TDB_DATA 	kbuf;

	/* delete the tdb data first */
	slprintf(key, sizeof(key)-1, "%s/%s/%d/%s", DRIVERS_PREFIX,
		short_archi, version, drivername);

	DEBUG(5,("tdb_del_driver: key = [%s]\n", key));

	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;

	/* ok... the driver exists so the delete should return success */
	if (tdb_delete(tdb_drivers, kbuf) == -1) {
		DEBUG (0,("tdb_del_driver: fail to delete %s!\n", key));
		return False;
	}

	DEBUG(5,("tdb_del_driver: driver delete successful [%s]\n", key));

	return True;
}

static BOOL tdb_del_driver_init(const char *drivername)
{
	pstring key;
	TDB_DATA kbuf;

	if (!drivername || !*drivername) {
		DEBUG(3,("del_driver_init: No drivername specified!\n"));
		return False;
	}

	slprintf(key, sizeof(key)-1, "%s%s", DRIVER_INIT_PREFIX, drivername);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	DEBUG(6,("del_driver_init: Removing driver init data for [%s]\n", drivername));

	return (tdb_delete(tdb_drivers, kbuf) == 0);
}

WERROR tdb_get_secdesc(TALLOC_CTX *ctx, const char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	prs_struct ps;
	fstring key;

	/* Fetch security descriptor from tdb */
	slprintf(key, sizeof(key)-1, "%s%s", SECDESC_PREFIX, printername);

	if (tdb_prs_fetch(tdb_printers, key, &ps, ctx)!=0 ||
	    !sec_io_desc_buf("nt_printing_getsec", secdesc_ctr, &ps, 1)) {
		return WERR_NOMEM;
	}
	prs_mem_free(&ps);

	return WERR_OK;
}

static WERROR tdb_set_secdesc(TALLOC_CTX *ctx, const char *printername, SEC_DESC_BUF *secdesc_ctr)
{
	prs_struct ps;
	fstring key;

	/* Fetch security descriptor from tdb */
	slprintf(key, sizeof(key)-1, "%s%s", SECDESC_PREFIX, printername);

	prs_init(&ps, (uint32)sec_desc_size(secdesc_ctr->sec) +
		sizeof(SEC_DESC_BUF), ctx, MARSHALL);

	if (sec_io_desc_buf("tdb_set_secdesc", &secdesc_ctr, &ps, 1))
		tdb_prs_store(tdb_printers, key, &ps);

	prs_mem_free(&ps);

	return WERR_OK;
}

int tdb_get_printers(fstring **list)
{
	int total=0;
	fstring *fl;
	pstring key;
	TDB_DATA kbuf, newkey;

	slprintf(key, sizeof(key)-1, "%s", PRINTERS_PREFIX);

	for (kbuf = tdb_firstkey(tdb_printers);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb_printers, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, key, strlen(key)) != 0)
			continue;
		
		if ((fl = SMB_REALLOC_ARRAY(*list, fstring, total+1)) == NULL) {
			DEBUG(0,("tdb_get_printers: failed to enlarge list!\n"));
			return -1;
		} else {
			*list = fl;
		}

		fstrcpy((*list)[total], kbuf.dptr+strlen(key));
		total++;
	}

	return total;
}

WERROR tdb_get_printer(NT_PRINTER_INFO_LEVEL_2 **info_ptr, const char *sharename)
{
	pstring key;
	NT_PRINTER_INFO_LEVEL_2 info;
	int len = 0;
	TDB_DATA kbuf, dbuf;

	ZERO_STRUCT(info);

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, sharename);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb_printers, kbuf);
	if (!dbuf.dptr) {
		DEBUG(0,("tdb_get_printer: could not find printer: %s\n", sharename));
		return WERR_INVALID_PRINTER_NAME;
	}

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

	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);

	len += unpack_values( &info.data, dbuf.dptr+len, dbuf.dsize-len );

	SAFE_FREE(dbuf.dptr);

	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));

	return WERR_OK;	
}

static WERROR tdb_update_printer(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len;
	WERROR ret;
	TDB_DATA kbuf, dbuf;
	
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
			ret = WERR_NOMEM;
			goto done;
		}
		else buf = tb;
		buflen = len;
		goto again;
	}
	

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, info->sharename);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = (tdb_store(tdb_printers, kbuf, dbuf, TDB_REPLACE) == 0? WERR_OK : WERR_NOMEM);

done:
	if (!W_ERROR_IS_OK(ret))
		DEBUG(8, ("error updating printer to tdb on disk\n"));

	SAFE_FREE(buf);

	DEBUG(8,("packed printer [%s] with driver [%s] portname=[%s] len=%d\n",
		 info->sharename, info->drivername, info->portname, len));

	return ret;
}

static uint32 tdb_update_driver_init(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len, ret;
	TDB_DATA kbuf, dbuf;

	buf = NULL;
	buflen = 0;

 again:	
	len = 0;
	len += pack_devicemode(info->devmode, buf+len, buflen-len);

	len += pack_values( &info->data, buf+len, buflen-len );

	if (buflen < len) {
		char *tb;

		tb = (char *)SMB_REALLOC(buf, len);
		if (!tb) {
			DEBUG(0, ("tdb_update_driver_init: failed to enlarge buffer!\n"));
			ret = -1;
			goto done;
		}
		else
			buf = tb;
		buflen = len;
		goto again;
	}

	slprintf(key, sizeof(key)-1, "%s%s", DRIVER_INIT_PREFIX, info->drivername);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = tdb_store(tdb_drivers, kbuf, dbuf, TDB_REPLACE);

done:
	SAFE_FREE(buf);

	return ret;
}

static WERROR tdb_get_driver_init(const char *drivername, NT_PRINTER_INFO_LEVEL_2 **info_ptr )
{
	int                     len = 0;
	pstring                 key;
	TDB_DATA                kbuf, dbuf;
	NT_PRINTER_INFO_LEVEL_2 info;

	ZERO_STRUCT(info);

	slprintf(key, sizeof(key)-1, "%s%s", DRIVER_INIT_PREFIX, drivername);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb_drivers, kbuf);
	if (!dbuf.dptr)
		return WERR_UNKNOWN_PRINTER_DRIVER;

	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);

	len += unpack_values(&info.data, dbuf.dptr+len, dbuf.dsize-len);
	
	SAFE_FREE(dbuf.dptr);

	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));

	return WERR_OK;
}

static BOOL tdb_printerdb_close(void)
{
	return True;
}

static struct printerdb_methods tdb_methods = {

	tdb_get_last_update,
	tdb_set_last_update,
	tdb_printerdb_init, 
	tdb_get_c_setprinter,
	tdb_update_c_setprinter,
	tdb_get_forms, 
	tdb_write_forms,
	tdb_del_form,
	tdb_get_drivers,
	tdb_add_driver,
	tdb_get_driver,
	tdb_del_driver,
	tdb_del_driver_init,
	tdb_get_printers,
	tdb_get_printer,
	tdb_update_printer,
	tdb_del_printer,
	tdb_get_secdesc,
	tdb_set_secdesc,
	tdb_get_driver_init,
	tdb_update_driver_init,
	tdb_printerdb_close
};


NTSTATUS printerdb_tdb_init(void)
{
	return smb_register_printerdb(SMB_PRINTERDB_INTERFACE_VERSION, "tdb", &tdb_methods);
}
