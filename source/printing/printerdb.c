#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PRINTERDB

struct printerdb_function_entry {
	const char *name;
	struct printerdb_methods *methods;
	struct printerdb_function_entry *prev,*next;
};

static struct printerdb_function_entry *backends = NULL;

static struct printerdb_methods *cache_map;
static struct printerdb_methods *remote_map;


/**********************************************************************
 Get printerdb methods. Don't allow tdb to be a remote method.
**********************************************************************/

static struct printerdb_methods *get_methods(const char *name, BOOL cache_method)
{
	struct printerdb_function_entry *entry = backends;

	for(entry = backends; entry; entry = entry->next) {
		if (!cache_method && strequal(entry->name, "tdb"))
			continue; /* tdb is only cache method. */
		if (strequal(entry->name, name))
			return entry->methods;
	}

	return NULL;
}

/**********************************************************************
 Allow a module to register itself as a method.
**********************************************************************/

NTSTATUS smb_register_printerdb(int version, const char *name, struct printerdb_methods *methods)
{
	struct printerdb_function_entry *entry;

 	if ((version != SMB_PRINTERDB_INTERFACE_VERSION)) {
		DEBUG(0, ("smb_register_printerdb: Failed to register printerdb module.\n"
		          "The module was compiled against SMB_PRINTERDB_INTERFACE_VERSION %d,\n"
		          "current SMB_PRINTERDB_INTERFACE_VERSION is %d.\n"
		          "Please recompile against the current version of samba!\n",  
			  version, SMB_PRINTERDB_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
  	}

	if (!name || !name[0] || !methods) {
		DEBUG(0,("smb_register_printerdb: called with NULL pointer or empty name!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (get_methods(name, False)) {
		DEBUG(0,("smb_register_printerdb: printerdb module %s already registered!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = SMB_MALLOC(sizeof(struct printerdb_function_entry));
	entry->name = SMB_STRDUP(name);
	entry->methods = methods;

	DLIST_ADD(backends, entry);
	DEBUGADD(5, ("smb_register_printerdb: Successfully added printerdb backend '%s'\n", name));
	return NT_STATUS_OK;
}

/**********************************************************************
 Initialise printerdb cache and a remote backend (if configured).
**********************************************************************/

BOOL printerdb_init(const char **remote_backend)
{
	if (!backends)
		static_init_printerdb;

	if (!cache_map) {
		cache_map = get_methods("tdb", True);

		if (!cache_map) {
			DEBUG(0, ("printerdb_init: could not find tdb cache backend!\n"));
			return False;
		}
		
		if (!(cache_map->init( NULL ))) {
			DEBUG(0, ("printerdb_init: could not initialise tdb cache backend!\n"));
			return False;
		}
	}
	
	if ((remote_map == NULL) && (remote_backend != NULL) &&
	    (*remote_backend != NULL) && (**remote_backend != '\0'))  {
		char *rem_backend = smb_xstrdup(*remote_backend);
		fstring params = "";
		char *pparams;
		
		/* get any mode parameters passed in */
		
		if ( (pparams = strchr( rem_backend, ':' )) != NULL ) {
			*pparams = '\0';
			pparams++;
			fstrcpy( params, pparams );
		}
		
		DEBUG(3, ("printerdb_init: using '%s' as remote backend\n", rem_backend));
		
		if((remote_map = get_methods(rem_backend, False)) ||
		    (NT_STATUS_IS_OK(smb_probe_module("printerdb", rem_backend)) && 
		    (remote_map = get_methods(rem_backend, False)))) {
			remote_map->init(params);
		} else {
			DEBUG(0, ("printerdb_init: could not load remote backend '%s'\n", rem_backend));
			SAFE_FREE(rem_backend);
			return False;
		}
		SAFE_FREE(rem_backend);
	}

	return True;
}

/**************************************************************************
 Shutdown maps.
**************************************************************************/

BOOL printerdb_close(void)
{
	BOOL ret;

	ret = cache_map->close();
	if (!ret) {
		DEBUG(3, ("printerdb_close: failed to close local tdb cache!\n"));
	}
	cache_map = NULL;

	if (remote_map) {
		ret = remote_map->close();
		if (!ret) {
			DEBUG(3, ("printerdb_close: failed to close remote printerdb repository!\n"));
		}
		remote_map = NULL;
	}

	return ret;
}

/**************************************************************************
 Dump backend status.
**************************************************************************/

static BOOL printerdb_valid(struct printerdb_methods *printerdb, int tdb)
{
	time_t t = time(NULL);

	if (t < printerdb->get_last_update(tdb) + lp_printerdb_cache_time()) {
		DEBUG(10,("printerdb_valid: printerdb still valid (%d < %d)\n",
			(int)t, (int)printerdb->get_last_update(tdb) + lp_printerdb_cache_time()));
		return True;
	}

	DEBUG(3,("printerdb_valid: cache expired, asking remote backend\n"));

	return False;
}

void printerdb_status(void)
{
	cache_map->status();
	if (remote_map)
		remote_map->status();
}

uint32 printerdb_update_c_setprinter(BOOL initialize)
{
	if ( remote_map )
		return remote_map->update_c_setprinter( initialize );

	return cache_map->update_c_setprinter( initialize );
}

uint32 printerdb_get_c_setprinter(void)
{
	if ( remote_map )
		return remote_map->get_c_setprinter();

	return cache_map->get_c_setprinter();
}


uint32 printerdb_add_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver, const char *short_archi)
{
	int ret;
	if (remote_map) {
		ret = remote_map->add_driver(driver, short_archi);
		if (ret) return ret;
	}
	return cache_map->add_driver(driver, short_archi);
}

BOOL printerdb_set_driver_init( NT_PRINTER_INFO_LEVEL_2 *info_ptr )
{
	if ( remote_map )
		return remote_map->set_driver_init( info_ptr );

	return cache_map->set_driver_init( info_ptr );
}

uint32 printerdb_update_driver_init(NT_PRINTER_INFO_LEVEL_2 *info)
{
	if ( remote_map )
		return remote_map->update_driver_init( info );

	return cache_map->update_driver_init( info );
}


WERROR printerdb_get_secdesc(TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	return remote_map->get_secdesc(mem_ctx, printername, secdesc_ctr);
#if 0
	WERROR err;
	if (remote_map) {
		err = remote_map->get_secdesc(mem_ctx, printername, secdesc_ctr);
		if (!W_ERROR_IS_OK(err)) return err;
	}
#endif
	return cache_map->get_secdesc(mem_ctx, printername, secdesc_ctr);
}

WERROR printerdb_set_secdesc(TALLOC_CTX *mem_ctx, const char *printername, SEC_DESC_BUF *secdesc_ctr)
{
	return remote_map->set_secdesc(mem_ctx, printername, secdesc_ctr);
#if 0
	WERROR err;
	if (remote_map) {
		err = remote_map->set_secdesc(mem_ctx, printername, secdesc_ctr);
		if (!W_ERROR_IS_OK(err)) return err;
	}
#endif
	return cache_map->set_secdesc(mem_ctx, printername, secdesc_ctr);
}

BOOL printerdb_del_driver(const char *short_archi, int version, const char *drivername)
{
	BOOL ret;
	if (remote_map) {
		ret = remote_map->del_driver(short_archi, version, drivername);
		if (ret) 
			return ret;
	}
	return cache_map->del_driver(short_archi, version, drivername);
}

/* del driver_init */
BOOL printerdb_del_driver_init(const char *drivername)
{
	BOOL ret;
	if (remote_map) {
		ret = remote_map->del_driver_init(drivername);
		if (ret)
			return ret;
	}
	return cache_map->del_driver_init(drivername);
}

/* del printer */
WERROR printerdb_del_printer(const char *sharename)
{
	WERROR err;
	if (remote_map) {
		err = remote_map->del_printer(sharename);
		if (!W_ERROR_IS_OK(err)) 
			return err;
	}
	return cache_map->del_printer(sharename);
}

/* del form */
BOOL printerdb_del_form(char *del_name, WERROR *err)
{
	BOOL ret;
	if (remote_map) {
		ret = remote_map->del_form(del_name, err);
		if (ret)
			return ret;
	}
	return cache_map->del_form(del_name, err);
}

/* get forms */
int printerdb_get_forms(nt_forms_struct **list)
{
	int in_forms, out_forms;

	if (printerdb_valid(cache_map, TDB_FORMS))
		goto cache;
	
	if (remote_map) {
		in_forms = remote_map->get_forms(list);
		out_forms = cache_map->write_forms(list, in_forms);
		if (in_forms != out_forms) {
			DEBUG(0,("printerdb_get_forms: failed\n"));
			return 0;
		}
		return out_forms;
	}
cache:
	return cache_map->get_forms(list);
}

/* write forms */
int printerdb_write_forms(nt_forms_struct **list, int num_forms)
{
	int ret;
	if (remote_map) {
		ret = remote_map->write_forms(list, num_forms);
		if (!ret) 
			return ret;
	}
	return cache_map->write_forms(list, num_forms);
}

/* get drivers */
int printerdb_get_drivers(fstring **list, 
			  const char *short_archi, 
			  uint32 version)
{
	int num_drivers;
	int i = 0;

	if (printerdb_valid(cache_map, TDB_DRIVERS))
		goto cache;

	if (remote_map) {
		num_drivers = remote_map->get_drivers(list, short_archi, version);
		for (i=0; i < num_drivers; i++) {
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver = NULL;
			remote_map->get_driver(&driver, (*list)[i], short_archi, version);
			cache_map->add_driver(driver, short_archi);
		}
		return num_drivers;
	}
cache:
	return cache_map->get_drivers(list, short_archi, version);
}

/* get driver3 */
WERROR printerdb_get_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, 
			    fstring drivername, 
			    const char *arch, 
			    uint32 version)
{
	WERROR err;
	uint32 ret;

	if (printerdb_valid(cache_map, TDB_DRIVERS))
		goto cache;

	if (remote_map) {
		return remote_map->get_driver(info_ptr, drivername, arch, version);
		if (!W_ERROR_IS_OK(err)) return err;
		ret = cache_map->add_driver(*info_ptr, arch);
		if (ret)
			return WERR_UNKNOWN_PRINTER_DRIVER;
		return WERR_OK;
	}
cache:
	return cache_map->get_driver(info_ptr, drivername, arch, version);
}

/* update printer */
WERROR printerdb_update_printer(NT_PRINTER_INFO_LEVEL_2 *info)
{
	return remote_map->update_printer(info);
#if 0
	WERROR err;
	if (remote_map) {
		err = remote_map->update_printer(info);
		if (!W_ERROR_IS_OK(err)) return err;
	}
#endif
	return cache_map->update_printer(info);
}

/* get printer */
WERROR printerdb_get_printer(NT_PRINTER_INFO_LEVEL_2 **info_ptr, const char *sharename)
{
	return remote_map->get_printer(info_ptr, sharename);
	WERROR err;
	if (printerdb_valid(cache_map, TDB_PRINTERS))
		goto cache;
	
	if (remote_map) {
		err = remote_map->get_printer(info_ptr, sharename);
		if (!W_ERROR_IS_OK(err)) 
			return err;
		cache_map->update_printer(*info_ptr);
	}

cache:
	return cache_map->get_printer(info_ptr, sharename);
}
