#include "includes.h"

#if 0
struct ldap_printerldap_state {
	struct smbldap_state *smbldap_state;
	TALLOC_CTX *mem_ctx;
};

static struct ldap_printerldap_state ldap_state;
#endif

static BOOL ldap_printerdb_init( char *params )
{
	return True;
//	return init_ldap_conn();
};

uint32 ldap_get_c_setprinter(void)
{
	return 0;
}

uint32 ldap_update_c_setprinter(BOOL initialize)
{
	return 0;
}

int ldap_get_forms(nt_forms_struct **list)
{
	return 0;
}

int ldap_write_forms(nt_forms_struct **list, int num_forms)
{
	return 0;
}

time_t ldap_get_last_update(int tdb)
{
	return 0;
}

BOOL ldap_set_last_update(time_t update, int tdb)
{
	return True;
}

BOOL ldap_del_form(char *del_name, WERROR *ret)
{
	return True;
}

int ldap_get_drivers(fstring **list, 
		     const char *short_archi, 
		     uint32 version)
{
	return 0;
}

uint32 ldap_add_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver, 
		       const char *short_archi)
{
	return 0;
}

WERROR ldap_get_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, 
		       fstring drivername, 
		       const char *arch, 
		       uint32 version)
{

	become_root();
//	info_ptr = prldap_get_driver(drivername, arch, version);
	unbecome_root();
	if (!info_ptr) 
		return WERR_UNKNOWN_PRINTER_DRIVER;

	return WERR_OK;
}

static struct printerdb_methods ldap_methods = {
	ldap_get_last_update,
	ldap_set_last_update,
	ldap_printerdb_init, 
	ldap_get_c_setprinter, 
	ldap_update_c_setprinter, 
	ldap_get_forms, 
	ldap_write_forms,
	ldap_del_form, 
	ldap_get_drivers, 
	ldap_add_driver, 
	ldap_get_driver, /*
	ldap_set_driver_init_2,
	ldap_update_driver_init_2,
	ldap_del_driver,
	ldap_del_driver_all,
	ldap_get_printer_2,
	ldap_update_printer_2,
	ldap_del_printer,
	ldap_getsec,
	ldap_setsec,
	ldap_pack_values,
	ldap_unpack_values,
	ldap_pack_devicemode,
	ldap_unpack_devicemode,
	ldap_printerdb_close, */
};


NTSTATUS printerdb_ldap_init(void)
{
	return smb_register_printerdb(SMB_PRINTERDB_INTERFACE_VERSION, "ldap", &ldap_methods);
}

