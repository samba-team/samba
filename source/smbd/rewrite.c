#include "includes.h"
#include "dynconfig.h"


/*
 * initialize an smb process. Guaranteed to be called only once per
 * smbd instance (so it can assume it is starting from scratch, and
 * delete temporary files etc)
 */
void smbd_process_init(void)
{
	/* possibly reload the services file. */
	reload_services(NULL, True);

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) == 0)
			DEBUG(2,("Changed root to %s\n", lp_rootdir()));
	}

	service_cleanup_tmp_files();
}

void init_subsystems(void)
{
	/* Do *not* remove this, until you have removed
	 * passdb/secrets.c, and proved that Samba still builds... */

	/* Setup the SECRETS subsystem */
	if (!secrets_init()) {
		exit(1);
	}

	smbd_init_subsystems;
}

/****************************************************************************
 Reload the services file.
**************************************************************************/
BOOL reload_services(struct smbsrv_connection *smb, BOOL test)
{
	BOOL ret;
	
	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname,lp_configfile());
		if (file_exist(fname, NULL) &&
		    !strcsequal(fname, dyn_CONFIGFILE)) {
			pstrcpy(dyn_CONFIGFILE, fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	ret = lp_load(dyn_CONFIGFILE, False, False, True);

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(smb, True);

	reopen_logs();

	load_interfaces();

	return(ret);
}

