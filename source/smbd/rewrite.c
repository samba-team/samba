#include "includes.h"

/*

 this is a set of temporary stub functions used during the core smbd rewrite.
 This file will need to go away before the rewrite is complete
*/

void mangle_reset_cache(void) 
{}

void reset_stat_cache(void)
{}


BOOL set_current_service(void *conn, BOOL x)
{ return True; }

void change_to_root_user(void)
{}

void load_printers(void)
{}

void file_init(void)
{}

BOOL init_oplocks(void)
{ return True; }

BOOL init_change_notify(void)
{ return True; }


BOOL pcap_printername_ok(const char *service, const char *foo)
{ return True; }

BOOL share_access_check(struct smbsrv_request *req, struct smbsrv_tcon *tcon, int snum, uint32_t desired_access)
{ return True; }

BOOL init_names(void)
{ return True; }

/*
 * initialize an smb process
 */
void smbd_process_init(void)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("smbd_process_init talloc");
	if (!mem_ctx) {
		DEBUG(0,("smbd_process_init: ERROR: No memory\n"));
		exit(1);
	}

	/* possibly reload the services file. */
	reload_services(NULL, True);

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) == 0)
			DEBUG(2,("Changed root to %s\n", lp_rootdir()));
	}

	/* Setup oplocks */
	if (!init_oplocks())
		exit(1);
	
	/* Setup change notify */
	if (!init_change_notify())
		exit(1);

	talloc_destroy(mem_ctx);
}

void init_subsystems(void)
{
	/* Setup the PROCESS_MODEL subsystem */
	if (!process_model_init())
		exit(1);

	/* Setup the SERVER_SERVICE subsystem */
	if (!server_service_init())
		exit(1);

	/* Setup the AUTH subsystem */
	if (!auth_init())
		exit(1);

	/* Setup the NTVFS subsystem */
	if (!ntvfs_init())
		exit(1);

	/* Setup the DCERPC subsystem */
	if (!subsystem_dcerpc_init())
		exit(1);

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

	if (smb) {
		lp_killunused(smb, conn_snum_used);
	}
	
	ret = lp_load(dyn_CONFIGFILE, False, False, True);

	load_printers();

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(smb, True);

	reopen_logs();

	load_interfaces();

	mangle_reset_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,True);

	return(ret);
}

