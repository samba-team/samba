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

BOOL namecache_enable(void)
{ return True; }

BOOL share_info_db_init(void)
{ return True; }

BOOL init_registry(void)
{ return True; }

BOOL share_access_check(struct request_context *req, struct tcon_context *conn, int snum, uint32_t desired_access)
{ return True; }

BOOL init_names(void)
{ return True; }

