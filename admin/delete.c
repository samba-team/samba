#include "admin_locl.h"

RCSID("$Id$");

void
del_entry(int argc, char **argv)
{
    HDB *db;
    int err;
    hdb_entry ent;
    
    if(argc != 2){
	warnx("Usage: del_entry principal");
	return;
    }
	
    krb5_parse_name(context, argv[1], &ent.principal);
    
    if((err = hdb_open(context, &db, database, O_RDWR, 0600))){
	warnx("hdb_open: %s", krb5_get_err_text(context, err));
	return;
    }
    
    err = db->delete(context, db, &ent);
    
    switch(err){
    case 0: 
	break;
    default:
	warnx("delete: %s", krb5_get_err_text(context, err));;
	break;
    }
    memset(&ent, 0, sizeof(ent));
    db->close(context, db);
}
