#include "admin_locl.h"

RCSID("$Id$");

void
get_entry(int argc, char **argv)
{
    HDB *db;
    int err;
    hdb_entry ent;
    
    if(argc != 2){
	fprintf(stderr, "Usage: get_entry principal\n");
	return;
    }
	
    krb5_parse_name(context, argv[1], &ent.principal);
    
    if((err = hdb_open(context, &db, database, O_RDONLY, 0600))){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, err));
	return;
    }
    
    err = db->fetch(context, db, &ent);
    
    switch(err){
    case KRB5_HDB_NOENTRY:
	fprintf(stderr, "Entry not found in database\n");
	break;
    case 0: {
	char *name;
	krb5_unparse_name(context, ent.principal, &name);
	printf("Principal: %s\n", name);
	free(name);
	printf("Max ticket life: %d\n", ent.max_life);
	printf("Max renewable ticket life: %d\n", ent.max_renew);
	printf("Key type: ");
	if(ent.keyblock.keytype == KEYTYPE_DES)
	    printf("DES");
	else
	    printf("%d", (int)ent.keyblock.keytype);
	printf("\tKvno: %d\n", ent.kvno);
	break;
    }
    default:
	fprintf(stderr, "dbget: %s\n", krb5_get_err_text(context, err));;
	break;
    }
    memset(&ent, 0, sizeof(ent));
    db->close(context, db);
}
