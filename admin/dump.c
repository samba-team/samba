#include "kdc_locl.h"

RCSID("$Id$");

int main(int argc, char **argv)
{
    HDB *db;
    hdb_entry ent;
    krb5_context context;
    int err;
    int i;

    char *p;
    
    
    krb5_init_context(&context);
    err = hdb_open(context, &db, argv[1], O_RDONLY, 0600);
    if(err){
	fprintf(stderr, "%s\n", krb5_get_err_text(context, err));
	exit(1);
    }
    err = db->firstkey(context, db, &ent);
    while(err == 0){
	krb5_unparse_name(context, ent.principal, &p);
	printf("%s ", p);
	for(i = 0; i < ent.keyblock.contents.length; i++)
	    printf("%02x", (int)((unsigned char*)ent.keyblock.contents.data)[i]);
	printf(" ");
	printf("%d %d %d\n", ent.kvno, ent.max_life, ent.max_renew);
	free(p);
	err = db->nextkey(context, db, &ent);
    }
}
