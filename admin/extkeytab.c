#include "admin_locl.h"

RCSID("$Id$");

void 
ext_keytab(int argc, char **argv)
{
    HDB *db;
    hdb_entry ent;
    int ret;
    int i;
    krb5_keytab kid;
    krb5_keytab_entry key_entry;
    char *p;
    
    if(argc != 2){
	warnx("Usage: ext_keytab principal\n");
	return;
    }
	
    
    ret = hdb_open(context, &db, database, O_RDONLY, 0600);
    if(ret){
	warnx("%s", krb5_get_err_text(context, ret));
	return;
    }

    ret = krb5_parse_name (context, argv[1], &ent.principal);
    if (ret) {
	warnx("%s", krb5_get_err_text(context, ret));
	goto cleanup1;
    }

    ret = db->fetch(context, db, &ent);
    if (ret) {
	warnx ("%s", krb5_get_err_text(context, ret));
	krb5_free_principal (context, ent.principal);
	goto cleanup1;
    }

    krb5_copy_principal (context, ent.principal, &key_entry.principal);
    key_entry.vno = ent.kvno;
    key_entry.keyblock.keytype = ent.keyblock.keytype;
    key_entry.keyblock.keyvalue.length = 0;
    krb5_data_copy(&key_entry.keyblock.keyvalue,
		   ent.keyblock.keyvalue.data,
		   ent.keyblock.keyvalue.length);

    ret = krb5_kt_default (context, &kid);
    if (ret) {
	warnx("%s", krb5_get_err_text(context, ret));
	goto cleanup2;
    }

    ret = krb5_kt_add_entry(context,
			    kid,
			    &key_entry);
    /* XXX - krb5_kt_free_entry? */

    if (ret) {
	warnx("%s", krb5_get_err_text(context, ret));
    }
    krb5_kt_close (context, kid);
cleanup2:
    krb5_free_principal (context, key_entry.principal);
    krb5_free_keyblock (context, &key_entry.keyblock);
    hdb_free_entry (context, &ent);
cleanup1:
    db->close (context, db);
}
