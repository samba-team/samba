#include "admin_locl.h"

RCSID("$Id$");

int main(int argc, char **argv)
{
    HDB *db;
    hdb_entry ent;
    krb5_context context;
    int err;
    int i;
    krb5_keytab kid;
    krb5_keytab_entry key_entry;
    char *p;
    
    krb5_init_context(&context);
    err = hdb_open(context, &db, argv[2], O_RDONLY, 0600);
    if(err){
	fprintf(stderr, "%s\n", krb5_get_err_text(context, err));
	exit(1);
    }

    err = krb5_parse_name (context, argv[1], &ent.principal);
    if (err) {
      fprintf (stderr, "%s\n", krb5_get_err_text(context, err));
      exit(1);
    }

    err = db->fetch(context, db, &ent);
    if (err) {
      fprintf (stderr, "%s\n", krb5_get_err_text(context, err));
      exit(1);
    }

    krb5_copy_principal (context, ent.principal, &key_entry.principal);
    key_entry.vno = ent.kvno;
    key_entry.keyblock.keytype = ent.keyblock.keytype;
    key_entry.keyblock.contents.length = 0;
    krb5_data_copy(&key_entry.keyblock.contents,
		   ent.keyblock.contents.data,
		   ent.keyblock.contents.length);

    err = krb5_kt_default (context, &kid);
    if (err) {
      fprintf (stderr, "%s\n", krb5_get_err_text(context, err));
      exit(1);
    }

    err = krb5_kt_add_entry(context,
			    kid,
			    &key_entry);
    if (err) {
      fprintf (stderr, "%s\n", krb5_get_err_text(context, err));
      exit(1);
    }
    db->close (context, db);
}
