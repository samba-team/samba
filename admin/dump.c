#include "admin_locl.h"

RCSID("$Id$");

char *
time2str(time_t t)
{
    static char s[32];
    struct tm *tm;
    tm = gmtime(&t);
    strftime(s, sizeof(s), "%Y%m%d%H%M%S", tm);
    return s;
}

char *
key2str(krb5_keyblock *key)
{
    static char *s;
    unsigned char *p;
    int i;
    if(s)
	free(s);
    s = malloc(key->keyvalue.length*2+10);
    sprintf(s, "%d:", key->keytype);
    p = (unsigned char*)key->keyvalue.data;
    for(i = 0; i < key->keyvalue.length; i++)
	sprintf(s + strlen(s), "%02x", p[i]);
    return s;
}

void
dump(int argc, char **argv)
{
    HDB *db;
    hdb_entry ent;
    int err;
    int i;
    FILE *f;

    if(argc < 2)
	f = stdout;
    else
	f = fopen(argv[1], "w");
    

    err = hdb_open(context, &db, database, O_RDONLY, 0600);
    if(err){
	warnx("hdb_open: %s", krb5_get_err_text(context, err));
	if(f != stdout)
	    fclose(f);
	return;
    }
    err = db->firstkey(context, db, &ent);
    while(err == 0){
	char *p;
	krb5_unparse_name(context, ent.principal, &p);
	fprintf(f, "%s ", p);
	free(p);
	fprintf(f, "%d:%s", ent.kvno, key2str(&ent.keyblock));
	fprintf(f, " %d %d %s", 
		ent.max_life, 
		ent.max_renew, 
		time2str(ent.last_change));
	krb5_unparse_name(context, ent.changed_by, &p);
	fprintf(f, " %s %s %d\n", 
		p,
		time2str(ent.expires),
		ent.flags.i);
	free(p);
	hdb_free_entry(context, &ent);
	err = db->nextkey(context, db, &ent);
    }
    if(f != stdout)
	fclose(f);
    db->close(context, db);
}
