#include "admin_locl.h"

RCSID("$Id$");

time_t
get_time(const char *prompt, time_t def)
{
    char buf[1024];
    int tmp;
    
    while(1){
	if(def == 0)
	    printf("%s: [infinite] ", prompt);
	else
	    printf("%s: [%d] ", prompt, def);
	fgets(buf, sizeof(buf), stdin);
	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = 0;
	if(buf[0] == 0)
	    return def;
	if(strncmp(buf, "infinite", strlen(buf)) == 0)
	    return 0;
	if(sscanf(buf, "%d", &tmp) == 1)
	    return tmp;
	printf("Please specify a number\n");
    }
}


void
init(int argc, char **argv)
{
    HDB *db;
    char s[1024];
    char *p;
    int line;
    int err;
    int i;

    int tmp;
    int default_life = 86400;
    int default_renew = 5 * 86400;
    int max_life = 0;
    int max_renew = 0;
    
    hdb_entry ent;

    err = hdb_open(context, &db, database, O_RDWR | O_CREAT, 0600);
    if(err){
	warnx("hdb_open: %s", krb5_get_err_text(context, err));
	return;
    }
    memset(&ent, 0, sizeof(ent));
    for(i = 1; i < argc; i++){
	krb5_build_principal(context, &ent.principal, 
			     strlen(argv[i]), argv[i], 
			     "krbtgt",
			     argv[i],
			     NULL);
	err = db->fetch(context, db, &ent);
	switch(err){
	case 0:
	    fprintf(stderr, "Entry already exists\n");
	    krb5_free_principal(context, ent.principal);
	    continue;
	case KRB5_HDB_NOENTRY:
	    break;
	default:
	    warnx("hdb_fetch: %s", krb5_get_err_text(context, err));
	    db->close(context, db);
	    return;
	}
	
	max_life = get_time("Realm max ticket life", max_life);
	max_renew = get_time("Realm max renewable ticket life", max_renew);
	default_life = get_time("Default ticket life", default_life);
	default_renew = get_time("Default renewable ticket life", 
				 default_renew);
	
	
	/* Create `krbtgt/REALM' */
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.length = 8;
	ent.keyblock.keyvalue.data = malloc(ent.keyblock.keyvalue.length);
	des_new_random_key(ent.keyblock.keyvalue.data);
	ent.kvno = 1;
	ent.max_life = max_life;
	ent.max_renew = max_renew;
	ent.last_change = time(NULL);
	krb5_build_principal(context, &ent.changed_by, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.expires = 0;
	ent.u.s.forwardable = 1;
	ent.u.s.renewable = 1;
	ent.u.s.server = 1;
	db->store(context, db, &ent);
	hdb_free_entry(context, &ent);

	/* Create `default' */
	memset(&ent, 0, sizeof(ent));
	krb5_build_principal(context, &ent.principal,
			     strlen(argv[i]), argv[i],
			     "default",
			     NULL);
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.length = 0;
	ent.keyblock.keyvalue.data = NULL;
	ent.kvno = 1;
	ent.max_life = default_life;
	ent.max_renew = default_renew;
	ent.last_change = time(NULL);
	krb5_build_principal(context, &ent.changed_by, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.expires = 0;
	ent.u.s.locked = 1;
	db->store(context, db, &ent);
	hdb_free_entry(context, &ent);
    }
    db->close(context, db);
}
