#include "admin_locl.h"

RCSID("$Id$");

struct entry{
    char *principal;
    char *key;
    char *kvno;
    char *max_life;
    char *max_renew;
};

static void
doit(char *filename, int merge)
{
    FILE *f;
    HDB *db;
    char s[1024];
    char *p;
    int line;
    int err;
    int i;
    int flags = O_RDWR;

    struct entry e;
    hdb_entry ent;

    f = fopen(filename, "r");
    if(f == NULL){
	fprintf(stderr, "%s: %s\n", filename, strerror(errno));
	return;
    }
    if(!merge)
	flags |= O_CREAT | O_TRUNC;
    err = hdb_open(context, &db, database, flags, 0600);
    if(err){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, err));
	fclose(f);
	return;
    }
    line = 0;
    while(fgets(s, sizeof(s), f)){
	line++;
	e.principal = s;
	for(p = s; *p; p++){
	    if(*p == '\\')
		p++;
	    else if(isspace(*p)) {
		*p = 0;
		break;
	    }
	}
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.key = p;
	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.kvno = p;

	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.max_life = p;

	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	e.max_renew = p;
	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;

	err = krb5_parse_name(context, e.principal, &ent.principal);
	if(err){
	    fprintf(stderr, "%s:%s:%s (%s)\n", 
		    filename, 
		    line,
		    krb5_get_err_text(context, err),
		    e.principal);
	    continue;
	}
	
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.data = malloc(strlen(e.key)/2+1);
	for(i = 1; i < strlen(e.key) - 1; i += 2){
	    unsigned tmp;
	    sscanf(e.key + i, "%2x", &tmp);
	    ((unsigned char *)ent.keyblock.keyvalue.data)[i/2] = tmp;
	}
	ent.keyblock.keyvalue.length = i / 2;
	ent.kvno = atoi(e.kvno);
	ent.max_life = atoi(e.max_life);
	ent.max_renew = atoi(e.max_renew);
	krb5_build_principal(context, &ent.changed_by,
			     0,
			     ""
			     "kadmin",
			     NULL);
	db->store(context, db, &ent);
	hdb_free_entry (context, &ent);
    }
    db->close(context, db);
    fclose(f);
}

void
load(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: load filename\n");
	return;
    }
    doit(argv[1], 0);
}

void
merge(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: merge filename\n");
	return;
    }
    doit(argv[1], 1);
}
