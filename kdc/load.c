#include "kdc_locl.h"

RCSID("$Id$");

struct entry{
    char *principal;
    char *key;
    char *kvno;
    char *max_life;
    char *max_renew;
};

int main(int argc, char **argv)
{
    FILE *f;
    HDB *db;
    krb5_context context;
    char s[1024];
    char *p;
    int line;
    int err;
    int i;

    struct entry e;
    hdb_entry ent;

    
    krb5_init_context(&context);
    f = fopen(argv[1], "r");
    err = hdb_open(context, &db, argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600);
    if(err){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, err));
	exit(1);
    }
    line = 0;
    while(fgets(s, sizeof(s), f)){
	line++;
	e.principal = s;
	for(p = s; *p; p++){
	    if(*p == '\\')
		p++;
	    else if(isspace(*p)) {
		*p == 0;
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
		    argv[1], 
		    line,
		    krb5_get_err_text(context, err),
		    e.principal);
	    continue;
	}
	
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.contents.data = malloc(strlen(e.key)/2+1);
	for(i = 0; i < strlen(e.key); i += 2){
	    sscanf(e.key + i, "%2x", 
		   (unsigned char *)ent.keyblock.contents.data + (i/2));
	}
	ent.keyblock.contents.length = i / 2;
	ent.kvno = atoi(e.kvno);
	ent.max_life = atoi(e.max_life);
	ent.max_renew = atoi(e.max_renew);
	db->store(context, db, &ent);
    }
    db->close(context, db);
}
