#include "kdc_locl.h"

RCSID("$Id$");

int main(int argc, char **argv)
{
    FILE *f;
    DB *db;
    krb5_context context;
    char s[1024];
    char *p;
    int line;
    unsigned char key_buf[1024];
    unsigned char *q;
    unsigned char value_buf[1024];
    krb5_keyblock keyblock;
    DBT key, value;
    int err;
    int i;
    krb5_storage *sp;

    struct entry e;

    krb5_principal princ;
    
    krb5_init_context(&context);
    f = fopen(argv[1], "r");
    db = dbopen(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600, DB_BTREE, NULL);
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

	err = krb5_parse_name(context, e.principal, &princ);
	if(err){
	    fprintf(stderr, "%s:%s:%s (%s)\n", 
		    argv[1], 
		    line,
		    krb5_get_err_text(context, err),
		    e.principal);
	    continue;
	}
	
	sp = krb5_storage_from_mem(key_buf, sizeof(key_buf));
	princ->type = 0;
	krb5_store_principal(sp, princ);
	key.data = key_buf;
	key.size = sp->seek(sp, 0, SEEK_CUR);
	krb5_storage_free(sp);

	keyblock.keytype = KEYTYPE_DES;
	keyblock.contents.data = malloc(strlen(e.key)/2+1);
	for(i = 0; i < strlen(e.key); i += 2){
	    sscanf(e.key + i, "%2x", 
		   (unsigned char *)keyblock.contents.data + (i/2));
	}
	keyblock.contents.length = i / 2;
	sp = krb5_storage_from_mem(value_buf, sizeof(value_buf));
	krb5_store_keyblock(sp, keyblock);
	krb5_store_int32(sp, atoi(e.kvno));
	krb5_store_int32(sp, atoi(e.max_life));
	krb5_store_int32(sp, atoi(e.max_renew));
	value.data = value_buf;
	value.size = sp->seek(sp, 0, SEEK_CUR);
	db->put(db, &key, &value, 0);
	krb5_storage_free(sp);
    }
    db->close(db);
}
