#include "kdc_locl.h"

RCSID("$Id$");

int main(int argc, char **argv)
{
    HDB *db;
    krb5_context context;
    int err;

    hdb_entry ent;
    
    krb5_init_context(&context);
    while (1){
	int32_t tmp;
	char buf[1024];
	
	printf("Principal: ");
	fgets(buf, sizeof(buf), stdin);
	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = 0;
	if(buf[0] == 0)
	    break;
	krb5_parse_name(context, buf, &ent.principal);
	
	hdb_open(context, &db, argv[1], O_RDWR, 0600);
	
	err = db->fetch(context, db, &ent);

	switch(err){
	case KRB5_HDB_NOENTRY:
	    ent.kvno = 0;
	    ent.max_life = 86400;
	    ent.max_renew = 5 * 86400;
	    break;
	case 0:
	    break;
	default:
	    fprintf(stderr, "dbget: %s\n", krb5_get_err_text(context, err));;
	    exit(1);
	}
	printf("Max ticket life [%d]: ", ent.max_life);
	fgets(buf, sizeof(buf), stdin);
	if(sscanf(buf, "%d", &tmp) == 1)
	    ent.max_life = tmp;
	printf("Max renewable ticket [%d]: ", ent.max_renew);
	fgets(buf, sizeof(buf), stdin);
	if(sscanf(buf, "%d", &tmp) == 1)
	    ent.max_renew = tmp;
	des_read_pw_string(buf, sizeof(buf), "Password:", 1);
	{
	    krb5_data salt;
	    memset(&salt, 0, sizeof(salt));
	    krb5_get_salt(ent.principal, &salt);
	    krb5_string_to_key(buf, &salt, &ent.keyblock);
	}
	ent.kvno++;
	{
	    err = db->store(context, db, &ent);
	    if(err == -1){
		perror("dbput");
		exit(1);
	    }
	}
	db->close(context, db);
    }
    return 0;
}
