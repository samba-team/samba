#include "kadm5_locl.h"

kadm5_ret_t
_kadm5_set_keys(kadm5_server_context *context,
		hdb_entry *ent, const char *password)
{
    int i;
    krb5_data salt;
    kadm5_ret_t ret;
    Key *key;
    krb5_get_salt(ent->principal, &salt);
    for(i = 0; i < ent->keys.len; i++){
	key = &ent->keys.val[i];
	if(key->salt && key->salt->type == hdb_pw_salt && 
	   key->salt->salt.length != 0){
	    /* zap old salt, but not v4 salts */
	    free_Salt(key->salt);
	    key->salt = NULL;
	}
	krb5_free_keyblock(context->context, &key->key);
	ret = krb5_string_to_key(password, 
				 key->salt ? &key->salt->salt : &salt,
				 key->key.keytype,
				 &key->key);
	if(ret)
	    break;
    }
    ent->kvno++;
    krb5_data_free(&salt);
    return ret;
}
