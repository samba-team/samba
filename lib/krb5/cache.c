#include "krb5_locl.h"

/* XXX shouldn't be here */

void
krb5_free_ccache(krb5_context context,
		 krb5_ccache val)
{
    free(((krb5_fcache*)(val->data.data))->filename);
    krb5_data_free (&val->data);
    free(val);
}


krb5_error_code
krb5_cc_resolve(krb5_context context,
		const char *residual,
		krb5_ccache *id)
{
    krb5_ccache p;
    krb5_fcache *f;

    if(strncmp(residual, "FILE:", 5)){
	return KRB5_CC_UNKNOWN_TYPE;
    }

    p = ALLOC(1, krb5_ccache_data);
  
    if(!p)
	return ENOMEM;
  
    f = ALLOC(1, krb5_fcache);
  
    if(!f){
	free(p);
	return ENOMEM;
    }
    f->filename = strdup(residual + 5);
    if(!f->filename){
	free(f);
	free(p);
	return ENOMEM;
    }
  
    p->data.data = f;
    p->data.length = sizeof(*f);
    p->type = 1;

    *id = p;
  
    return 0;
}

#if 0
krb5_error_code
krb5_cc_gen_new(krb5_context context,
		krb5_cc_ops *ops,
		krb5_ccache *id)
{
}

krb5_error_code
krb5_cc_register(krb5_context context,
		 krb5_cc_ops *ops,
		 krb5_boolean override)
{
}
#endif

char*
krb5_cc_get_name(krb5_context context,
		 krb5_ccache id)
{
    return ((krb5_fcache*)(id->data.data))->filename;
}

char*
krb5_cc_default_name(krb5_context context)
{
    static char name[1024];
    char *p;
    p = getenv("KRB5CCNAME");
    if(p)
	strcpy(name, p);
    else
	sprintf(name, "FILE:/tmp/krb5cc_%d", getuid());
    return name;
}




krb5_error_code
krb5_cc_default(krb5_context context,
		krb5_ccache *id)
{
    return krb5_cc_resolve(context, 
			   krb5_cc_default_name(context), 
			   id);
}

krb5_error_code
erase_file(const char *filename)
{
    int fd;
    off_t pos;
    char *p;

    fd = open(filename, O_RDWR);
    if(fd < 0)
	if(errno == ENOENT)
	    return 0;
	else
	    return errno;
    pos = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    p = (char*) malloc(pos);
    memset(p, 0, pos);
    write(fd, p, pos);
    free(p);
    close(fd);
    unlink(filename);
    return 0;
}

krb5_error_code
krb5_cc_initialize(krb5_context context,
		   krb5_ccache id,
		   krb5_principal primary_principal)
{
    int ret;
    int fd;

    char *f;

    f = krb5_cc_get_name(context, id);
  
    if((ret = erase_file(f)))
	return ret;
  
    fd = open(f, O_RDWR | O_CREAT | O_EXCL, 0600);
    if(fd == -1)
	return errno;
    {
	krb5_storage *sp;    
	sp = krb5_storage_from_fd(fd);
	krb5_store_int16(sp, 0x503);
	krb5_store_principal(sp, primary_principal);
	krb5_storage_free(sp);
    }
    close(fd);
	
    return 0;
}


krb5_error_code
krb5_cc_destroy(krb5_context context,
		krb5_ccache id)
{
    char *f;
    int ret;
    f = krb5_cc_get_name(context, id);

    ret = erase_file(f);
  
    krb5_free_ccache(context, id);
    return ret;
}

krb5_error_code
krb5_cc_close(krb5_context context,
	      krb5_ccache id)
{
    krb5_data_free (&id->data);
    free(id);
    return 0;
}

krb5_error_code
krb5_cc_store_cred(krb5_context context,
		   krb5_ccache id,
		   krb5_creds *creds)
{
    int fd;
    krb5_fcache *f;

    f = (krb5_fcache *)id->data.data;

    fd = open(f->filename, O_WRONLY | O_APPEND);
    if(fd < 0)
	return errno;
    {
	krb5_storage *sp;
	sp = krb5_storage_from_fd(fd);
	krb5_store_principal(sp, creds->client);
	krb5_store_principal(sp, creds->server);
	krb5_store_keyblock(sp, creds->session);
	krb5_store_times(sp, creds->times);
	krb5_store_int8(sp, 0); /* s/key */
	krb5_store_int32(sp, 0); /* flags */
	krb5_store_addrs(sp, creds->addresses);
	krb5_store_authdata(sp, creds->authdata);
	krb5_store_data(sp, creds->ticket);
	krb5_store_data(sp, creds->second_ticket);
	krb5_storage_free(sp);
    }
	close(fd);
    return 0; /* XXX */
}

static krb5_error_code
krb5_cc_read_cred (int fd,
		   krb5_creds *creds)
{
    int ret;
    int8_t dummy8;
    int32_t dummy32;
    krb5_storage *sp;

    sp = krb5_storage_from_fd(fd);

    ret = krb5_ret_principal (sp,  &creds->client);
    if(ret) return ret;
    ret = krb5_ret_principal (sp,  &creds->server);
    if(ret) return ret;
    ret = krb5_ret_keyblock (sp,  &creds->session);
    if(ret) return ret;
    ret = krb5_ret_times (sp,  &creds->times);
    if(ret) return ret;
    ret = krb5_ret_int8 (sp,  &dummy8);
    if(ret) return ret;
    ret = krb5_ret_int32 (sp,  &dummy32);
    if(ret) return ret;
    ret = krb5_ret_addrs (sp,  &creds->addresses);
    if(ret) return ret;
    ret = krb5_ret_authdata (sp,  &creds->authdata);
    if(ret) return ret;
    ret = krb5_ret_data (sp,  &creds->ticket);
    if(ret) return ret;
    ret = krb5_ret_data (sp,  &creds->second_ticket);
    krb5_storage_free(sp);
    return ret;
}

krb5_error_code
krb5_cc_retrieve_cred(krb5_context context,
		      krb5_ccache id,
		      krb5_flags whichfields,
		      krb5_creds *mcreds,
		      krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    krb5_cc_get_first(context, id, &cursor);
    while((ret = krb5_cc_get_next(context, id, creds, &cursor)) == 0){
	if(krb5_principal_compare(context, mcreds->server, creds->server)){
	    ret = 0;
	    break;
	}
    }
    krb5_cc_end_get(context, id, &cursor);
    return ret;
}

krb5_error_code
krb5_cc_get_principal(krb5_context context,
		      krb5_ccache id,
		      krb5_principal *principal)
{
    int fd;
    int16_t tag;
    krb5_storage *sp;

    fd = open(krb5_cc_get_name(context, id), O_RDONLY);
    if(fd < 0)
	return errno;
    sp = krb5_storage_from_fd(fd);
    krb5_ret_int16(sp, &tag);
    krb5_ret_principal(sp, principal);
    krb5_storage_free(sp);
    close(fd);
    return 0;
}

krb5_error_code
krb5_cc_start_seq_get (krb5_context context,
		       krb5_ccache id,
		       krb5_cc_cursor *cursor)
{
    int16_t tag;
    krb5_principal principal;
    krb5_storage *sp;

    if (id->type != 1)
	abort ();
    cursor->fd = open (krb5_cc_get_name (context, id), O_RDONLY);
    if (cursor->fd < 0)
	return errno;
    sp = krb5_storage_from_fd(cursor->fd);
    krb5_ret_int16 (sp, &tag);
    krb5_ret_principal (sp, &principal);
    krb5_storage_free(sp);
    krb5_free_principal (principal);
    return 0;
}

krb5_error_code
krb5_cc_next_cred (krb5_context context,
		   krb5_ccache id,
		   krb5_creds *creds,
		   krb5_cc_cursor *cursor)
{
    krb5_error_code err;
    krb5_storage *sp;
    if (id->type != 1)
	abort ();
    
    krb5_storage_from_fd(cursor->fd);
    err = krb5_cc_read_cred (sp, creds);
    krb5_storage_free(sp);
}

krb5_error_code
krb5_cc_end_seq_get (krb5_context context,
		     krb5_ccache id,
		     krb5_cc_cursor *cursor)
{
    if (id->type != 1)
	abort ();
    return close (cursor->fd);
}

krb5_error_code
krb5_cc_get_first(krb5_context context,
		  krb5_ccache id,
		  krb5_cc_cursor *cursor)
{
    int fd;
    int16_t tag;
    krb5_principal principal;
    krb5_storage *sp;
    
    fd = open(krb5_cc_get_name (context, id), O_RDONLY);
    cursor->fd = fd;
    sp = krb5_storage_from_fd(fd);
    krb5_ret_int16(sp, &tag);
    krb5_ret_principal(sp, &principal);
    krb5_storage_free(sp);
    return 0;
}

krb5_error_code
krb5_cc_get_next(krb5_context context,
		 krb5_ccache id,
		 krb5_creds *creds,
		 krb5_cc_cursor *cursor)
{
    return krb5_cc_read_cred(cursor->fd, creds);
}

krb5_error_code
krb5_cc_end_get(krb5_context context,
		krb5_ccache id,
		krb5_cc_cursor *cursor)
{
    close(cursor->fd);
    return 0;
}

krb5_error_code
krb5_cc_remove_cred(krb5_context context,
		    krb5_ccache id,
		    krb5_flags which,
		    krb5_creds *cred)
{
    return 0; /* XXX */
}

krb5_error_code
krb5_cc_set_flags(krb5_context context,
		  krb5_ccache id,
		  krb5_flags flags)
{
    return 0; /* XXX */
}
		    
