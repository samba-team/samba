#include "krb5_locl.h"

RCSID("$Id$");

#define FILENAME(X) (((krb5_fcache*)(X)->data.data)->filename)

static char*
fcc_get_name(krb5_context context,
	     krb5_ccache id)
{
    return FILENAME(id);
}

static krb5_error_code
fcc_resolve(krb5_context context, krb5_ccache *id, const char *res)
{
    krb5_fcache *f;
    f = malloc(sizeof(*f));
    if(f == NULL)
	return KRB5_CC_NOMEM;
    f->filename = strdup(res);
    if(f->filename == NULL){
	free(f);
	return KRB5_CC_NOMEM;
    }
    (*id)->data.data = f;
    (*id)->data.length = sizeof(*f);
    return 0;
}

static krb5_error_code
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

static krb5_error_code
fcc_gen_new(krb5_context context, krb5_ccache *id)
{
    abort();
}

static krb5_error_code
fcc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    int ret;
    int fd;

    char *f;
    
    f = FILENAME(id);
  
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


static krb5_error_code
fcc_destroy(krb5_context context,
	    krb5_ccache id)
{
    char *f;
    int ret;
    f = FILENAME(id);

    ret = erase_file(f);
  
    krb5_free_ccache(context, id);
    return ret;
}

static krb5_error_code
fcc_close(krb5_context context,
	  krb5_ccache id)
{
    krb5_data_free(&id->data);
    return 0;
}

static krb5_error_code
fcc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    int fd;
    char *f;

    f = FILENAME(id);

    fd = open(f, O_WRONLY | O_APPEND);
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
fcc_read_cred (int fd,
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

static krb5_error_code
fcc_get_principal(krb5_context context,
		      krb5_ccache id,
		      krb5_principal *principal)
{
    int fd;
    int16_t tag;
    krb5_storage *sp;

    fd = open(FILENAME(id), O_RDONLY);
    if(fd < 0)
	return errno;
    sp = krb5_storage_from_fd(fd);
    krb5_ret_int16(sp, &tag);
    krb5_ret_principal(sp, principal);
    krb5_storage_free(sp);
    close(fd);
    return 0;
}

static krb5_error_code
fcc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    int16_t tag;
    krb5_principal principal;
    krb5_storage *sp;

    cursor->fd = open (krb5_cc_get_name (context, id), O_RDONLY);
    if (cursor->fd < 0)
	return errno;
    sp = krb5_storage_from_fd(cursor->fd);
    krb5_ret_int16 (sp, &tag);
    krb5_ret_principal (sp, &principal);
    krb5_storage_free(sp);
    krb5_free_principal (context, principal);
    return 0;
}

static krb5_error_code
fcc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_error_code err;
    krb5_storage *sp;
    sp =  krb5_storage_from_fd(cursor->fd);
    err = fcc_read_cred (cursor->fd, creds);
    krb5_storage_free(sp);
    return err;
}

static krb5_error_code
fcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    return close (cursor->fd);
}

static krb5_error_code
fcc_remove_cred(krb5_context context,
		 krb5_ccache id,
		 krb5_flags which,
		 krb5_creds *cred)
{
    return 0; /* XXX */
}

static krb5_error_code
fcc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    return 0; /* XXX */
}
		    
krb5_cc_ops fcc_ops = {
    "FILE",
    fcc_get_name,
    fcc_resolve,
    fcc_gen_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store_cred,
    NULL, /* fcc_retrieve */
    fcc_get_principal,
    fcc_get_first,
    fcc_get_next,
    fcc_end_get,
    fcc_remove_cred,
    fcc_set_flags
};
