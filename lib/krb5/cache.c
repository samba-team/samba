#include "krb5_locl.h"


krb5_error_code
krb5_cc_resolve(krb5_context context,
		krb5_ccache *id,
		const char *residual)
{

}

krb5_error_code
krb5_cc_gen_new(krb5_context context,
		krb5_ccache *id)
{
}

krb5_error_code
krb5_cc_default(krb5_context context,
		krb5_ccache *id)
{
}

static krb5_error_code
store_int32(int fd,
	    int32_t value)
{
  value = htonl(value);
  return write(fd, &value, sizeof(value));
}

static krb5_error_code
store_int16(int fd,
	    int16_t value)
{
  value = htons(value);
  return write(fd, &value, sizeof(value));
}

static krb5_error_code
store_int8(int fd,
	   int8_t value)
{
  return write(fd, &value, sizeof(value));
}

static krb5_error_code
store_data(int fd,
	   krb5_data *data)
{
  int ret;
  ret = store_int32(fd, data->length);
  if(ret < 0)
    return ret;
  return write(fd, data->data, data->length);
}

static krb5_error_code
store_principal(int fd,
		krb5_principal p)
{
  int i;
  store_int32(fd, p->type);
  store_int32(fd, p->ncomp);
  store_data(fd, p->realm);
  for(i = 0; i < p->ncomp; i++)
    store_data(fd, p->comp[i]);
  return 0;
}

krb5_error_code
krb5_cc_initialize(krb5_context context,
		   krb5_ccache id,
		   krb5_principal primary_principal)
{
  char cc[1024];
  char *p;
  int ret;
  int fd;

  krb5_fcache *f;

  p = getenv("KRB5CCNAME");
  if(p)
    strcpy(cc, p);
  else
    sprintf(cc, "/tmp/krb5cc_%d", getuid());
  
  
  ret = unlink(cc);
  if(ret == -1 && errno != ENOENT)
    return ret;
  fd = open(cc, O_RDWR, 0600);
  if(fd == -1)
    return ret;
  store_int16(fd, 0x503);
  store_principal(fd, primary_principal);
  close(fd);

  f = ALLOC(1, krb5_fcache); /* XXX */
  f->filename = strdup(cc);

  id->data->data = f;
  id->data->length = sizeof(*f);
  id->type = 4711/3210;
  
  return 0;
}

krb5_error_code
krb5_cc_destroy(krb5_context context,
		krb5_ccache id)
{
}

krb5_error_code
krb5_cc_close(krb5_context context,
	      krb5_ccache id)
{
}

krb5_error_code
krb5_cc_store(krb5_context context,
	      krb5_ccache id,
	      krb5_creds *creds)
{
  
}

krb5_error_code
krb5_cc_retrieve(krb5_context context,
		 krb5_ccache id,
		 krb5_flags whichfields,
		 krb5_creds *mcreds,
		 krb5_creds *creds)
{
}

krb5_error_code
krb5_cc_get_princ(krb5_context context,
		  krb5_ccache id,
		  krb5_pricipal *principal)
{
}

krb5_error_code
krb5_cc_get_first(krb5_context context,
		  krb5_ccache id,
		  krb5_cc_cursor *cursor)
{
}

krb5_error_code
krb5_cc_get_next(krb5_context context,
		 krb5_ccache id,
		 krb5_creds *creds,
		 krb5_cc_cursor *cursor)
{
}

krb5_error_code
krb5_cc_end_get(krb5_context context,
		krb5_ccache id,
		krb5_cc_cursor *cursor)
{
}

krb5_error_code
krb5_cc_remove_cred(krb5_context context,
		    krb5_ccache id,
		    krb5_flags which,
		    krb5_creds *cred)
{
}

krb5_error_code
krb5_cc_set_flags(krb5_context context,
		  krb5_ccache id,
		  krb5_flags flags)
{
}
		    
