#include "krb5_locl.h"

/* XXX shouldn't be here */

void krb5_free_ccache(krb5_context context,
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
	return -1;
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

static krb5_error_code
store_int32(int fd,
	    int32_t value)
{
    int ret;

    value = htonl(value);
    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:-1;
    return 0;
}

static krb5_error_code
ret_int32(int fd,
	  int32_t *value)
{
    int32_t v;
    int ret;
    ret = read(fd, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:-1; /* XXX */

    *value = ntohl(v);
    return 0;
}

static krb5_error_code
store_int16(int fd,
	    int16_t value)
{
    int ret;

    value = htons(value);
    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:-1;
    return 0;
}

static krb5_error_code
ret_int16(int fd,
	  int16_t *value)
{
    int16_t v;
    int ret;
    ret = read(fd, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:-1; /* XXX */
  
    *value = ntohs(v);
    return 0;
}

static krb5_error_code
store_int8(int fd,
	   int8_t value)
{
    int ret;

    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:-1;
    return 0;
}

static krb5_error_code
ret_int8(int fd,
	 int8_t *value)
{
    int ret;

    ret = read (fd, value, sizeof(*value));
    if (ret != sizeof(*value))
	return (ret<0)?errno:-1;
    return 0;
}

static krb5_error_code
store_data(int fd,
	   krb5_data data)
{
    int ret;
    ret = store_int32(fd, data.length);
    if(ret < 0)
	return ret;
    return write(fd, data.data, data.length);
}

static krb5_error_code
ret_data(int fd,
	 krb5_data *data)
{
    int ret;
    int size;
    ret = ret_int32(fd, &size);
    data->length = size;
    data->data = malloc(size);
    ret = read(fd, data->data, size);
    if(ret != size)
	return (ret < 0)? errno : -1; /* XXX */
    return 0;
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

static krb5_error_code
ret_principal(int fd,
	      krb5_principal *princ)
{
    int i;
    krb5_principal p;

    p = ALLOC(1, krb5_principal_data);

    if(ret_int32(fd, &p->type))
	return -1;
    ret_int32(fd, &p->ncomp);
    ret_data(fd, &p->realm);
    p->comp = ALLOC(p->ncomp, krb5_data);
    for(i = 0; i < p->ncomp; i++)
	ret_data(fd, &p->comp[i]);
    *princ = p;
    return 0;
}

static krb5_error_code
store_keyblock(int fd, krb5_keyblock p)
{
    store_int32(fd, p.keytype);
    store_data(fd, p.contents);
    return 0;
}

static krb5_error_code
ret_keyblock(int fd, krb5_keyblock *p)
{
    ret_int32(fd, (int32_t*)&p->keytype); /* keytype + etype */
    ret_data(fd, &p->contents);
    return 0;
}

static krb5_error_code
store_times(int fd, krb5_times times)
{
    store_int32(fd, times.authtime);
    store_int32(fd, times.starttime);
    store_int32(fd, times.endtime);
    store_int32(fd, times.renew_till);
    return 0;
}

static krb5_error_code
ret_times(int fd, krb5_times *times)
{
    ret_int32(fd, &times->authtime);
    ret_int32(fd, &times->starttime);
    ret_int32(fd, &times->endtime);
    ret_int32(fd, &times->renew_till);
    return 0;
}

static krb5_error_code
store_address(int fd, krb5_address p)
{
    store_int16(fd, p.type);
    store_data(fd, p.address);
    return 0;
}

static krb5_error_code
ret_address(int fd, krb5_address *adr)
{
    ret_int16(fd, (int16_t*)&adr->type);
    ret_data(fd, &adr->address);
    return 0;
}

static krb5_error_code
store_addrs(int fd, krb5_addresses p)
{
    int i;
    store_int32(fd, p.number);
    for(i = 0; i<p.number; i++)
	store_address(fd, p.addrs[i]);
    return 0;
}

static krb5_error_code
ret_addrs(int fd, krb5_addresses *adr)
{
    int i;
    ret_int32(fd, &adr->number);
    adr->addrs = ALLOC(adr->number, krb5_address);
    for(i = 0; i < adr->number; i++)
	ret_address(fd, &adr->addrs[i]);
    return 0;
}

static krb5_error_code
store_authdata(int fd, krb5_data p)
{
    store_data(fd, p);
    return 0;
}

static krb5_error_code
ret_authdata(int fd, krb5_data *auth)
{
    ret_data(fd, auth);
    return 0;
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
    store_int16(fd, 0x503);
    store_principal(fd, primary_principal);
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
    store_principal(fd, creds->client);
    store_principal(fd, creds->server);
    store_keyblock(fd, creds->session);
    store_times(fd, creds->times);
    store_int8(fd, 0); /* s/key */
    store_int32(fd, 0); /* flags */
    store_addrs(fd, creds->addresses);
    store_authdata(fd, creds->authdata);
    store_data(fd, creds->ticket);
    store_data(fd, creds->second_ticket);
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

    ret = ret_principal (fd, &creds->client);
    if(ret) return ret;
    ret = ret_principal (fd, &creds->server);
    if(ret) return ret;
    ret = ret_keyblock (fd, &creds->session);
    if(ret) return ret;
    ret = ret_times (fd, &creds->times);
    if(ret) return ret;
    ret = ret_int8 (fd, &dummy8);
    if(ret) return ret;
    ret = ret_int32 (fd, &dummy32);
    if(ret) return ret;
    ret = ret_addrs (fd, &creds->addresses);
    if(ret) return ret;
    ret = ret_authdata (fd, &creds->authdata);
    if(ret) return ret;
    ret = ret_data (fd, &creds->ticket);
    if(ret) return ret;
    ret = ret_data (fd, &creds->second_ticket);
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

    fd = open(krb5_cc_get_name(context, id), O_RDONLY);
    if(fd < 0)
	return errno;
    ret_int16(fd, &tag);
    ret_principal(fd, principal);
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

    if (id->type != 1)
	abort ();
    cursor->fd = open (krb5_cc_get_name (context, id), O_RDONLY);
    if (cursor->fd < 0)
	return errno;
    ret_int16 (cursor->fd, &tag);
    ret_principal (cursor->fd, &principal);
    krb5_free_principal (principal);
    return 0;
}

krb5_error_code
krb5_cc_next_cred (krb5_context context,
		   krb5_ccache id,
		   krb5_creds *creds,
		   krb5_cc_cursor *cursor)
{
    if (id->type != 1)
	abort ();
    return krb5_cc_read_cred (cursor->fd, creds);
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
    
    fd = open(krb5_cc_get_name (context, id), O_RDONLY);
    cursor->fd = fd;
    ret_int16(fd, &tag);
    ret_principal(fd, &principal);
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
		    
