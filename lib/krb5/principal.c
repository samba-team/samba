#include "krb5_locl.h"

RCSID("$Id$");

/* Public principal handling functions */

#ifdef USE_ASN1_PRINCIPAL
#define num_components(P) ((P)->name.name_string.len)
#define princ_type(P) ((P)->name.name_type)
#else
#define num_components(P) ((P)->ncomp)
#define princ_type(P) ((P)->type)
#endif

void
krb5_free_principal(krb5_context context,
		    krb5_principal p)
{
#ifdef USE_ASN1_PRINCIPAL
    free_Principal(p);
#else
    int i;
    for(i = 0; i < num_components(p); i++)
	krb5_data_free(&p->comp[i]);
    free(p->comp);
    krb5_data_free(&p->realm);
#endif
    free(p);
}

krb5_error_code
krb5_parse_name(krb5_context context,
		const char *name,
		krb5_principal *principal)
{

#ifdef USE_ASN1_PRINCIPAL
    general_string *comp;
    general_string realm;
#else
    krb5_data *comp;
    krb5_data realm;
#endif
    int ncomp;

    char *p;
    char *q;
    char *s;
    char *start;

    int n;
    char c;
    int got_realm = 0;
  
    /* count number of component */
    ncomp = 1;
    for(p = (char*)name; *p; p++){
	if(*p=='\\'){
	    if(!p[1])
		return KRB5_PARSE_MALFORMED;
	    p++;
	} else if(*p == '/')
	    ncomp++;
    }
#ifdef USE_ASN1_PRINCIPAL
    comp = calloc(ncomp, sizeof(*comp));
#else
    comp = ALLOC(ncomp, krb5_data);
#endif
  
    n = 0;
    start = q = p = s = strdup(name);
    while(*p){
	c = *p++;
	if(c == '\\'){
	    c = *p++;
	    if(c == 'n')
		c = '\n';
	    else if(c == 't')
		c = '\t';
	    else if(c == 'b')
		c = '\b';
	    else if(c == '0')
		c = '\0';
	}else if(c == '/' || c == '@'){
	    if(got_realm){
	    exit:
		while(n>0){
#ifdef USE_ASN1_PRINCIPAL
		    free(comp[--n]);
#else
		    free(comp[--n].data);
#endif
		}
		free(comp);
		free(s);
		return KRB5_PARSE_MALFORMED;
	    }else{
#ifdef USE_ASN1_PRINCIPAL
		comp[n] = malloc(q - start + 1);
		strncpy(comp[n], start, q - start);
		comp[n][q - start] = 0;
#else
		comp[n].length = q - start;
		comp[n].data = (krb5_pointer)malloc(comp[n].length);
		memmove(comp[n].data, start, comp[n].length);
#endif
		n++;
	    }
	    if(c == '@')
		got_realm = 1;
	    start = q;
	    continue;
	}
	if(got_realm && (c == ':' || c == '/' || c == '\0'))
	    goto exit;
	*q++ = c;
    }
    if(got_realm){
#ifdef USE_ASN1_PRINCIPAL
	realm = malloc(q - start + 1);
	strncpy(realm, start, q - start);
	realm[q - start] = 0;
#else
	realm.length = q - start;
	realm.data = (krb5_pointer)malloc(realm.length);
	memmove(realm.data, start, realm.length);
#endif
    }else{
#ifdef USE_ASN1_PRINCIPAL
	comp[n] = malloc(q - start + 1);
	strncpy(comp[n], start, q - start);
	comp[n][q - start] = 0;
#else
	comp[n].length = q - start;
	comp[n].data = (krb5_pointer)malloc(comp[n].length);
	memmove(comp[n].data, start, comp[n].length);
#endif
	n++;
    }
    *principal = malloc(sizeof(**principal));
#ifdef USE_ASN1_PRINCIPAL
    (*principal)->name.name_type = KRB5_NT_PRINCIPAL;
    (*principal)->name.name_string.val = comp;
#else    
    (*principal)->type = KRB5_NT_PRINCIPAL;
    (*principal)->comp = comp;
#endif
    num_components(*principal) = n;
    (*principal)->realm = realm;
    free(s);
    return 0;
}

static void quote_string(char *s, int len, char **out)
{
    char *q;
    char *p = *out;
    int c=0;
#ifdef USE_ASN1_PRINCIPAL
    len = strlen(s);
#endif
    for(q = s; q < s + len; q++){
	if(*q == '\n')
	    c = 'n';
	else if(*q == '\t')
	    c = 't';
	else if(*q == '\b')
	    c = 'b';
	else if(*q == '\0')
	    c = '0';
	else if(*q == '/')
	    c='/';      
	else if(*q == '@')
	    c = '@';
	if(c){
	    *p++ = '\\';
	    *p++ = c;
	    c = 0;
	}else
	    *p++ = *q;
    }
    *out = p;
}


krb5_error_code
krb5_unparse_name(krb5_context context,
		  krb5_principal principal,
		  char **name)
{
    int size;
    char *p;
    char *s;
    int i;
    int ncomp = num_components(principal);
#ifdef USE_ASN1_PRINCIPAL
    size = 2 * strlen(principal->realm) + 1;
    for (i = 0; i < ncomp; i++)
	size += 2 * strlen(principal->name.name_string.val[i]) + 1;
#else
    size = 2 * principal->realm.length + 1;
    for(i = 0; i < ncomp; i++)
	size += 2 * principal->comp[i].length + 1;
#endif
    s = malloc(size);
    p = s;
    for(i = 0; i < ncomp; i++){
	if(i) *p++ = '/';
	quote_string(
#ifdef USE_ASN1_PRINCIPAL
		     principal->name.name_string.val[i], 0,
#else
		     principal->comp[i].data, principal->comp[i].length, 
#endif
		     &p);
    }
    *p++ = '@';
#ifdef USE_ASN1_PRINCIPAL
    quote_string(principal->realm, 0, &p);
#else
    quote_string(principal->realm.data, principal->realm.length, &p);
#endif
    *p = 0;
    *name = s;
    return 0;
}


krb5_error_code
krb5_unparse_name_ext(krb5_context context,
		      krb5_const_principal principal,
		      char **name,
		      size_t *size)
{
    fprintf(stderr, "krb5_unparse_name_ext: not implemented\n");
    abort();
}


krb5_realm*
krb5_princ_realm(krb5_context context,
		 krb5_principal principal)
{
    return &principal->realm;
}


void
krb5_princ_set_realm(krb5_context context,
		     krb5_principal principal,
		     krb5_realm *realm)
{
    principal->realm = *realm;
}


krb5_error_code
krb5_build_principal(krb5_context context,
		     krb5_principal *principal,
		     int rlen,
		     const char *realm,
		     ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}

krb5_error_code
krb5_principal_set_component(krb5_context context, krb5_principal p, 
			     int n, void *data, size_t len)
{
#ifdef USE_ASN1_PRINCIPAL
    general_string *tmp = p->name.name_string.val;
#else
    krb5_data *tmp = p->comp;
#endif
    if(num_components(p) <= n){
	int s = n + 10;
	tmp = realloc(tmp, s * sizeof(*tmp));
	if(!tmp)
	    return ENOMEM;
	memset(tmp + num_components(p), 0, 
	       (s - num_components(p)) * sizeof(*tmp));
#ifdef USE_ASN1_PRINCIPAL
	p->name.name_string.val = tmp;
#else
	p->comp = tmp;
#endif
	num_components(p)= s;
    }
#ifdef USE_ASN1_PRINCIPAL
    if(p->name.name_string.val[n])
	free(p->name.name_string.val[n]);
    p->name.name_string.val[n] = malloc(len + 1);
    strncpy(p->name.name_string.val[n], data, len);
    p->name.name_string.val[n][len] = 0;
#else
    p->comp[n].length = 0;
    p->comp[n].data = NULL;
    krb5_data_copy(&p->comp[n], data, len);
#endif
    return 0;
}

static void
va_ext_princ(krb5_context context, krb5_principal p, va_list ap)
{
    int n = 0;
    while(1){
	char *s;
	int len;
	len  = va_arg(ap, int);
	if(len == 0)
	    break;
	s = va_arg(ap, char*);
	krb5_principal_set_component(context, p, n, s, len);
	n++;
    }
    num_components(p) = n;
}

static void
va_princ(krb5_context context, krb5_principal p, va_list ap)
{
    int n = 0;
    while(1){
	char *s;
	int len;
	s = va_arg(ap, char*);
	if(s == NULL)
	    break;
	len = strlen(s);
	krb5_principal_set_component(context, p, n, s, len);
	n++;
    }
    num_components(p) = n;
}


static krb5_error_code
build_principal(krb5_context context,
		krb5_principal *principal,
		int rlen,
		const char *realm,
		void (*func)(krb5_context, krb5_principal, va_list),
		va_list ap)
{
    krb5_principal p;
    int n;
  
    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;
    princ_type(p) = KRB5_NT_PRINCIPAL;

#ifdef USE_ASN1_PRINCIPAL
    p->realm = strdup(realm);
    if(p->realm == NULL){
	free(p);
	return ENOMEM;
    }
#else
    if(krb5_data_copy(&p->realm, (void*)realm, rlen)){
	free(p);
	return ENOMEM;
    }
#endif
  
    (*func)(context, p, ap);
    *principal = p;
    return 0;
}

krb5_error_code
krb5_build_principal_va(krb5_context context, 
			krb5_principal *principal, 
			int rlen,
			const char *realm,
			va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_princ, ap);
}

/* Not part of MIT K5 API */
krb5_error_code
krb5_build_principal_va_ext(krb5_context context, 
			    krb5_principal *principal, 
			    int rlen,
			    const char *realm,
			    va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_ext_princ, ap);
}


krb5_error_code
krb5_build_principal_ext(krb5_context context,
			 krb5_principal *principal,
			 int rlen,
			 const char *realm,
			 ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va_ext(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}


krb5_error_code
krb5_copy_principal(krb5_context context,
		    krb5_const_principal inprinc,
		    krb5_principal *outprinc)
{
    krb5_principal p;
    int i;
    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;
#ifdef USE_ASN1_PRINCIPAL
    copy_PrincipalName(&inprinc->name, &p->name);
    copy_Realm(&inprinc->realm, &p->realm);
#else
    princ_type(p) = princ_type(inprinc);
    if(krb5_data_copy(&p->realm, inprinc->realm.data, inprinc->realm.length)){
	krb5_free_principal(context, p);
	return ENOMEM;
    }
    p->comp = ALLOC(inprinc->ncomp, krb5_data);
    if(!p->comp){
	krb5_free_principal(context, p);
	return ENOMEM;
    }
  
    for(i=0; i<inprinc->ncomp; i++){
	p->comp[i].length = 0;
	if(krb5_data_copy(&p->comp[i], inprinc->comp[i].data, 
			  inprinc->comp[i].length)){
	    krb5_free_principal(context, p);
	    return ENOMEM;
	}
	p->ncomp = i+1;
    }
#endif
    *outprinc = p;
    return 0;
}


krb5_boolean
krb5_principal_compare(krb5_context context,
		       krb5_const_principal princ1,
		       krb5_const_principal princ2)
{
    int i;
    if(!krb5_realm_compare(context, princ1, princ2))
	return FALSE;
    if(num_components(princ1) != num_components(princ2))
	return FALSE;
    for(i = 0; i < num_components(princ1); i++){
#ifdef USE_ASN1_PRINCIPAL
	if(strcmp(princ1->name.name_string.val[i], 
		  princ2->name.name_string.val[i]) != 0)
	    return FALSE;
#else
	if(princ1->comp[i].length != princ2->comp[i].length)
	    return FALSE;
	if(memcmp(princ1->comp[i].data, princ2->comp[i].data, 
		  princ1->comp[i].length))
	    return FALSE;
#endif
    }
    return TRUE;
}


krb5_boolean
krb5_realm_compare(krb5_context context,
		   krb5_const_principal princ1,
		   krb5_const_principal princ2)
{
#ifdef USE_ASN1_PRINCIPAL
    return strcmp(princ1->realm, princ2->realm) == 0;
#else
    if(princ1->realm.length != princ2->realm.length)
	return FALSE;
    if(memcmp(princ1->realm.data, princ2->realm.data, princ1->realm.length))
	return FALSE;
    return TRUE;
#endif
}

		   
krb5_error_code
krb5_425_conv_principal(krb5_context context,
			const char *name,
			const char *instance,
			const char *realm,
			krb5_principal *princ)
{
    if(!strcmp(name, "rcmd"))
	name = "host";
    return krb5_build_principal(context, princ, 
				strlen(realm), realm, name, instance, 0);
}


			
krb5_error_code
krb5_sname_to_principal (krb5_context context,
			 const char *hostname,
			 const char *sname,
			 int32_t type,
			 krb5_principal *ret_princ)
{
    krb5_error_code ret;
    char **r;

    ret = krb5_get_host_realm (context, hostname, &r);
    if (ret)
	return ret;
    
    return krb5_build_principal (context,
				 ret_princ,
				 strlen(r[0]),
				 r[0],
				 sname,
				 hostname,
				 0);
}
