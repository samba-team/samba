
int
krb5_kdc_process_generic_request(krb5_context context, 
			    struct krb5_kdc_configuration *config,
			    unsigned char *buf, 
			    size_t len, 
			    krb5_data *reply,
			    krb5_boolean *prependlength,
			    const char *from,
			    struct sockaddr *addr);

int krb5_kdc_process_krb5_request(krb5_context context, 
				  struct krb5_kdc_configuration *config,
				  unsigned char *buf, 
				  size_t len, 
				  krb5_data *reply,
				  const char *from,
				  struct sockaddr *addr);

void krb5_kdc_default_config(struct krb5_kdc_configuration *config);

void
kdc_openlog(krb5_context context, 
	    struct krb5_kdc_configuration *config);
