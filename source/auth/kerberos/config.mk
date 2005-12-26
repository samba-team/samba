#################################
# Start SUBSYSTEM KERBEROS
[SUBSYSTEM::KERBEROS]
OBJ_FILES = kerberos.o \
			clikrb5.o \
			kerberos_verify.o \
			kerberos_util.o \
			kerberos_pac.o \
			gssapi_parse.o \
			krb5_init_context.o
REQUIRED_SUBSYSTEMS = KERBEROS_LIB NDR_KRB5PAC 
# End SUBSYSTEM KERBEROS
#################################
