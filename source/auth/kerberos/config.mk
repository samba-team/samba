#################################
# Start SUBSYSTEM KERBEROS
[SUBSYSTEM::KERBEROS]
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5 NDR_KRB5PAC samba-socket LIBCLI_RESOLVE
PRIVATE_DEPENDENCIES = ASN1_UTIL auth_sam_reply LIBPACKET LIBNDR
# End SUBSYSTEM KERBEROS
#################################

KERBEROS_OBJ_FILES = $(addprefix $(authsrcdir)/kerberos/, \
	kerberos.o \
	clikrb5.o \
	kerberos_heimdal.o \
	kerberos_pac.o \
	gssapi_parse.o \
	krb5_init_context.o)

$(KERBEROS_OBJ_FILES): CFLAGS+=$(KRB5_CFLAGS) -I$(heimdalsrcdir)/lib/roken -I$(heimdalsrcdir)/lib -I$(heimdalsrcdir)/lib/hx509

$(eval $(call proto_header_template,$(authsrcdir)/kerberos/proto.h,$(KERBEROS_OBJ_FILES:.o=.c)))

