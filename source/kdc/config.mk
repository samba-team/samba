# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = smbd
PRIVATE_DEPENDENCIES = \
		LIBLDB HEIMDAL HEIMDAL_KDC HEIMDAL_HDB SAMDB
# End SUBSYSTEM KDC
#######################

KDC_OBJ_FILES = $(addprefix $(kdcsrcdir)/, kdc.o kpasswdd.o)
$(KDC_OBJ_FILES): CFLAGS+=$(KRB5_CFLAGS) $(GSSAPI_CFLAGS) -I$(heimdalsrcdir)/lib/roken -I$(heimdalsrcdir)/lib -I$(heimdalsrcdir)/lib/wind -I$(heimdalsrcdir)/kdc -I$(heimdalsrcdir)/lib/ntlm -I$(heimdalsrcdir)/lib/hdb

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::HDB_LDB]
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply HEIMDAL CREDENTIALS \
		HEIMDAL_HDB_ASN1
# End SUBSYSTEM KDC
#######################

HDB_LDB_OBJ_FILES = $(addprefix $(kdcsrcdir)/, hdb-ldb.o pac-glue.o)
$(HDB_LDB_OBJ_FILES): CFLAGS+=-I$(heimdalsrcdir)/kdc -I$(heimdalsrcdir)/lib/hdb -I$(heimdalsrcdir)/lib/com_err -I$(heimdalsrcdir)/lib/krb5 $(KRB5_CFLAGS) -I$(heimdalsrcdir)/lib -I$(heimdalsrcdir)/lib/roken
$(eval $(call proto_header_template,$(kdcsrcdir)/pac_glue.h,$(HDB_LDB_OBJ_FILES:.o=.c)))
