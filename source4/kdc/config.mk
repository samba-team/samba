# KDC server subsystem

#######################
# Start SUBSYSTEM KDC
[MODULE::KDC]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = service
PRIVATE_DEPENDENCIES = \
		HEIMDAL_KDC HDB_SAMBA4 WDC_SAMBA4 LIBSAMBA-HOSTCONFIG \
		LIBTSOCKET LIBSAMBA_TSOCKET
# End SUBSYSTEM KDC
#######################

KDC_OBJ_FILES = $(addprefix $(kdcsrcdir)/, kdc.o kpasswdd.o)

#######################
# Start SUBSYSTEM HDB
[SUBSYSTEM::HDB_SAMBA4]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply CREDENTIALS \
		HEIMDAL_HDB LIBSAMBA-HOSTCONFIG
# End SUBSYSTEM HDB
#######################

HDB_SAMBA4_OBJ_FILES = $(addprefix $(kdcsrcdir)/, hdb-samba4.o)

#######################
# Start SUBSYSTEM WDC
[SUBSYSTEM::WDC_SAMBA4]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply CREDENTIALS \
		HEIMDAL_HDB PAC_GLUE LIBSAMBA-HOSTCONFIG
# End SUBSYSTEM WDC
#######################

WDC_SAMBA4_OBJ_FILES = $(addprefix $(kdcsrcdir)/, wdc-samba4.o)

#######################
# Start SUBSYSTEM KDC
[SUBSYSTEM::PAC_GLUE]
CFLAGS = -Iheimdal/kdc -Iheimdal/lib/hdb
PRIVATE_DEPENDENCIES = \
		LIBLDB auth_sam auth_sam_reply CREDENTIALS \
		HEIMDAL_HDB LIBSAMBA-HOSTCONFIG
# End SUBSYSTEM KDC
#######################

PAC_GLUE_OBJ_FILES = $(addprefix $(kdcsrcdir)/, pac-glue.o)
