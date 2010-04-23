# $(utilssrcdir)/net subsystem


#################################
# Start MODULE net_drs
[MODULE::net_drs]
SUBSYSTEM = net
OUTPUT_TYPE = MERGED_OBJ
PRIVATE_DEPENDENCIES = \
		LIBCLI_DRSUAPI \
		LIBLDB
# End MODULE net_drs
#################################

net_drs_OBJ_FILES = $(addprefix $(utilssrcdir)/net/drs/,  \
		net_drs.o \
		net_drs_bind.o \
		net_drs_kcc.o \
		net_drs_replicate.o \
		net_drs_showrepl.o)

$(eval $(call proto_header_template,$(utilssrcdir)/net/drs/net_drs_proto.h,$(net_drs_OBJ_FILES:.o=.c)))


#################################
# Start BINARY net
[BINARY::net]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBSAMBA-NET \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		policy \
		net_drs
# End BINARY net
#################################

net_OBJ_FILES = $(addprefix $(utilssrcdir)/net/,  \
		net.o \
		net_password.o \
		net_join.o \
		net_vampire.o \
		net_gpo.o)


$(eval $(call proto_header_template,$(utilssrcdir)/net/net_proto.h,$(net_OBJ_FILES:.o=.c)))

