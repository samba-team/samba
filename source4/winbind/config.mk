# server subsystem

#######################
# Start SUBSYSTEM WINBIND
[MODULE::WINBIND]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = service
PRIVATE_PROTO_HEADER = wb_proto.h
PRIVATE_DEPENDENCIES = \
		WB_HELPER \
		IDMAP \
		NDR_WINBIND \
		process_model \
		RPC_NDR_LSA \
		dcerpc_samr \
		PAM_ERRORS \
		LIBCLI_LDAP
# End SUBSYSTEM WINBIND
#######################

WINBIND_OBJ_FILES = $(addprefix winbind/, \
		wb_server.o \
		wb_irpc.o \
		wb_samba3_protocol.o \
		wb_samba3_cmd.o \
		wb_init_domain.o \
		wb_dom_info.o \
		wb_dom_info_trusted.o \
		wb_sid2domain.o \
		wb_name2domain.o \
		wb_gid2sid.o \
		wb_sid2uid.o \
		wb_sid2gid.o \
		wb_uid2sid.o \
		wb_connect_lsa.o \
		wb_connect_sam.o \
		wb_cmd_lookupname.o \
		wb_cmd_lookupsid.o \
		wb_cmd_getdcname.o \
		wb_cmd_getpwnam.o \
		wb_cmd_getpwuid.o \
		wb_cmd_userdomgroups.o \
		wb_cmd_usersids.o \
		wb_cmd_list_trustdom.o \
		wb_cmd_list_users.o \
		wb_cmd_setpwent.o \
		wb_cmd_getpwent.o \
		wb_pam_auth.o \
		wb_sam_logon.o)

################################################
# Start SUBYSTEM WB_HELPER
[SUBSYSTEM::WB_HELPER]
PRIVATE_PROTO_HEADER = wb_helper.h
PUBLIC_DEPENDENCIES = RPC_NDR_LSA dcerpc_samr
# End SUBSYSTEM WB_HELPER
################################################

WB_HELPER_OBJ_FILES = $(addprefix winbind/, wb_async_helpers.o wb_utils.o)

################################################
# Start SUBYSTEM IDMAP
[SUBSYSTEM::IDMAP]
PRIVATE_PROTO_HEADER = idmap_proto.h
PUBLIC_DEPENDENCIES = SAMDB_COMMON
# End SUBSYSTEM IDMAP
################################################

IDMAP_OBJ_FILES = winbind/idmap.o
