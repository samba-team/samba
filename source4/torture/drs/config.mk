#################################
# Start SUBSYSTEM TORTURE_DRS
[MODULE::TORTURE_DRS]
SUBSYSTEM = smbtorture
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = torture_drs_init
PRIVATE_DEPENDENCIES = \
		NDR_TABLE RPC_NDR_UNIXINFO dcerpc_samr RPC_NDR_WINREG RPC_NDR_INITSHUTDOWN \
		RPC_NDR_OXIDRESOLVER RPC_NDR_EVENTLOG RPC_NDR_ECHO RPC_NDR_SVCCTL \
		RPC_NDR_NETLOGON dcerpc_atsvc dcerpc_mgmt RPC_NDR_DRSUAPI \
		RPC_NDR_LSA RPC_NDR_EPMAPPER RPC_NDR_DFS RPC_NDR_FRSAPI RPC_NDR_SPOOLSS \
		RPC_NDR_SRVSVC RPC_NDR_WKSSVC RPC_NDR_ROT RPC_NDR_DSSETUP \
		RPC_NDR_REMACT RPC_NDR_OXIDRESOLVER RPC_NDR_NTSVCS WB_HELPER LIBSAMBA-NET \
		LIBCLI_AUTH POPT_CREDENTIALS TORTURE_LDAP TORTURE_UTIL TORTURE_RAP \
		dcerpc_server service process_model ntvfs SERVICE_SMB RPC_NDR_BROWSER LIBCLI_DRSUAPI TORTURE_LDB_MODULE
# End SUBSYSTEM TORTURE_DRS
#################################

TORTURE_DRS_OBJ_FILES = \
		$(torturesrcdir)/drs/drs_init.o \
		$(torturesrcdir)/drs/drs_util.o \
		$(torturesrcdir)/drs/unit/schemainfo_tests.o \
		$(torturesrcdir)/drs/unit/prefixmap_tests.o

$(eval $(call proto_header_template,$(torturesrcdir)/drs/proto.h,$(TORTURE_DRS_OBJ_FILES:.o=.c)))
