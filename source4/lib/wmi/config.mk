#################################
# Start BINARY wmic
[BINARY::wmic]
PRIVATE_PROTO_HEADER = proto.h
INSTALLDIR = BINDIR
OBJ_FILES = \
                wmic.o \
		wmicore.o \
		wbemdata.o \
		../librpc/gen_ndr/dcom_p.o
PRIVATE_DEPENDENCIES = \
                POPT_SAMBA \
                POPT_CREDENTIALS \
                LIBPOPT \
		RPC_NDR_OXIDRESOLVER \
		NDR_DCOM \
		RPC_NDR_REMACT \
		NDR_TABLE \
		DCOM_PROXY_DCOM \
		dcom
# End BINARY wmic
#################################

#################################
# Start BINARY wmis
[BINARY::wmis]
INSTALLDIR = BINDIR
OBJ_FILES = \
                wmis.o \
		wmicore.o \
		wbemdata.o \
		../librpc/gen_ndr/dcom_p.o
PRIVATE_DEPENDENCIES = \
                POPT_SAMBA \
                POPT_CREDENTIALS \
                LIBPOPT \
		RPC_NDR_OXIDRESOLVER \
		NDR_DCOM \
		RPC_NDR_REMACT \
		NDR_TABLE \
		DCOM_PROXY_DCOM \
		dcom
# End BINARY wmis
#################################

librpc/gen_ndr/dcom_p.c: idl

#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::pywmi]
LIBRARY_REALNAME = _pywmi.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBCLI_SMB NDR_MISC LIBSAMBA-UTIL LIBSAMBA-CONFIG RPC_NDR_SAMR RPC_NDR_LSA DYNCONFIG \
		RPC_NDR_OXIDRESOLVER \
		NDR_DCOM \
		RPC_NDR_REMACT \
		NDR_TABLE \
		DCOM_PROXY_DCOM \
		dcom \
		RPC_NDR_WINREG
OBJ_FILES = wbemdata.o \
	    wmicore.o \
	    ../librpc/gen_ndr/dcom_p.o \
	    pywmi_wrap.o
# End LIBRARY swig_dcerpc
#######################

#################################
# Start BINARY pdhc
#[BINARY::pdhc]
#INSTALLDIR = BINDIR
#OBJ_FILES = \
#                pdhc.o
#PRIVATE_DEPENDENCIES = \
#                POPT_SAMBA \
#                POPT_CREDENTIALS \
#                LIBPOPT \
#		NDR_TABLE \
#		RPC_NDR_WINREG
# End BINARY pdhc
#################################

