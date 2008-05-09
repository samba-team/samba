[SUBSYSTEM::WMI]
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = RPC_NDR_OXIDRESOLVER \
		NDR_DCOM \
		RPC_NDR_REMACT \
		NDR_TABLE \
		DCOM_PROXY_DCOM \
		DCOM

WMI_OBJ_FILES = $(addprefix lib/wmi/, wmicore.o wbemdata.o ../../librpc/gen_ndr/dcom_p.o)

#################################
# Start BINARY wmic
[BINARY::wmic]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
                POPT_SAMBA \
                POPT_CREDENTIALS \
                LIBPOPT \
				WMI

wmic_OBJ_FILES = lib/wmi/tools/wmic.o
# End BINARY wmic
#################################

#################################
# Start BINARY wmis
[BINARY::wmis]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
                POPT_SAMBA \
                POPT_CREDENTIALS \
                LIBPOPT \
				WMI

wmis_OBJ_FILES = \
                lib/wmi/tools/wmis.o

# End BINARY wmis
#################################

librpc/gen_ndr/dcom_p.c: idl

#######################
# Start LIBRARY swig_dcerpc
[PYTHON::pywmi]
PUBLIC_DEPENDENCIES = LIBCLI_SMB NDR_MISC LIBSAMBA-UTIL LIBSAMBA-CONFIG WMI
SWIG_FILE = pywmi.i

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
