mkinclude auth/config.mk
mkinclude ldap/config.mk
mkinclude security/config.mk
mkinclude wbclient/config.mk

[SUBSYSTEM::LIBSAMBA-ERRORS]

LIBSAMBA-ERRORS_OBJ_FILES = $(addprefix libcli/util/, doserr.o errormap.o nterr.o)

PUBLIC_HEADERS += $(addprefix libcli/, util/error.h util/ntstatus.h util/doserr.h util/werror.h)

[SUBSYSTEM::LIBCLI_LSA]
PRIVATE_PROTO_HEADER = util/clilsa.h
PUBLIC_DEPENDENCIES = RPC_NDR_LSA
PRIVATE_DEPENDENCIES = LIBSECURITY

LIBCLI_LSA_OBJ_FILES = libcli/util/clilsa.o

[SUBSYSTEM::LIBCLI_COMPOSITE]
PRIVATE_PROTO_HEADER = composite/proto.h
PUBLIC_DEPENDENCIES = LIBEVENTS

LIBCLI_COMPOSITE_OBJ_FILES = libcli/composite/composite.o

[SUBSYSTEM::LIBCLI_SMB_COMPOSITE]
PRIVATE_PROTO_HEADER = smb_composite/proto.h
PUBLIC_DEPENDENCIES = LIBCLI_COMPOSITE CREDENTIALS gensec LIBCLI_RESOLVE

LIBCLI_SMB_COMPOSITE_OBJ_FILES = $(addprefix libcli/smb_composite/, \
	loadfile.o \
	savefile.o \
	connect.o \
	sesssetup.o \
	fetchfile.o \
	appendacl.o \
	fsinfo.o)


[SUBSYSTEM::NDR_NBT_BUF]
PRIVATE_PROTO_HEADER = nbt/nbtname.h

NDR_NBT_BUF_OBJ_FILES = libcli/nbt/nbtname.o

[SUBSYSTEM::LIBCLI_NBT]
#VERSION = 0.0.1
#SO_VERSION = 0
PRIVATE_PROTO_HEADER = nbt/nbt_proto.h
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT LIBCLI_COMPOSITE LIBEVENTS \
	NDR_SECURITY samba-socket LIBSAMBA-UTIL

LIBCLI_NBT_OBJ_FILES = $(addprefix libcli/nbt/, \
	nbtsocket.o \
	namequery.o \
	nameregister.o \
	namerefresh.o \
	namerelease.o)

[PYTHON::python_libcli_nbt]
SWIG_FILE = swig/libcli_nbt.i
PUBLIC_DEPENDENCIES = LIBCLI_NBT DYNCONFIG LIBSAMBA-HOSTCONFIG

python_libcli_nbt_OBJ_FILES = libcli/swig/libcli_nbt_wrap.o

[PYTHON::python_libcli_smb]
SWIG_FILE = swig/libcli_smb.i
PUBLIC_DEPENDENCIES = LIBCLI_SMB DYNCONFIG LIBSAMBA-HOSTCONFIG

python_libcli_smb_OBJ_FILES = libcli/swig/libcli_smb_wrap.o

[SUBSYSTEM::LIBCLI_DGRAM]
PUBLIC_DEPENDENCIES = LIBCLI_NBT LIBNDR LIBCLI_RESOLVE

LIBCLI_DGRAM_OBJ_FILES = $(addprefix libcli/dgram/, \
	dgramsocket.o \
	mailslot.o \
	netlogon.o \
	ntlogon.o \
	browse.o)

[SUBSYSTEM::LIBCLI_CLDAP]
PUBLIC_DEPENDENCIES = LIBCLI_LDAP
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBLDB

LIBCLI_CLDAP_OBJ_FILES = libcli/cldap/cldap.o
# PUBLIC_HEADERS += libcli/cldap/cldap.h

[SUBSYSTEM::LIBCLI_WREPL]
PRIVATE_PROTO_HEADER = wrepl/winsrepl_proto.h
PUBLIC_DEPENDENCIES = NDR_WINSREPL samba-socket LIBCLI_RESOLVE LIBEVENTS \
					  LIBPACKET LIBNDR

LIBCLI_WREPL_OBJ_FILES = libcli/wrepl/winsrepl.o

[SUBSYSTEM::LIBCLI_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/proto.h
PUBLIC_DEPENDENCIES = NDR_NBT

LIBCLI_RESOLVE_OBJ_FILES = libcli/resolve/resolve.o

[SUBSYSTEM::LP_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/lp_proto.h
PRIVATE_DEPENDENCIES = LIBCLI_NBT LIBSAMBA-HOSTCONFIG LIBNETIF 

LP_RESOLVE_OBJ_FILES = $(addprefix libcli/resolve/, \
					  bcast.o nbtlist.o wins.o \
					  host.o resolve_lp.o)

[SUBSYSTEM::LIBCLI_FINDDCS]
PRIVATE_PROTO_HEADER = finddcs.h
PUBLIC_DEPENDENCIES = LIBCLI_NBT MESSAGING

LIBCLI_FINDDCS_OBJ_FILES = libcli/finddcs.o

[SUBSYSTEM::LIBCLI_SMB]
PRIVATE_PROTO_HEADER = libcli_proto.h
PUBLIC_DEPENDENCIES = LIBCLI_RAW LIBSAMBA-ERRORS LIBCLI_AUTH \
	LIBCLI_SMB_COMPOSITE LIBCLI_NBT LIBSECURITY LIBCLI_RESOLVE \
	LIBCLI_DGRAM LIBCLI_SMB2 LIBCLI_FINDDCS samba-socket

LIBCLI_SMB_OBJ_FILES = $(addprefix libcli/, \
		clireadwrite.o \
		cliconnect.o \
		clifile.o \
		clilist.o \
		clitrans2.o \
		climessage.o \
		clideltree.o)

# PUBLIC_HEADERS += libcli/libcli.h

[SUBSYSTEM::LIBCLI_RAW]
PRIVATE_PROTO_HEADER = raw/raw_proto.h
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE LP_RESOLVE gensec LIBCLI_RESOLVE LIBSECURITY LIBNDR
#LDFLAGS = $(LIBCLI_SMB_COMPOSITE_OUTPUT)
PUBLIC_DEPENDENCIES = samba-socket LIBPACKET gensec LIBCRYPTO CREDENTIALS 

LIBCLI_RAW_OBJ_FILES = $(addprefix libcli/raw/, rawfile.o smb_signing.o clisocket.o \
					  clitransport.o clisession.o clitree.o clierror.o rawrequest.o \
					  rawreadwrite.o rawsearch.o rawsetfileinfo.o raweas.o rawtrans.o \
					  clioplock.o rawnegotiate.o rawfsinfo.o rawfileinfo.o rawnotify.o \
					  rawioctl.o rawacl.o rawdate.o rawlpq.o rawshadow.o)

mkinclude smb2/config.mk
