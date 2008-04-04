mkinclude auth/config.mk
mkinclude ldap/config.mk
mkinclude security/config.mk
mkinclude wbclient/config.mk

[SUBSYSTEM::LIBSAMBA-ERRORS]
OBJ_FILES = util/doserr.o \
		    util/errormap.o \
		    util/nterr.o \


PUBLIC_HEADERS += $(addprefix libcli/, util/error.h util/ntstatus.h util/doserr.h util/werror.h)

[SUBSYSTEM::LIBCLI_LSA]
PRIVATE_PROTO_HEADER = util/clilsa.h
OBJ_FILES = util/clilsa.o
PUBLIC_DEPENDENCIES = RPC_NDR_LSA
PRIVATE_DEPENDENCIES = LIBSECURITY

[SUBSYSTEM::LIBCLI_COMPOSITE]
PRIVATE_PROTO_HEADER = composite/proto.h
OBJ_FILES = \
	composite/composite.o
PUBLIC_DEPENDENCIES = LIBEVENTS

[SUBSYSTEM::LIBCLI_SMB_COMPOSITE]
PRIVATE_PROTO_HEADER = smb_composite/proto.h
OBJ_FILES = \
	smb_composite/loadfile.o \
	smb_composite/savefile.o \
	smb_composite/connect.o \
	smb_composite/sesssetup.o \
	smb_composite/fetchfile.o \
	smb_composite/appendacl.o \
	smb_composite/fsinfo.o 
PUBLIC_DEPENDENCIES = LIBCLI_COMPOSITE CREDENTIALS gensec LIBCLI_RESOLVE

[SUBSYSTEM::NDR_NBT_BUF]
PRIVATE_PROTO_HEADER = nbt/nbtname.h
OBJ_FILES = nbt/nbtname.o

[SUBSYSTEM::LIBCLI_NBT]
#VERSION = 0.0.1
#SO_VERSION = 0
PRIVATE_PROTO_HEADER = nbt/nbt_proto.h
OBJ_FILES = \
	nbt/nbtsocket.o \
	nbt/namequery.o \
	nbt/nameregister.o \
	nbt/namerefresh.o \
	nbt/namerelease.o
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT LIBCLI_COMPOSITE LIBEVENTS \
	NDR_SECURITY samba-socket LIBSAMBA-UTIL

[PYTHON::python_libcli_nbt]
SWIG_FILE = swig/libcli_nbt.i
PUBLIC_DEPENDENCIES = LIBCLI_NBT DYNCONFIG LIBSAMBA-HOSTCONFIG

[PYTHON::python_libcli_smb]
SWIG_FILE = swig/libcli_smb.i
PUBLIC_DEPENDENCIES = LIBCLI_SMB DYNCONFIG LIBSAMBA-HOSTCONFIG

[SUBSYSTEM::LIBCLI_DGRAM]
OBJ_FILES = \
	dgram/dgramsocket.o \
	dgram/mailslot.o \
	dgram/netlogon.o \
	dgram/ntlogon.o \
	dgram/browse.o
PUBLIC_DEPENDENCIES = LIBCLI_NBT LIBNDR LIBCLI_RESOLVE

[SUBSYSTEM::LIBCLI_CLDAP]
OBJ_FILES = cldap/cldap.o
PUBLIC_DEPENDENCIES = LIBCLI_LDAP
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBLDB

# PUBLIC_HEADERS += libcli/cldap/cldap.h

[SUBSYSTEM::LIBCLI_WREPL]
PRIVATE_PROTO_HEADER = wrepl/winsrepl_proto.h
OBJ_FILES = \
	wrepl/winsrepl.o
PUBLIC_DEPENDENCIES = NDR_WINSREPL samba-socket LIBCLI_RESOLVE LIBEVENTS \
					  LIBPACKET LIBNDR

[SUBSYSTEM::LIBCLI_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/proto.h
OBJ_FILES = \
	resolve/resolve.o
PUBLIC_DEPENDENCIES = NDR_NBT

[SUBSYSTEM::LP_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/lp_proto.h
OBJ_FILES = \
	resolve/bcast.o \
	resolve/nbtlist.o \
	resolve/wins.o \
	resolve/host.o \
	resolve/resolve_lp.o
PRIVATE_DEPENDENCIES = LIBCLI_NBT LIBSAMBA-HOSTCONFIG LIBNETIF 

[SUBSYSTEM::LIBCLI_FINDDCS]
PRIVATE_PROTO_HEADER = finddcs.h
OBJ_FILES = \
	finddcs.o
PUBLIC_DEPENDENCIES = LIBCLI_NBT MESSAGING

[SUBSYSTEM::LIBCLI_SMB]
PRIVATE_PROTO_HEADER = libcli_proto.h
OBJ_FILES = clireadwrite.o \
		cliconnect.o \
		clifile.o \
		clilist.o \
		clitrans2.o \
		climessage.o \
		clideltree.o
PUBLIC_DEPENDENCIES = LIBCLI_RAW LIBSAMBA-ERRORS LIBCLI_AUTH \
	LIBCLI_SMB_COMPOSITE LIBCLI_NBT LIBSECURITY LIBCLI_RESOLVE \
	LIBCLI_DGRAM LIBCLI_SMB2 LIBCLI_FINDDCS samba-socket


# PUBLIC_HEADERS += libcli/libcli.h

[SUBSYSTEM::LIBCLI_RAW]
PRIVATE_PROTO_HEADER = raw/raw_proto.h
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE LP_RESOLVE gensec LIBCLI_RESOLVE LIBSECURITY LIBNDR
#LDFLAGS = $(LIBCLI_SMB_COMPOSITE_OUTPUT)
PUBLIC_DEPENDENCIES = samba-socket LIBPACKET gensec LIBCRYPTO CREDENTIALS 
OBJ_FILES = raw/rawfile.o \
		raw/smb_signing.o \
		raw/clisocket.o \
		raw/clitransport.o \
		raw/clisession.o \
		raw/clitree.o \
		raw/clierror.o \
		raw/rawrequest.o \
		raw/rawreadwrite.o \
		raw/rawsearch.o \
		raw/rawsetfileinfo.o \
		raw/raweas.o \
		raw/rawtrans.o \
		raw/clioplock.o \
		raw/rawnegotiate.o \
		raw/rawfsinfo.o \
		raw/rawfileinfo.o \
		raw/rawnotify.o \
		raw/rawioctl.o \
		raw/rawacl.o \
		raw/rawdate.o \
		raw/rawlpq.o \
		raw/rawshadow.o

mkinclude smb2/config.mk
