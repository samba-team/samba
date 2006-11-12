include auth/config.mk
include ldap/config.mk
include security/config.mk

[SUBSYSTEM::LIBSAMBA-ERRORS]
PUBLIC_PROTO_HEADER = util/proto.h
PUBLIC_HEADERS = util/error.h util/nterr.h util/doserr.h util/nt_status.h
OBJ_FILES = util/doserr.o \
		util/errormap.o \
		util/clierror.o \
		util/nterr.o \

[SUBSYSTEM::ASN1_UTIL]
PUBLIC_PROTO_HEADER = util/asn1_proto.h
PUBLIC_HEADERS = util/asn_1.h
OBJ_FILES = util/asn1.o

[SUBSYSTEM::LIBCLI_LSA]
PRIVATE_PROTO_HEADER = util/clilsa.h
OBJ_FILES = util/clilsa.o
PUBLIC_DEPENDENCIES = RPC_NDR_LSA

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
PUBLIC_DEPENDENCIES = LIBCLI_COMPOSITE CREDENTIALS

[SUBSYSTEM::NDR_NBT_BUF]
PRIVATE_PROTO_HEADER = nbt/nbtname.h
OBJ_FILES = nbt/nbtname.o

[SUBSYSTEM::LIBCLI_NBT]
#VERSION = 0.0.1
#SO_VERSION = 0
#DESCRIPTION = NetBios over TCP/IP client library
PRIVATE_PROTO_HEADER = nbt/nbt_proto.h
OBJ_FILES = \
	nbt/nbtsocket.o \
	nbt/namequery.o \
	nbt/nameregister.o \
	nbt/namerefresh.o \
	nbt/namerelease.o
PUBLIC_DEPENDENCIES = LIBNDR NDR_NBT LIBCLI_COMPOSITE LIBEVENTS \
	NDR_SECURITY samba-socket LIBSAMBA-UTIL

[LIBRARY::swig_libcli_nbt]
LIBRARY_REALNAME = swig/_libcli_nbt.$(SHLIBEXT)
OBJ_FILES = swig/libcli_nbt_wrap.o
PUBLIC_DEPENDENCIES = LIBCLI_NBT DYNCONFIG LIBSAMBA-CONFIG

[SUBSYSTEM::LIBCLI_DGRAM]
OBJ_FILES = \
	dgram/dgramsocket.o \
	dgram/mailslot.o \
	dgram/netlogon.o \
	dgram/ntlogon.o \
	dgram/browse.o
PUBLIC_DEPENDENCIES = LIBCLI_NBT

[LIBRARY::LIBCLI_CLDAP]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = CLDAP client library
OBJ_FILES = cldap/cldap.o
PUBLIC_HEADERS = cldap/cldap.h
PUBLIC_DEPENDENCIES = LIBCLI_LDAP
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL ldb

[LIBRARY::LIBCLI_WREPL]
PRIVATE_PROTO_HEADER = wrepl/winsrepl_proto.h
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = WINS Replication client library
OBJ_FILES = \
	wrepl/winsrepl.o
PUBLIC_DEPENDENCIES = NDR_WINSREPL samba-socket LIBCLI_RESOLVE LIBEVENTS LIBPACKET

[SUBSYSTEM::LIBCLI_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/proto.h
OBJ_FILES = \
	resolve/resolve.o \
	resolve/bcast.o \
	resolve/nbtlist.o \
	resolve/wins.o \
	resolve/host.o
PUBLIC_DEPENDENCIES = LIBNETIF
PRIVATE_DEPENDENCIES = LIBCLI_NBT 

[SUBSYSTEM::LIBCLI_FINDDCS]
PRIVATE_PROTO_HEADER = finddcs.h
OBJ_FILES = \
	finddcs.o
PUBLIC_DEPENDENCIES = LIBCLI_NBT MESSAGING

[LIBRARY::LIBCLI_SMB]
PUBLIC_HEADERS = libcli.h
PUBLIC_PROTO_HEADER = libcli_proto.h
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = SMB/CIFS client library
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

[SUBSYSTEM::LIBCLI_RAW]
PRIVATE_PROTO_HEADER = raw/raw_proto.h
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE 
PUBLIC_DEPENDENCIES = samba-socket LIBPACKET gensec LIBCRYPTO
LDFLAGS = $(SUBSYSTEM_LIBCLI_SMB_COMPOSITE_OUTPUT)
OBJ_FILES = raw/rawfile.o \
		raw/smb_signing.o \
		raw/clisocket.o \
		raw/clitransport.o \
		raw/clisession.o \
		raw/clitree.o \
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
		raw/rawlpq.o

include smb2/config.mk
