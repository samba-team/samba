include auth/config.mk
include ldap/config.mk
include security/config.mk

[SUBSYSTEM::LIBCLI_UTILS]
PRIVATE_PROTO_HEADER = util/proto.h
PUBLIC_HEADERS = util/nterr.h util/doserr.h util/nt_status.h
OBJ_FILES = util/asn1.o \
		util/doserr.o \
		util/errormap.o \
		util/clierror.o \
		util/nterr.o \
		util/smbdes.o

[SUBSYSTEM::LIBCLI_LSA]
PRIVATE_PROTO_HEADER = util/clilsa.h
OBJ_FILES = util/clilsa.o
REQUIRED_SUBSYSTEMS = RPC_NDR_LSA

[SUBSYSTEM::LIBCLI_COMPOSITE]
PRIVATE_PROTO_HEADER = composite/proto.h
OBJ_FILES = \
	composite/composite.o
REQUIRED_SUBSYSTEMS = LIBEVENTS

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
REQUIRED_SUBSYSTEMS = LIBCLI_COMPOSITE

[SUBSYSTEM::NDR_NBT_BUF]
OBJ_FILES = nbt/nbtname.o\

[LIBRARY::LIBCLI_NBT]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = NetBios over TCP/IP client library
PRIVATE_PROTO_HEADER = nbt/nbt_proto.h
OBJ_FILES = \
	nbt/nbtsocket.o \
	nbt/namequery.o \
	nbt/nameregister.o \
	nbt/namerefresh.o \
	nbt/namerelease.o
REQUIRED_SUBSYSTEMS = LIBNDR NDR_NBT SOCKET LIBCLI_COMPOSITE LIBEVENTS \
	NDR_SECURITY

[SUBSYSTEM::LIBCLI_DGRAM]
OBJ_FILES = \
	dgram/dgramsocket.o \
	dgram/mailslot.o \
	dgram/netlogon.o \
	dgram/ntlogon.o \
	dgram/browse.o
NOPROTO=YES
REQUIRED_SUBSYSTEMS = LIBCLI_NBT

[LIBRARY::LIBCLI_CLDAP]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = CLDAP client library
OBJ_FILES = cldap/cldap.o
PUBLIC_HEADERS = cldap/cldap.h
NOPROTO=YES
REQUIRED_SUBSYSTEMS = LIBCLI_LDAP

[LIBRARY::LIBCLI_WREPL]
PRIVATE_PROTO_HEADER = wrepl/winsrepl_proto.h
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = WINS Replication client library
OBJ_FILES = \
	wrepl/winsrepl.o
REQUIRED_SUBSYSTEMS = NDR_WINSREPL SOCKET LIBEVENTS

[SUBSYSTEM::LIBCLI_RESOLVE]
PRIVATE_PROTO_HEADER = resolve/resolve.h
OBJ_FILES = \
	resolve/resolve.o \
	resolve/nbtlist.o \
	resolve/bcast.o \
	resolve/wins.o \
	resolve/host.o
REQUIRED_SUBSYSTEMS = LIBCLI_NBT LIBNETIF

[SUBSYSTEM::LIBCLI_FINDDCS]
PRIVATE_PROTO_HEADER = finddcs.h
OBJ_FILES = \
	finddcs.o
REQUIRED_SUBSYSTEMS = LIBCLI_NBT MESSAGING

[LIBRARY::LIBCLI]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = SMB/CIFS client library
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBCLI_UTILS LIBCLI_AUTH \
	LIBCLI_SMB_COMPOSITE LIBCLI_NBT LIB_SECURITY LIBCLI_RESOLVE \
	LIBCLI_DGRAM LIBCLI_SMB2 LIBCLI_FINDDCS

[SUBSYSTEM::LIBSMB]
REQUIRED_SUBSYSTEMS = LIBCLI SOCKET
PRIVATE_PROTO_HEADER = libcli_proto.h
OBJ_FILES = clireadwrite.o \
		cliconnect.o \
		clifile.o \
		clilist.o \
		clitrans2.o \
		climessage.o \
		clideltree.o

[SUBSYSTEM::LIBCLI_RAW]
PRIVATE_PROTO_HEADER = raw/raw_proto.h
REQUIRED_SUBSYSTEMS = LIBCLI_RAW_KRB5
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
REQUIRED_SUBSYSTEMS = LIBPACKET GENSEC

include smb2/config.mk
