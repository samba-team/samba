[SUBSYSTEM::LIBCLI_UTILS]
ADD_OBJ_FILES = libcli/util/asn1.o \
		libcli/util/doserr.o \
		libcli/util/errormap.o \
		libcli/util/clierror.o \
		libcli/util/nterr.o \
		libcli/util/smbdes.o

[SUBSYSTEM::LIBCLI_LSA]
ADD_OBJ_FILES = libcli/util/clilsa.o
REQUIRED_SUBSYSTEMS = RPC_NDR_LSA

[SUBSYSTEM::LIBCLI_COMPOSITE]
ADD_OBJ_FILES = \
	libcli/composite/composite.o
REQUIRED_SUBSYSTEMS = LIBEVENTS

[SUBSYSTEM::LIBCLI_SMB_COMPOSITE]
ADD_OBJ_FILES = \
	libcli/smb_composite/loadfile.o \
	libcli/smb_composite/savefile.o \
	libcli/smb_composite/connect.o \
	libcli/smb_composite/sesssetup.o \
	libcli/smb_composite/fetchfile.o \
	libcli/smb_composite/appendacl.o \
	libcli/smb_composite/fsinfo.o 
REQUIRED_SUBSYSTEMS = LIBCLI_COMPOSITE

[SUBSYSTEM::LIBCLI_NBT]
ADD_OBJ_FILES = \
	libcli/nbt/nbtname.o \
	libcli/nbt/nbtsocket.o \
	libcli/nbt/namequery.o \
	libcli/nbt/nameregister.o \
	libcli/nbt/namerefresh.o \
	libcli/nbt/namerelease.o
REQUIRED_SUBSYSTEMS = NDR_RAW NDR_NBT SOCKET LIBCLI_COMPOSITE LIBEVENTS \
	LIB_SECURITY_NDR

[SUBSYSTEM::LIBCLI_DGRAM]
ADD_OBJ_FILES = \
	libcli/dgram/dgramsocket.o \
	libcli/dgram/mailslot.o \
	libcli/dgram/netlogon.o \
	libcli/dgram/ntlogon.o \
	libcli/dgram/browse.o
NOPROTO=YES
REQUIRED_SUBSYSTEMS = LIBCLI_NBT

[SUBSYSTEM::LIBCLI_CLDAP]
ADD_OBJ_FILES = \
	libcli/cldap/cldap.o
NOPROTO=YES
REQUIRED_SUBSYSTEMS = LIBCLI_LDAP

[SUBSYSTEM::LIBCLI_WREPL]
ADD_OBJ_FILES = \
	libcli/wrepl/winsrepl.o
REQUIRED_SUBSYSTEMS = NDR_WINSREPL SOCKET LIBEVENTS

[SUBSYSTEM::LIBCLI_RESOLVE]
ADD_OBJ_FILES = \
	libcli/resolve/resolve.o \
	libcli/resolve/nbtlist.o \
	libcli/resolve/bcast.o \
	libcli/resolve/wins.o \
	libcli/resolve/host.o
REQUIRED_SUBSYSTEMS = LIBCLI_NBT

[SUBSYSTEM::LIBCLI]
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBCLI_UTILS LIBCLI_AUTH \
	LIBCLI_SMB_COMPOSITE LIBCLI_NBT LIB_SECURITY LIBCLI_RESOLVE \
	LIBCLI_DGRAM

[SUBSYSTEM::LIBSMB]
REQUIRED_SUBSYSTEMS = LIBCLI SOCKET
ADD_OBJ_FILES = libcli/clireadwrite.o \
		libcli/cliconnect.o \
		libcli/clifile.o \
		libcli/clilist.o \
		libcli/clitrans2.o \
		libcli/climessage.o \
		libcli/clideltree.o

[SUBSYSTEM::LIBCLI_RAW]
REQUIRED_SUBSYSTEMS = LIBCLI_RAW_KRB5
OBJ_FILES = libcli/raw/rawfile.o \
		libcli/raw/smb_signing.o \
		libcli/raw/clisocket.o \
		libcli/raw/clitransport.o \
		libcli/raw/clisession.o \
		libcli/raw/clitree.o \
		libcli/raw/rawrequest.o \
		libcli/raw/rawreadwrite.o \
		libcli/raw/rawsearch.o \
		libcli/raw/rawsetfileinfo.o \
		libcli/raw/raweas.o \
		libcli/raw/rawtrans.o \
		libcli/raw/clioplock.o \
		libcli/raw/rawnegotiate.o \
		libcli/raw/rawfsinfo.o \
		libcli/raw/rawfileinfo.o \
		libcli/raw/rawnotify.o \
		libcli/raw/rawioctl.o \
		libcli/raw/rawacl.o \
		libcli/raw/rawdate.o \
		libcli/raw/rawlpq.o
