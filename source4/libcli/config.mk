[SUBSYSTEM::LIBCLI_UTILS]
ADD_OBJ_FILES = libcli/util/asn1.o \
		libcli/util/smberr.o \
		libcli/util/doserr.o \
		libcli/util/errormap.o \
		libcli/util/clierror.o \
		libcli/util/nterr.o \
		libcli/util/smbdes.o \
		libcli/util/smbencrypt.o

[SUBSYSTEM::LIBCLI_LSA]
ADD_OBJ_FILES = libcli/util/clilsa.o
REQUIRED_SUBSYSTEMS = RPC_NDR_LSA

[SUBSYSTEM::LIBCLI_COMPOSITE]
ADD_OBJ_FILES = \
	libcli/composite/composite.o \
	libcli/composite/loadfile.o \
	libcli/composite/savefile.o \
	libcli/composite/connect.o \
	libcli/composite/sesssetup.o \
	libcli/composite/fetchfile.o

[SUBSYSTEM::LIBCLI_NBT]
ADD_OBJ_FILES = \
	libcli/nbt/nbtname.o \
	libcli/nbt/nbtsocket.o \
	libcli/nbt/namequery.o
REQUIRED_SUBSYSTEMS = NDR_NBT

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
	LIBCLI_COMPOSITE LIBCLI_NBT LIBCLI_RESOLVE
