[SUBSYSTEM::LIBCLI_UTILS]
ADD_OBJ_FILES = libcli/util/asn1.o \
		libcli/util/smberr.o \
		libcli/util/doserr.o \
		libcli/util/errormap.o \
		libcli/util/clierror.o \
		libcli/util/nterr.o \
		libcli/util/smbdes.o \
		libcli/util/smbencrypt.o

[SUBSYSTEM::LIBCLI_NMB]
ADD_OBJ_FILES = libcli/unexpected.o \
		libcli/namecache.o \
		libcli/nmblib.o \
		libcli/namequery.o

[SUBSYSTEM::LIBCLI]
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBCLI_UTILS LIBCLI_AUTH LIBCLI_NMB
