dnl # LIBSMB subsystem

[SUBSYSTEM::LIBSMB]
REQUIRED_SUBSYSTEMS = LIBCLI LIBRPC SOCKET
ADD_OBJ_LIST = libcli/clireadwrite.o \
		libcli/cliconnect.o \
		libcli/clifile.o \
		libcli/clilist.o \
		libcli/clitrans2.o \
		libcli/climessage.o \
		libcli/clideltree.o
