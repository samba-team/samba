dnl # LIBSMB subsystem

SMB_SUBSYSTEM(LIBSMB,[],
		[libcli/clireadwrite.o
		libcli/cliconnect.o
		libcli/clifile.o
		libcli/clilist.o
		libcli/clitrans2.o
		libcli/climessage.o
		libcli/clideltree.o],
		[],
		[LIBCLI LIBRPC SOCKET])
