dnl # TORTURE subsystem

SMB_SUBSYSTEM(TORTURE_BASIC,[],
		[torture/basic/scanner.o
		torture/basic/utable.o
		torture/basic/charset.o
		torture/basic/mangle_test.o
		torture/basic/denytest.o
		torture/basic/aliases.o],
		[],
		[LIBSMB])

SMB_SUBSYSTEM(TORTURE_RAW,[],
		[torture/raw/qfsinfo.o
		torture/raw/qfileinfo.o
		torture/raw/setfileinfo.o
		torture/raw/search.o
		torture/raw/close.o
		torture/raw/open.o
		torture/raw/mkdir.o
		torture/raw/oplock.o
		torture/raw/notify.o
		torture/raw/mux.o
		torture/raw/ioctl.o
		torture/raw/chkpath.o
		torture/raw/unlink.o
		torture/raw/read.o
		torture/raw/context.o
		torture/raw/write.o
		torture/raw/lock.o
		torture/raw/rename.o
		torture/raw/seek.o],
		[],
		[LIBSMB])

SMB_SUBSYSTEM(TORTURE_RPC,[],
		[torture/rpc/lsa.o
		torture/rpc/echo.o
		torture/rpc/dfs.o
		torture/rpc/spoolss.o
		torture/rpc/samr.o
		torture/rpc/wkssvc.o
		torture/rpc/srvsvc.o
		torture/rpc/atsvc.o
		torture/rpc/eventlog.o
		torture/rpc/epmapper.o
		torture/rpc/winreg.o
		torture/rpc/mgmt.o
		torture/rpc/scanner.o
		torture/rpc/autoidl.o
		torture/rpc/netlogon.o],
		[],
		[LIBSMB])

SMB_SUBSYSTEM(TORTURE_NBENCH,[],
		[torture/nbench/nbio.o
		torture/nbench/nbench.o])

SMB_BINARY(smbtorture, [ALL], [BIN],
		[torture/torture.o
		torture/torture_util.o
		libcli/raw/clirewrite.o],
		[],
		[TORTURE_BASIC TORTURE_RAW TORTURE_RPC TORTURE_NBENCH CONFIG LIBCMDLINE LIBBASIC])
