dnl # SMB server subsystem

SMB_SUBSYSTEM(SMB,smb_server/smb_server.o,
		[smb_server/conn.o
		smb_server/connection.o
		smb_server/negprot.o
		smb_server/nttrans.o
		smb_server/password.o
		smb_server/reply.o
		smb_server/request.o
		smb_server/search.o
		smb_server/service.o
		smb_server/session.o
		smb_server/sesssetup.o
		smb_server/srvtime.o
		smb_server/trans2.o])
