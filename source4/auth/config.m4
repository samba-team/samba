dnl # AUTH Server subsystem

SMB_MODULE(auth_sam,AUTH,STATIC,[auth/auth_sam.o])
SMB_MODULE(auth_builtin,AUTH,STATIC,[auth/auth_builtin.o])

SMB_SUBSYSTEM(AUTH,auth/auth.o,
		[auth/auth_ntlmssp.o
		auth/auth_util.o
		auth/pampass.o
		auth/pass_check.o])
