# AUTH Server subsystem

#######################
# Start MODULE auth_sam
[MODULE::auth_sam]
INIT_OBJ_FILES = \
		auth/auth_sam.o
# End MODULE auth_sam
#######################

#######################
# Start MODULE auth_builtin
[MODULE::auth_builtin]
INIT_OBJ_FILES = \
		auth/auth_builtin.o
# End MODULE auth_builtin
#######################

#######################
# Start SUBSYSTEM AUTH
[SUBSYSTEM::AUTH]
INIT_OBJ_FILES = \
		auth/auth.o
ADD_OBJ_FILES = \
		auth/auth_ntlmssp.o \
		auth/auth_util.o \
		auth/pampass.o \
		auth/pass_check.o
# End SUBSYSTEM AUTH
#######################
