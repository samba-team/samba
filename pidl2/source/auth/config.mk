# AUTH Server subsystem

#######################
# Start MODULE auth_sam
[MODULE::auth_sam]
INIT_FUNCTION = auth_sam_init
SUBSYSTEM = AUTH
INIT_OBJ_FILES = \
		auth/auth_sam.o
REQUIRED_SUBSYSTEMS = \
		SAMDB
# End MODULE auth_sam
#######################

#######################
# Start MODULE auth_anonymous
[MODULE::auth_anonymous]
INIT_FUNCTION = auth_anonymous_init
SUBSYSTEM = AUTH
INIT_OBJ_FILES = \
		auth/auth_anonymous.o
# End MODULE auth_anonymous
#######################

#######################
# Start MODULE auth_winbind
[MODULE::auth_winbind]
INIT_FUNCTION = auth_winbind_init
SUBSYSTEM = AUTH
INIT_OBJ_FILES = \
		auth/auth_winbind.o
REQUIRED_SUBSYSTEMS = \
		LIB_WINBIND_CLIENT \
		NDR_NETLOGON NDR
# End MODULE auth_winbind
#######################

#######################
# Start MODULE auth_domain
[MODULE::auth_domain]
INIT_FUNCTION = auth_domain_init
SUBSYSTEM = AUTH
INIT_OBJ_FILES = \
		auth/auth_domain.o
REQUIRED_SUBSYSTEMS = \
		NDR_NETLOGON NDR
# End MODULE auth_winbind
#######################

#######################
# Start MODULE auth_developer
[MODULE::auth_developer]
INIT_FUNCTION = auth_developer_init
SUBSYSTEM = AUTH
INIT_OBJ_FILES = \
		auth/auth_developer.o
# End MODULE auth_developer
#######################

#######################
# Start SUBSYSTEM AUTH
[SUBSYSTEM::AUTH]
INIT_OBJ_FILES = \
		auth/auth.o
ADD_OBJ_FILES = \
		auth/auth_util.o \
		auth/ntlm_check.o
# End SUBSYSTEM AUTH
#######################
