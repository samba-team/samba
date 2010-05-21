[SUBSYSTEM::policy]
PRIVATE_DEPENDENCIES = LIBLDB LIBSAMBA-NET

policy_OBJ_FILES = $(policydir)/gp_ldap.o $(policydir)/gp_filesys.c $(policydir)/gp_manage.c $(policydir)/gp_ini.c

PC_FILES += $(policydir)/policy.pc
