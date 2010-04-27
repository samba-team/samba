[SUBSYSTEM::policy]
PRIVATE_DEPENDENCIES = LIBLDB LIBSAMBA-NET

policy_OBJ_FILES = $(policydir)/gp_ldap.o $(policydir)/gp_filesys.c

PC_FILES += $(policydir)/policy.pc
