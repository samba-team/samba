# Registry backends

################################################
# Start MODULE registry_nt4
[MODULE::registry_nt4]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_nt4/reg_backend_nt4.o
# End MODULE registry_nt4
################################################

################################################
# Start MODULE registry_w95
[MODULE::registry_w95]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_w95/reg_backend_w95.o
# End MODULE registry_w95
################################################

################################################
# Start MODULE registry_dir
[MODULE::registry_dir]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_dir/reg_backend_dir.o
# End MODULE registry_dir
################################################

################################################
# Start MODULE registry_rpc
[MODULE::registry_rpc]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_rpc/reg_backend_rpc.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB
# End MODULE registry_rpc
################################################

################################################
# Start MODULE registry_gconf
[MODULE::registry_gconf]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_gconf/reg_backend_gconf.o
REQUIRED_LIBRARIES = \
		gconf
# End MODULE registry_gconf
################################################

################################################
# Start MODULE registry_ldb
[MODULE::registry_ldb]
INIT_OBJ_FILES = \
		lib/registry/reg_backend_ldb/reg_backend_ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB
# End MODULE registry_ldb
################################################

################################################
# Start SUBSYSTEM REGISTRY
[SUBSYSTEM::REGISTRY]
INIT_OBJ_FILES = \
		lib/registry/common/reg_interface.o
ADD_OBJ_FILES = \
		lib/registry/common/reg_objects.o \
		lib/registry/common/reg_util.o
REQUIRED_SUBSYSTEMS = \
		LIBBASIC
# End MODULE registry_ldb
################################################

################################################
# Start LIBRARY libwinregistry
[LIBRARY::libwinregistry]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
REQUIRED_SUBSYSTEMS = \
		REGISTRY
#
# End LIBRARY libwinregistry
################################################

################################################
# Start BINARY regdiff
[BINARY::regdiff]
OBJ_FILES= \
		lib/registry/tools/regdiff.o
REQUIRED_SUBSYSTEMS = \
		CONFIG LIBCMDLINE REGISTRY
# End BINARY regdiff
################################################

################################################
# Start BINARY regpatch
[BINARY::regpatch]
OBJ_FILES= \
		lib/registry/tools/regpatch.o
REQUIRED_SUBSYSTEMS = \
		CONFIG LIBCMDLINE REGISTRY
# End BINARY regpatch
################################################

################################################
# Start BINARY regshell
[BINARY::regshell]
OBJ_FILES= \
		lib/registry/tools/regshell.o
REQUIRED_SUBSYSTEMS = \
		CONFIG LIBCMDLINE REGISTRY
# End BINARY regshell
################################################

################################################
# Start BINARY regtree
[BINARY::regtree]
OBJ_FILES= \
		lib/registry/tools/regtree.o
REQUIRED_SUBSYSTEMS = \
		CONFIG LIBCMDLINE REGISTRY
# End BINARY regtree
################################################

################################################
# Start BINARY gregedit
[BINARY::gregedit]
OBJ_FILES= \
		lib/registry/tools/gregedit.o
REQUIRED_LIBRARIES = \
		gtk
REQUIRED_SUBSYSTEMS = \
		CONFIG LIBCMDLINE REGISTRY
# End BINARY gregedit
################################################
