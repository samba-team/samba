dnl SMB Build System
dnl ----------------
dnl ----------------
dnl
dnl SMB_MODULE_DEFAULT(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_MODULE	( 
dnl		1:name,
dnl		2:subsystem,
dnl		3:default_build,
dnl		4:init_obj_file,
dnl		5:add_obj_files,
dnl		6:required_libs,
dnl		7:required_subsystems
dnl		)
dnl
dnl SMB_MODULE_MK(
dnl		1:name,
dnl		2:subsystem,
dnl		3:default_build,
dnl		4:config_mk_file
dnl		)
dnl
dnl SMB_SUBSYSTEM_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_SUBSYSTEM(
dnl		1:name,
dnl		2:init_obj_file,
dnl		3:add_obj_files,
dnl		4:required_libs,
dnl		5:required_subsystems
dnl		)
dnl
dnl SMB_SUBSYSTEM_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
dnl
dnl SMB_EXT_LIB(
dnl		1:name,
dnl		2:libs,
dnl		3:cflags,
dnl		4:cppflags,
dnl		5:lddflags
dnl		)
dnl
dnl SMB_LIBRARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_LIBRARY(
dnl		1:name,
dnl		2:obj_files,
dnl		3:required_libs,
dnl		4:required_subsystems
dnl		)
dnl
dnl SMB_LIBRARY_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
dnl
dnl SMB_BINARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_BINARY(
dnl		1:name,
dnl		2:build_targets,
dnl		3:install_path
dnl		4:obj_files,
dnl		5:required_libs,
dnl		6:required_subsystems
dnl		)
dnl
dnl SMB_BINARY_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
dnl
dnl SMB_MAKE_TARGET(
dnl		1:name
dnl		2:calledname
dnl		)
dnl
dnl SMB_AC_OUTPUT(
dnl		1: outputfile
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl SMB_MODULE_DEFAULT(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_MODULE_DEFAULT],
[
	dnl Fall back to static if dlopen() is not available
	[MODULE_DEFAULT_][$1]=$2

	if test x"$[MODULE_DEFAULT_][$1]" = xSHARED -a x"$ac_cv_func_dlopen" != xyes; then
		[MODULE_DEFAULT_][$1]=STATIC
	fi
])

dnl SMB_MODULE	( 
dnl		1:name,
dnl		2:subsystem,
dnl		3:default_build,
dnl		4:init_obj_file,
dnl		5:add_obj_files,
dnl		6:required_libs,
dnl		7:required_subsystems
dnl		)
AC_DEFUN([SMB_MODULE],
[

SMB_INFO_MODULES="$SMB_INFO_MODULES
###################################
# Start MODULE $1
\$module{$1}{NAME} = \"$1\";
\$module{$1}{SUBSYSTEM} = \"$2\";
\$module{$1}{DEFAULT_BUILD} = \"$3\";
\$module{$1}{INIT_OBJ_FILE} = \"$4\";
\$module{$1}{ADD_OBJ_FILES} = \"$5\";
\$module{$1}{REQUIRED_LIBS} = \"$6\";
\$module{$1}{REQUIRED_SUBSYSTEMS} = \"$7\";
# End MODULE $1
###################################
"
])

dnl SMB_MODULE_MK(
dnl		1:name,
dnl		2:subsystem,
dnl		3:default_build,
dnl		4:config_mk_file
dnl		)
AC_DEFUN([SMB_MODULE_MK],
[

SMB_INFO_MODULES="$SMB_INFO_MODULES
###################################
# Start MODULE $1
\$module{$1}{NAME} = \"$1\";
\$module{$1}{SUBSYSTEM} = \"$2\";
\$module{$1}{DEFAULT_BUILD} = \"$3\";
\$module{$1}{INIT_OBJ_FILE} = module_get($4, $1,\"INIT_OBJ_FILE\");
\$module{$1}{ADD_OBJ_FILES} = module_get($4, $1,\"ADD_OBJ_FILES\");
\$module{$1}{REQUIRED_LIBS} = module_get($4, $1,\"REQUIRED_LIBS\");
\$module{$1}{REQUIRED_SUBSYSTEMS} = module_get($4, $1,\"REQUIRED_SUBSYSTEMS\");
# End MODULE $1
###################################
"
])

dnl SMB_SUBSYSTEM_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_SUBSYSTEM_ENABLE],
[
	[SUBSYSTEM_][$1][_ENABLE]=$2
])

dnl SMB_SUBSYSTEM(
dnl		1:name,
dnl		2:init_objfile,
dnl		3:add_objfiles,
dnl		4:required_libs,
dnl		5:required_subsystems
dnl		)
AC_DEFUN([SMB_SUBSYSTEM],
[

SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
###################################
# Start Subsystem $1
\$subsystem{$1}{NAME} = \"$1\";
\$subsystem{$1}{INIT_OBJ_FILE} = \"$2\";
\$subsystem{$1}{ADD_OBJ_FILES} = \"$3\";
\$subsystem{$1}{REQUIRED_LIBS} = \"$4\";
\$subsystem{$1}{REQUIRED_SUBSYSTEMS} = \"$5\";
# End Subsystem $1
###################################
"
])

dnl SMB_SUBSYSTEM_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
AC_DEFUN([SMB_SUBSYSTEM_MK],
[

SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
###################################
# Start Subsystem $1
\$subsystem{$1}{NAME} = \"$1\";
\$subsystem{$1}{INIT_OBJ_FILE} = subsystem_get($2, $1,\"INIT_OBJ_FILE\");
\$subsystem{$1}{ADD_OBJ_FILES} = subsystem_get($2, $1,\"ADD_OBJ_FILES\");
\$subsystem{$1}{REQUIRED_LIBS} = subsystem_get($2, $1,\"REQUIRED_LIBS\");
\$subsystem{$1}{REQUIRED_SUBSYSTEMS} = subsystem_get($2, $1,\"REQUIRED_SUBSYSTEMS\");
# End Subsystem $1
###################################
"
])

dnl SMB_EXT_LIB(
dnl		1:name,
dnl		2:libs,
dnl		3:cflags,
dnl		4:cppflags,
dnl		5:lddflags
dnl		)
AC_DEFUN([SMB_EXT_LIB],
[
	echo "#SMB_EXT_LIB TOTO"
])


dnl SMB_LIBRARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_LIBRARY_ENABLE],
[
	[LIBRARY_][$1][_ENABLE]=$2
])

dnl SMB_LIBRARY(
dnl		1:name,
dnl		2:obj_files,
dnl		3:required_libs,
dnl		4:required_subsystems
dnl		)
AC_DEFUN([SMB_LIBRARY],
[

SMB_INFO_LIBRARIES="$SMB_INFO_LIBRARIES
###################################
# Start Library $1
\$library{$1}{NAME} = \"$1\";
\$library{$1}{OBJ_FILES} = \"$2\";
\$library{$1}{REQUIRED_LIBS} = \"$3\";
\$library{$1}{REQUIRED_SUBSYSTEMS} = \"$4\";
# End Library $1
###################################
"
])

dnl SMB_LIBRARY_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
AC_DEFUN([SMB_LIBRARY_MK],
[

SMB_INFO_LIBRARIES="$SMB_INFO_LIBRARIES
###################################
# Start Library $1
\$library{$1}{NAME} = \"$1\";
\$library{$1}{OBJ_FILES} = library_get($2, $1,\"OBJ_FILES\");
\$library{$1}{REQUIRED_LIBS} = library_get($2, $1,\"REQUIRED_LIBS\");
\$library{$1}{REQUIRED_SUBSYSTEMS} = library_get($2, $1,\"REQUIRED_SUBSYSTEMS\");
# End Library $1
###################################
"
])

dnl SMB_BINARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_BINARY_ENABLE],
[
	[BINARY_][$1][_ENABLE]=$2
])

dnl SMB_BINARY(
dnl		1:name,
dnl		2:build_targets,
dnl		3:install_path
dnl		4:objfiles,
dnl		5:required_libs,
dnl		6:required_subsystems
dnl		)
AC_DEFUN([SMB_BINARY],
[

SMB_INFO_BINARIES="$SMB_INFO_BINARIES
###################################
# Start Binary $1
\$binary{$1}{NAME} = \"$1\";
\$binary{$1}{BUILD_TARGETS} = \"$2\";
\$binary{$1}{INSTALL_PATH} = \"$3\";
\$binary{$1}{OBJ_FILES} = \"$4\";
\$binary{$1}{REQUIRED_LIBS} = \"$5\";
\$binary{$1}{REQUIRED_SUBSYSTEMS} = \"$6\";
# End Binary $1
###################################
"
])

dnl SMB_BINARY_MK(
dnl		1:name,
dnl		2:config_mk_file
dnl		)
AC_DEFUN([SMB_BINARY_MK],
[

SMB_INFO_BINARIES="$SMB_INFO_BINARIES
###################################
# Start Binary $1
\$binary{$1}{NAME} = \"$1\";
\$binary{$1}{BUILD_TARGETS} = binary_get($2, $1,\"BUILD_TARGETS\");
\$binary{$1}{INSTALL_PATH} = binary_get($2, $1,\"BUILD_TARGETS\");
\$binary{$1}{OBJ_FILES} = binary_get($2, $1,\"OBJ_FILES\");
\$binary{$1}{REQUIRED_LIBS} = binary_get($2, $1,\"REQUIRED_LIBS\");
\$binary{$1}{REQUIRED_SUBSYSTEMS} = binary_get($2, $1,\"REQUIRED_SUBSYSTEMS\");
# End Binary $1
###################################
"
])

dnl SMB_MAKE_TARGET(
dnl		1:name
dnl		2:calledname
dnl		)
AC_DEFUN([SMB_MAKE_TARGET],
[
	echo "#SMB_MAKE_TARGET TOTO"
])

dnl SMB_AC_OUTPUT(
dnl		1: outputfile
dnl		)
AC_DEFUN([SMB_AC_OUTPUT],
[
	AC_OUTPUT([],[],[SMB_BUILD_CORE([$1])])
])
