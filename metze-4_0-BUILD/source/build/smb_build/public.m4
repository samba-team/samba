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
	[SMB_MODULE_DEFAULT_][$1]="$2"
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

	if test -z "$[SMB_MODULE_DEFAULT_][$1]"; then
		[SMB_MODULE_DEFAULT_][$1]=$3
	fi
	
	if test "$[SMB_MODULE_][$1]"; then
		[SMB_MODULE_][$1]=$[SMB_MODULE_][$1]
	elif test "$[SMB_MODULE_]translit([$2], [A-Z], [a-z])" -a x"$[SMB_MODULE_DEFAULT_][$1]" != xNOT; then
		[SMB_MODULE_][$1]=$[SMB_MODULE_]translit([$2], [A-Z], [a-z])
	else
		[SMB_MODULE_][$1]="DEFAULT";
	fi

SMB_INFO_MODULES="$SMB_INFO_MODULES
###################################
# Start MODULE $1
\$modules{$1}{NAME} = \"$1\";
\$modules{$1}{SUBSYSTEM} = \"$2\";
\$modules{$1}{DEFAULT_BUILD} = \"$[SMB_MODULE_DEFAULT_][$1]\";
\$modules{$1}{INIT_OBJ_FILE} = \"$4\";
\$modules{$1}{ADD_OBJ_FILES} = \"$5\";
\$modules{$1}{REQUIRED_LIBS} = \"$6\";
\$modules{$1}{REQUIRED_SUBSYSTEMS} = \"$7\";
#
\$modules{$1}{CHOSEN_BUILD} = \"$[SMB_MODULE_][$1]\";
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

	if test -z "$[SMB_MODULE_DEFAULT_][$1]"; then
		[SMB_MODULE_DEFAULT_][$1]=$3
	fi
	
	if test "$[SMB_MODULE_][$1]"; then
		[SMB_MODULE_][$1]=$[SMB_MODULE_][$1]
	elif test "$[SMB_MODULE_]translit([$2], [A-Z], [a-z])" -a x"$[SMB_MODULE_DEFAULT_][$1]" != xNOT; then
		[SMB_MODULE_][$1]=$[SMB_MODULE_]translit([$2], [A-Z], [a-z])
	else
		[SMB_MODULE_][$1]="DEFAULT";
	fi

SMB_INFO_MODULES="$SMB_INFO_MODULES
###################################
# Start MODULE $1
\$modules{$1}{NAME} = \"$1\";
\$modules{$1}{SUBSYSTEM} = \"$2\";
\$modules{$1}{DEFAULT_BUILD} = \"$[SMB_MODULE_DEFAULT_][$1]\";
\$modules{$1}{INIT_OBJ_FILE} = module_get(\"$4\", \"$1\", \"INIT_OBJ_FILE\");
\$modules{$1}{ADD_OBJ_FILES} = module_get(\"$4\", \"$1\", \"ADD_OBJ_FILES\");
\$modules{$1}{REQUIRED_LIBS} = module_get(\"$4\", \"$1\", \"REQUIRED_LIBS\");
\$modules{$1}{REQUIRED_SUBSYSTEMS} = module_get(\"$4\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$modules{$1}{CHOSEN_BUILD} = \"$[SMB_MODULE_][$1]\";
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
	[SMB_SUBSYSTEM_ENABLE_][$1]="$2"
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

	if test -z "$[SMB_SUBSYSTEM_ENABLE_][$1]"; then
		[SMB_SUBSYSTEM_ENABLE_][$1]="YES";
	fi

SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
###################################
# Start Subsystem $1
\$subsystems{$1}{NAME} = \"$1\";
\$subsystems{$1}{INIT_OBJ_FILE} = \"$2\";
\$subsystems{$1}{ADD_OBJ_FILES} = \"$3\";
\$subsystems{$1}{REQUIRED_LIBS} = \"$4\";
\$subsystems{$1}{REQUIRED_SUBSYSTEMS} = \"$5\";
#
\$subsystems{$1}{ENABLE} = \"$[SMB_SUBSYSTEM_ENABLE_][$1]\";
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

	if test -z "$[SMB_SUBSYSTEM_ENABLE_][$1]"; then
		[SMB_SUBSYSTEM_ENABLE_][$1]="YES";
	fi

SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
###################################
# Start Subsystem $1
\$subsystems{$1}{NAME} = \"$1\";
\$subsystems{$1}{INIT_OBJ_FILE} = subsystem_get(\"$2\", \"$1\", \"INIT_OBJ_FILE\");
\$subsystems{$1}{ADD_OBJ_FILES} = subsystem_get(\"$2\", \"$1\", \"ADD_OBJ_FILES\");
\$subsystems{$1}{REQUIRED_LIBS} = subsystem_get(\"$2\", \"$1\", \"REQUIRED_LIBS\");
\$subsystems{$1}{REQUIRED_SUBSYSTEMS} = subsystem_get(\"$2\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$subsystems{$1}{ENABLE} = \"$[SMB_SUBSYSTEM_ENABLE_][$1]\";
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
	[SMB_LIBRARY_ENABLE_][$1]="$2"
])

dnl SMB_LIBRARY(
dnl		1:name,
dnl		2:obj_files,
dnl		3:required_libs,
dnl		4:required_subsystems
dnl		)
AC_DEFUN([SMB_LIBRARY],
[

	if test -z "$[SMB_LIBRARY_ENABLE_][$1]"; then
		[SMB_LIBRARY_ENABLE_][$1]="YES";
	fi

SMB_INFO_LIBRARIES="$SMB_INFO_LIBRARIES
###################################
# Start Library $1
\$libraries{$1}{NAME} = \"$1\";
\$libraries{$1}{OBJ_FILES} = \"$2\";
\$libraries{$1}{REQUIRED_LIBS} = \"$3\";
\$libraries{$1}{REQUIRED_SUBSYSTEMS} = \"$4\";
#
\$libraries{$1}{ENABLE} = \"$[SMB_LIBRARY_ENABLE_][$1]\";
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

	if test -z "$[SMB_LIBRARY_ENABLE_][$1]"; then
		[SMB_LIBRARY_ENABLE_][$1]="YES";
	fi

SMB_INFO_LIBRARIES="$SMB_INFO_LIBRARIES
###################################
# Start Library $1
\$libraries{$1}{NAME} = \"$1\";
\$libraries{$1}{OBJ_FILES} = library_get(\"$2\", \"$1\", \"OBJ_FILES\");
\$libraries{$1}{REQUIRED_LIBS} = library_get(\"$2\", \"$1\", \"REQUIRED_LIBS\");
\$libraries{$1}{REQUIRED_SUBSYSTEMS} = library_get(\"$2\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$libraries{$1}{ENABLE} = \"$[SMB_LIBRARY_ENABLE_][$1]\";
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
	[SMB_BINARY_ENABLE_][$1]="$2";
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

	if test -z "$[SMB_BINARY_ENABLE_][$1]"; then
		[SMB_BINARY_ENABLE_][$1]="YES";
	fi

SMB_INFO_BINARIES="$SMB_INFO_BINARIES
###################################
# Start Binary $1
\$binaries{$1}{NAME} = \"$1\";
\$binaries{$1}{BUILD_TARGETS} = \"$2\";
\$binaries{$1}{INSTALL_PATH} = \"$3\";
\$binaries{$1}{OBJ_FILES} = \"$4\";
\$binaries{$1}{REQUIRED_LIBS} = \"$5\";
\$binaries{$1}{REQUIRED_SUBSYSTEMS} = \"$6\";
#
\$binaries{$1}{ENABLE} = \"$[SMB_BINARY_ENABLE_][$1]\";
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

	if test -z "$[SMB_BINARY_ENABLE_][$1]"; then
		[SMB_BINARY_ENABLE_][$1]="YES";
	fi

SMB_INFO_BINARIES="$SMB_INFO_BINARIES
###################################
# Start Binary $1
\$binaries{$1}{NAME} = \"$1\";
\$binaries{$1}{BUILD_TARGETS} = binary_get(\"$2\", \"$1\", \"BUILD_TARGETS\");
\$binaries{$1}{INSTALL_PATH} = binary_get(\"$2\", \"$1\", \"INSTALL_PATH\");
\$binaries{$1}{OBJ_FILES} = binary_get(\"$2\", \"$1\", \"OBJ_FILES\");
\$binaries{$1}{REQUIRED_LIBS} = binary_get(\"$2\", \"$1\",\"REQUIRED_LIBS\");
\$binaries{$1}{REQUIRED_SUBSYSTEMS} = binary_get(\"$2\", \"$1\",\"REQUIRED_SUBSYSTEMS\");
#
\$binaries{$1}{ENABLE} = \"$[SMB_BINARY_ENABLE_][$1]\";
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
	AC_OUTPUT([$1],[rm -f [$1][.in]],[_SMB_BUILD_CORE([[$1][.in]])])
])
