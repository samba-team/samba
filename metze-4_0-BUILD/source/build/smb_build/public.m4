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
dnl		4:init_obj_files,
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
dnl		2:init_obj_files,
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
dnl SMB_EXT_LIB_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_EXT_LIB(
dnl		1:name,
dnl		2:libs,
dnl		3:cflags,
dnl		4:cppflags,
dnl		5:ldflags
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
dnl		4:init_obj_files,
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
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{NAME} = \"$1\";
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{SUBSYSTEM} = \"$2\";
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{DEFAULT_BUILD} = \"$[SMB_MODULE_DEFAULT_][$1]\";
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{INIT_OBJ_FILES}} = str2array(\"$4\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{ADD_OBJ_FILES}} = str2array(\"$5\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{REQUIRED_LIBRARIES}} = str2array(\"$6\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{REQUIRED_SUBSYSTEMS}} = str2array(\"$7\");
#
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{CHOSEN_BUILD} = \"$[SMB_MODULE_][$1]\";
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
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{NAME} = \"$1\";
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{SUBSYSTEM} = \"$2\";
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{DEFAULT_BUILD} = \"$[SMB_MODULE_DEFAULT_][$1]\";
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{INIT_OBJ_FILES}} = module_get_array(\"$4\", \"$1\", \"INIT_OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{ADD_OBJ_FILES}} = module_get_array(\"$4\", \"$1\", \"ADD_OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{REQUIRED_LIBRARIES}} = module_get_array(\"$4\", \"$1\", \"REQUIRED_LIBRARIES\");
@{\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{REQUIRED_SUBSYSTEMS}} = module_get_array(\"$4\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$SMB_BUILD_CTX->{INPUT}{MODULES}{$1}{CHOSEN_BUILD} = \"$[SMB_MODULE_][$1]\";
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
dnl		2:init_obj_files,
dnl		3:add_obj_files,
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
\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{INIT_OBJ_FILES}} = str2array(\"$2\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{ADD_OBJ_FILES}} = str2array(\"$3\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{REQUIRED_LIBRARIES}} = str2array(\"$4\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{REQUIRED_SUBSYSTEMS}} = str2array(\"$5\");
#
\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{ENABLE} = \"$[SMB_SUBSYSTEM_ENABLE_][$1]\";
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
\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{INIT_OBJ_FILES}} = subsystem_get_array(\"$2\", \"$1\", \"INIT_OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{ADD_OBJ_FILES}} = subsystem_get_array(\"$2\", \"$1\", \"ADD_OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{REQUIRED_LIBRARIES}} = subsystem_get_array(\"$2\", \"$1\", \"REQUIRED_LIBRARIES\");
@{\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{REQUIRED_SUBSYSTEMS}} = subsystem_get_array(\"$2\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$SMB_BUILD_CTX->{INPUT}{SUBSYSTEMS}{$1}{ENABLE} = \"$[SMB_SUBSYSTEM_ENABLE_][$1]\";
# End Subsystem $1
###################################
"
])

dnl SMB_EXT_LIB_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_EXT_LIB_ENABLE],
[
	[SMB_EXT_LIB_ENABLE_][$1]="$2"
])

dnl SMB_EXT_LIB(
dnl		1:name,
dnl		2:libs,
dnl		3:cflags,
dnl		4:cppflags,
dnl		5:ldflags
dnl		)
AC_DEFUN([SMB_EXT_LIB],
[

	if test -z "$[SMB_EXT_LIB_ENABLE_][$1]"; then
		[SMB_EXT_LIB_ENABLE_][$1]="NO";
	fi

SMB_INFO_EXT_LIBS="$SMB_INFO_EXT_LIBS
###################################
# Start Ext Lib $1
\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{LIBS}} = str2array(\"$2\");
@{\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{CFLAGS}} = str2array(\"$3\");
@{\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{CPPFLAGS}} = str2array(\"$4\");
@{\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{LDFLAGS}} = str2array(\"$5\");
#
\$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$1}{ENABLE} = \"$[SMB_EXT_LIB_ENABLE_][$1]\";
# End Ext Lib $1
###################################
"
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
\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{OBJ_FILES}} = str2array(\"$2\");
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{REQUIRED_LIBRARIES}} = str2array(\"$3\");
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{REQUIRED_SUBSYSTEMS}} = str2array(\"$4\");
#
\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{ENABLE} = \"$[SMB_LIBRARY_ENABLE_][$1]\";
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
\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{OBJ_FILES}} = library_get_array(\"$2\", \"$1\", \"OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{REQUIRED_LIBRARIES}} = library_get_array(\"$2\", \"$1\", \"REQUIRED_LIBRARIES\");
@{\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{REQUIRED_SUBSYSTEMS}} = library_get_array(\"$2\", \"$1\", \"REQUIRED_SUBSYSTEMS\");
#
\$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$1}{ENABLE} = \"$[SMB_LIBRARY_ENABLE_][$1]\";
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
\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{BUILD_TARGETS}} = str2array(\"$2\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{INSTALL_PATH}} = str2array(\"$3\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{OBJ_FILES}} = str2array(\"$4\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{REQUIRED_LIBRARIES}} = str2array(\"$5\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{REQUIRED_SUBSYSTEMS}} = str2array(\"$6\");
#
\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{ENABLE} = \"$[SMB_BINARY_ENABLE_][$1]\";
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
\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{NAME} = \"$1\";
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{BUILD_TARGETS}} = binary_get_array(\"$2\", \"$1\", \"BUILD_TARGETS\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{INSTALL_PATH}} = binary_get_array(\"$2\", \"$1\", \"INSTALL_PATH\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{OBJ_FILES}} = binary_get_array(\"$2\", \"$1\", \"OBJ_FILES\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{REQUIRED_LIBRARIES}} = binary_get_array(\"$2\", \"$1\",\"REQUIRED_LIBRARIES\");
@{\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{REQUIRED_SUBSYSTEMS}} = binary_get_array(\"$2\", \"$1\",\"REQUIRED_SUBSYSTEMS\");
#
\$SMB_BUILD_CTX->{INPUT}{BINARIES}{$1}{ENABLE} = \"$[SMB_BINARY_ENABLE_][$1]\";
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
	AC_OUTPUT([$1],[],[_SMB_BUILD_CORE([[$1][.in]])])
])
