dnl SMB Build System
dnl ----------------
dnl Copyright (C) 2004 Stefan Metzmacher
dnl Copyright (C) 2004 Jelmer Vernooij
dnl Published under the GPL
dnl
dnl SMB_MODULE_DEFAULT(
dnl		1:name,
dnl		2:default_build
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
dnl		4:required_libraries,
dnl		5:required_subsystems
dnl		)
dnl
dnl SMB_EXT_LIB_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_EXT_LIB_FROM_PKGCONFIG(
dnl		1:name,
dnl		2:pkg-config name
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
dnl SMB_BINARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
dnl
dnl SMB_MAKE_TARGET(
dnl		1:name
dnl		2:calledname
dnl		)
dnl
dnl SMB_INCLUDE_M4(
dnl		1: inputfile
dnl		2: comment
dnl		)
dnl
dnl SMB_ENV_CHECK(
dnl		1:dummy
dnl		)
dnl
dnl SMB_AC_OUTPUT(
dnl		1: outputfile
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

AC_DEFUN([STR2ARRAY], [@<:@ input::str2array(\"$1\") @:>@])


dnl SMB_MODULE_DEFAULT(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_MODULE_DEFAULT],
[
	[SMB_MODULE_DEFAULT][$1]="$2"
SMB_INFO_MODULES="$SMB_INFO_MODULES
\$INPUT{$1}{DEFAULT_BUILD} = \"$2\";"
])

dnl SMB_SUBSYSTEM_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_SUBSYSTEM_ENABLE],
[
	[SMB_SUBSYSTEM_ENABLE_][$1]="$2"
SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
\$INPUT{$1}{ENABLE} = \"$2\";"
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

	if test -z "$[SMB_SUBSYSTEM_NOPROTO_][$1]"; then
		[SMB_SUBSYSTEM_NOPROTO_][$1]="NO";
	fi

SMB_INFO_SUBSYSTEMS="$SMB_INFO_SUBSYSTEMS
###################################
# Start Subsystem $1
\$INPUT{$1} = {
	TYPE => \"SUBSYSTEM\",
	NAME => \"$1\",
	INIT_OBJ_FILES => ][STR2ARRAY([$2])][,
	ADD_OBJ_FILES => ][STR2ARRAY([$3])][,
	REQUIRED_LIBRARIES => ][STR2ARRAY([$4])][,
	REQUIRED_SUBSYSTEMS => ][STR2ARRAY([$5])][,
	ENABLE => \"YES\"
};
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
SMB_INFO_ENABLES="$SMB_INFO_ENABLES
\$INPUT{EXT_LIB_$1}{ENABLE} = \"$2\";"
])

dnl SMB_EXT_LIB_FROM_PKGCONFIG(
dnl		1:name,
dnl		2:pkg-config name
dnl )
AC_DEFUN([SMB_EXT_LIB_FROM_PKGCONFIG], 
[
	dnl Figure out the correct variables and call SMB_EXT_LIB()

	if test -z "$PKG_CONFIG"; then
		AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	fi

	if test "$PKG_CONFIG" = "no" ; then
    		echo "*** The pkg-config script could not be found. Make sure it is"
    		echo "*** in your path, or set the PKG_CONFIG environment variable"
    		echo "*** to the full path to pkg-config."
    		echo "*** Or see http://www.freedesktop.org/software/pkgconfig to get pkg-config."
			SMB_EXT_LIB($1)
			SMB_EXT_LIB_ENABLE($1, NO)
	else
		if $PKG_CONFIG --atleast-pkgconfig-version 0.9.0; then
        		AC_MSG_CHECKING(for $2)

          		if test "$SMB_EXT_LIB_$1"x = "NO"x ; then
				SMB_EXT_LIB_ENABLE($1, NO)
				AC_MSG_RESULT(disabled)		
          		elif $PKG_CONFIG --exists '$2' ; then
            			AC_MSG_RESULT(yes)

				SMB_EXT_LIB_ENABLE($1, YES)
				SMB_EXT_LIB($1, 
					[`$PKG_CONFIG --libs-only-l '$2'`], 
					[`$PKG_CONFIG --cflags-only-other '$2'`],
					[`$PKG_CONFIG --cflags-only-I '$2'`],
					[`$PKG_CONFIG --libs-only-other '$2'` `$PKG_CONFIG --libs-only-L '$2'`])

				# FIXME: Dirty hack
				$1_CFLAGS="`$PKG_CONFIG --cflags '$2'`"
				CFLAGS="$CFLAGS $$1_CFLAGS"
        		else
				SMB_EXT_LIB($1)
				SMB_EXT_LIB_ENABLE($1, NO)
				AC_MSG_RESULT(no)
            			$PKG_CONFIG --errors-to-stdout --print-errors '$2'
        		fi
     		else
        		echo "*** Your version of pkg-config is too old. You need version $PKG_CONFIG_MIN_VERSION or newer."
        			echo "*** See http://www.freedesktop.org/software/pkgconfig"
				SMB_EXT_LIB($1)
				SMB_EXT_LIB_ENABLE($1, NO)
     		fi
  	fi
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

SMB_INFO_EXT_LIBS="$SMB_INFO_EXT_LIBS
###################################
# Start Ext Lib $1
\$INPUT{EXT_LIB_$1} = {
	TYPE => \"EXT_LIB\",
	NAME => \"EXT_LIB_$1\",
	LIBS => ][STR2ARRAY([$2])][,
	CFLAGS => ][STR2ARRAY([$3])][,
	CPPFLAGS => ][STR2ARRAY([$4])][,
	LDFLAGS => ][STR2ARRAY([$5])][
};
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
SMB_INFO_ENABLES="$SMB_INFO_ENABLES
\$INPUT{$1}{ENABLE} = \"$2\";"
])

dnl SMB_BINARY_ENABLE(
dnl		1:name,
dnl		2:default_build
dnl		)
AC_DEFUN([SMB_BINARY_ENABLE],
[
	[SMB_BINARY_ENABLE_][$1]="$2";

SMB_INFO_BINARIES="$SMB_INFO_BINARIES
\$INPUT{$1}{ENABLE} = \"$2\";"
])

dnl SMB_MAKE_TARGET(
dnl		1:name
dnl		2:calledname
dnl		)
AC_DEFUN([SMB_MAKE_TARGET],
[
	echo "#SMB_MAKE_TARGET TOTO"
])

dnl SMB_INCLUDE_M4(
dnl		1: inputfile
dnl		2: comment
dnl		)
AC_DEFUN([SMB_INCLUDE_M4],
[
###################################
# Start Include $1
# $2
sinclude($1)
# End Include $1
###################################
])

dnl SMB_ENV_CHECK(
dnl		1:dummy
dnl		)
AC_DEFUN([SMB_ENV_CHECK],
[
	_SMB_BUILD_ENV($1)
])

dnl SMB_AC_OUTPUT(
dnl		1: outputfile
dnl		)
AC_DEFUN([SMB_AC_OUTPUT],
[
	AC_OUTPUT([$1],[],[_SMB_BUILD_CORE([[$1][.in]])])
])
