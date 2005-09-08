dnl SMB Compiler Capability Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004,2005
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

############################################
# Check if the compiler handles c99 struct initialization.
# Usage: SMB_CC_SUPPORTS_C99_STRUCT_INIT(success-action,failure-action)

AC_DEFUN([SMB_CC_SUPPORTS_C99_STRUCT_INIT],
[
AC_MSG_CHECKING(for C99 designated initializers)
AC_TRY_COMPILE([
    #include <stdio.h>],
    [
       struct foo {
	   int x;
	   char y;
       } ;
       struct foo bar = {
	    .y = 'X',
	    .x = 1
       };	 
    ],
[AC_MSG_RESULT(yes); $1],[AC_MSG_RESULT(no); $2])
])

