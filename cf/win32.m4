dnl $Id$
dnl rk_WIN32_EXPORT buildsymbol symbol-that-export
AC_DEFUN([rk_WIN32_EXPORT],[AH_TOP([#ifdef $1
#ifndef $2
#ifdef _WIN32_
#define $2 _export _stdcall
#else
#define $2
#endif
#endif
#endif
])])
