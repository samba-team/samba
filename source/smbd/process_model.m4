dnl # Server process model subsystem

SMB_ENABLE(process_model_thread,NO)

#################################################
# check for pthread support
AC_MSG_CHECKING(whether to use pthreads)
AC_ARG_WITH(pthreads,
[  --with-pthreads              Include pthreads (default=no) ],
[ case "$withval" in
	yes)
		AC_MSG_RESULT(yes)
		if test x"$ac_cv_func_pread" != x"yes" -o x"$ac_cv_func_pwrite" != x"yes";then
			AC_MSG_ERROR([You cannot enable threads when you don't have pread/pwrite!])
		fi
		SMB_ENABLE(process_model_thread,YES)
		SMB_EXT_LIB_ENABLE(PTHREAD,YES)
	;;
	*)
		AC_MSG_RESULT(no)
	;;
  esac ],
AC_MSG_RESULT(no)
)

SMB_EXT_LIB(PTHREAD,[-lpthread])
