dnl # Server process model subsystem

SMB_MODULE(process_model_single,PROCESS_MODEL,STATIC,[smbd/process_single.o])
SMB_MODULE(process_model_standard,PROCESS_MODEL,STATIC,[smbd/process_standard.o])

#################################################
# check for pthread support
AC_MSG_CHECKING(whether to use pthreads)
AC_ARG_WITH(pthreads,
[  --with-pthreads              Include pthreads (default=no) ],
[ case "$withval" in
	yes)
		AC_MSG_RESULT(yes)
		SMB_MODULE_DEFAULT(process_model_thread,STATIC)
	;;
	*)
		AC_MSG_RESULT(no)
	;;
  esac ],
AC_MSG_RESULT(no)
)

SMB_MODULE(process_model_thread,PROCESS_MODEL,NOT,
		[smbd/process_thread.o],[],[-lpthread])

SMB_SUBSYSTEM(PROCESS_MODEL,smbd/process_model.o,
		[],smbd/process_model_public_proto.h)
