dnl # LIB GTK SMB subsystem

SMB_EXT_LIB_FROM_PKGCONFIG(gtk, [glib-2.0 gtk+-2.0])
SMB_SUBSYSTEM_ENABLE(GTKSMB, NO)
SMB_BINARY_ENABLE(gregedit, NO)
SMB_BINARY_ENABLE(gwcrontab, NO)
SMB_BINARY_ENABLE(gwsam, NO)

if test t$SMB_EXT_LIB_ENABLE_gtk = tYES; then
	SMB_SUBSYSTEM_ENABLE(GTKSMB, YES)
	SMB_BINARY_ENABLE(gregedit, YES)
	SMB_BINARY_ENABLE(gwcrontab, YES)
	# this break the build on my SuSE 9.1 --metze
	#SMB_BINARY_ENABLE(gwsam, YES)
	AC_DEFINE(HAVE_GTK, 1, [Whether GTK+ is available])
fi

SMB_SUBSYSTEM_MK(GTKSMB,gtk/config.mk)
SMB_BINARY_MK(gregedit,gtk/config.mk)
SMB_BINARY_MK(gwcrontab,gtk/config.mk)
SMB_BINARY_MK(gwsam,gtk/config.mk)
