dnl # LIB GTK SMB subsystem

SMB_EXT_LIB_FROM_PKGCONFIG(gtk, [glib-2.0 gtk+-2.0 >= 2.4])
SMB_ENABLE(gtksamba, NO)
SMB_ENABLE(gregedit, NO)
SMB_ENABLE(gwcrontab, NO)
SMB_ENABLE(gwsam, NO)
SMB_ENABLE(gepdump, NO)
SMB_ENABLE(gwsvcctl, NO)
SMB_ENABLE(EVENTS_GTK, NO)

if test t$SMB_ENABLE_gtk = tYES; then
	SMB_ENABLE(gtksamba, YES)
	SMB_ENABLE(gregedit, YES)
	SMB_ENABLE(gwcrontab, YES)
	SMB_ENABLE(gwsam, YES)
	SMB_ENABLE(gwsvcctl, YES)
	SMB_ENABLE(gepdump, YES)
	SMB_ENABLE(EVENTS_GTK, YES)
	AC_DEFINE(HAVE_GTK, 1, [Whether GTK+ is available])
fi
