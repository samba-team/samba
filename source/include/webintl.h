#ifndef I18N_H_INCLUDED
#define I18N_H_INCLUDED 1

/*
 * I18N_ORIGINAL_LANG ...the language of the original document files (*.html).
 */
#define I18N_ORIGINAL_LANG "en"

/* these constants are defined in Makefile.
 *
 * I18N_PACKAGE ...package name "i18n_swat" defined in configure.in.
 * I18N_LOCALEDIR ...directory to put message catalogs.
 * I18N_LOCALE_FILE ...filename of the language-locale map file.
 */

#ifdef ENABLE_NLS
#define I18N_GETTEXT 1
#endif /* ENABLE_NLS */

/* if NLS is disabled (ENABLE_NLS == 0), configure script will
 * automatically creates intl/libintl.h -> intl/libgettext.h (symlink)
 * and gettext(str) is defined as (str) in that file.
 */
#include <libintl.h>
#define _(String) gettext(String)
#define N_(String) (String)

#if I18N_SWAT
#define LN_(fname) ln_get_pref_file_n_o(fname)
#else
#define LN_(fname) (fname)
#endif /* I18N_SWAT */

/* global function pointers defined in kanji.c. */
extern char *(*dos_to_dos)(char *to, const char *from);

/* ******************************************************************
 * macros for debugging.
 ***************************************************************** */
#define LN_R_NODEBUG 1
#ifdef LN_R_NODEBUG
#define rassert(b) (void)0
#define rstrace(s) (void)0

#else
void ln_debug_error(const char *info, int nLine);
void rassert_help(BOOL b, int l);
#define rassert(b) rassert_help((BOOL)(b), (__LINE__))
#define rstrace(s) ln_debug_error((s), (__LINE__))
#endif /* LN_R_NODEBUG */

#endif /* I18N_H_INCLUDED */
