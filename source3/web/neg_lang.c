/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba Web Administration Tool
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Created by Ryo Kawahara <rkawa@lbe.co.jp> 
*/

#include "includes.h"
/* #include "config.h" */
#include "webintl.h"

#if I18N_SWAT
/* constants. */
/* it is ok to make them bigger.*/
#define LN_PREFLANG_MAX 10
#define LN_LNAME_LENGTH 8+1+8

#define LN_DEFAULT_LANG I18N_DEFAULT_LANG
#define LN_LANGDESC_DEFAULT -1
#define LN_NO_AVAILABLE_LANG -1

/* ******************************************************************
 * macros for debugging.
 ***************************************************************** */
#ifdef LN_R_NODEBUG

#else
/*
 *#define LN_DEBUG_LOG "/tmp/lndebug.log"
 *void ln_debug_error(const char *info, int nLine)
 *{
 *	FILE* fp;
 *	fp = sys_fopen(LN_DEBUG_LOG, "a");
 *	fprintf(fp, "%s at %d.\n", info, nLine);
 *	fclose(fp);
 *}
 *void rassert_help(BOOL b, int l)
 *{
 *	if(!b)
 *	{
 *		ln_debug_error("language negotiation error.", l);
 *		exit(1);
 *	}
 *}
 */
#endif /* LN_R_NODEBUG */

/* ****************************************************************
 LNNegotiator struct. It contains...
 [aPrefLang]
  the array of strings. each string is the name of
  languages ("ja", "ko"...), given by web browser.
 [nPrefLang]
  the number of the languages in aPrefLang.
 [lOriginalLang]
  == "en": indicates what language the  default(original) files
  are written with.
**************************************************************** */
typedef char lnstring[LN_LNAME_LENGTH + 1];
#define lnstrcpy(d,s) safe_strcpy((d),(s),sizeof(lnstring)-1)

typedef struct tagLNNegotiator
{
	lnstring aPrefLang[LN_PREFLANG_MAX];
	int nPrefLang;
	lnstring lOriginalLang;
}LNNegotiator;

/* **************************************************************
 * some access functions & macros for LNNegotiator struct.
 * ************************************************************ */
#define ln_getPreflangCount(pLn) ((pLn)->nPrefLang)
#define ln_getOriginalLang(pLn) ((pLn)->lOriginalLang)
#define ln_getDefaultPrefLang(pLn) ((pLn)->lDefaultPrefLang)

/* make it inline-expanded (or macro) to get better performance */
static const char* ln_getPreflang(LNNegotiator* pLn, int i)
{
	rassert(i == LN_LANGDESC_DEFAULT
	       || (0 <= i && i < ln_getPreflangCount(pLn)));

	if(i == LN_LANGDESC_DEFAULT)
		return NULL;
	if(0 <= i && i < ln_getPreflangCount(pLn))
		return pLn->aPrefLang[i];
	return NULL;
}
/* initialize structures */
static void ln_resetln(LNNegotiator* pLn)
{
	pLn->nPrefLang = 0;
	/* using fixed memory.*/
}
static BOOL ln_addPreflang(LNNegotiator* pLn, const char* pLang)
{
	int nPref = ln_getPreflangCount(pLn);

	if(nPref >= LN_PREFLANG_MAX)
		return False;

	lnstrcpy(pLn->aPrefLang[nPref], pLang);
	(pLn->nPrefLang)++;
	return True;
}
static void ln_initln_help(LNNegotiator* pLn)
{
	ln_resetln(pLn);
	lnstrcpy(pLn->lOriginalLang, I18N_ORIGINAL_LANG);
	/* I18N_ORIGINAL_LANG = "en" is hardcoded in
	   webintl.h. */
	if (I18N_DEFAULT_PREF_LANG[0] != '\0')
	      ln_addPreflang(pLn, I18N_DEFAULT_PREF_LANG);

	/* this entry is used only when web browser didn't send
	   ACCEPT-LANGUAGE header. */
}
/* ****************************************************************
 * store acceptable languages into LNNegotiator object.
 * [pstrLangarray] The arguments of "accept-language" http header, 
 * which is like "en-GB, es;q=0.5, ja". "q=0.5" is called quality value,
 * but it is ignored now. wiled card "*" is also ignored. 
 ***************************************************************** */
static BOOL ln_negotiate_language_help( LNNegotiator* pLn, const char* pstrLangarray )
{
	char* pToken;
	const char* pDelim = " \n\r\t,;";
	pstring strBuffer;

	rassert(pstrLangarray);
	rassert(pLn);

	ln_resetln(pLn);
	pstrcpy(strBuffer, pstrLangarray);
	pToken = strtok(strBuffer, pDelim);
	while(pToken != NULL)
	{
		if(strncmp(pToken, "q=", strlen("q=")) == 0)
		{
			pToken = strtok(NULL, pDelim);
			continue;
		}
		if(!ln_addPreflang(pLn, pToken))
			break;
		pToken = strtok(NULL, pDelim);
	}
	rassert(ln_getPreflangCount(pLn) != 0);
	return (ln_getPreflangCount(pLn) != 0);
}

/* **************************************************************
 initialize gettext. Before this, cgi_setup() should be done. 
 cgi_setup() calls ln_negotiate_language() if the user specifies
 languages in web browser. Then, ln_set_pref_language() will work.
 ************************************************************* */
static BOOL ln_init_lang_env_help(LNNegotiator* pLn)
{
#if I18N_GETTEXT
	int nLang;

	nLang = ln_set_pref_language(pLn);
	rstrace(getenv("LANGUAGE"));
#endif /* I18N_GETTEXT */
	return True;
}
/* *****************************************************************
 * This function searches for the "PrefLang" version of pFile.
 * if not available, returns pFile.
 * [pFile] the filename.
 * [pst] the address of a struct. it will be filled with the information
 *  of the file.
 * [pLangDesc] The address of an integer. a value which indicates the
 * language of the returned value is written to the address. the value
 * is used in ln_get_lang().
 * [return value] address of the name of the language version of the file.
 * It is static object so it will be destroyed at the time ln_get_pref_file()
 * is called.
 **************************************************************** */
static void ln_make_filename( pstring afname, const char* pFile, const char* pAdd )
{
#if LANG_PREFIX
  /* LANG_PREFIX is already undefined, maybe removed soon */
	/* maybe, foo.html.ja */
	pstrcpy(afname, pFile);
	pstrcat(afname, ".");
	pstrcat(afname, pAdd);
#else
	/* maybe, lang/ja/foo.html */
	pstrcpy(afname, "lang/");
	pstrcat(afname, pAdd);
	pstrcat(afname, "/");
	pstrcat(afname, pFile);
#endif
}
static const char* ln_get_pref_file_help(
	LNNegotiator* pLn, const char* pFile,
	 SMB_STRUCT_STAT* pst, int* pLangDesc)
{
	static pstring afname;
	int i;

	for(i = 0; i < ln_getPreflangCount(pLn); i++)
	{
		if(strcmp(ln_getPreflang(pLn, i), ln_getOriginalLang(pLn))
			  == 0)
			break;
		ln_make_filename(afname, pFile, ln_getPreflang(pLn, i));
		if(file_exist(afname, pst))
		{
			*pLangDesc = i;
			return afname;
		}
	}
	pstrcpy(afname, pFile);
	file_exist(afname, pst);
	*pLangDesc = LN_LANGDESC_DEFAULT;
	return afname;
}
/* *******************************************************************
 * file scope variables. this variable is not locked.
 * (not multithread-safe)
 ******************************************************************** */
static LNNegotiator lnLanguagenegotiator;

/* *******************************************************************
 * interfaces to the outside of this file.
 ******************************************************************** */
void ln_initln(void)
{
	ln_initln_help(&lnLanguagenegotiator);
}
BOOL ln_init_lang_env(void)
{
	return ln_init_lang_env_help(&lnLanguagenegotiator);
}
const char* ln_get_lang(int nLangDesc)
{
	return ln_getPreflang(&lnLanguagenegotiator, nLangDesc);
}
const char* ln_get_pref_file(const char* pFile,
			  SMB_STRUCT_STAT* pst, int* pLangDesc)
{
	return ln_get_pref_file_help(
		&lnLanguagenegotiator, pFile, pst, pLangDesc);
}
BOOL ln_negotiate_language(const char* pstrLangarray)
{
	return ln_negotiate_language_help(
		&lnLanguagenegotiator, pstrLangarray);
}
const char* ln_get_pref_file_n_o(const char* pFile)
{
	SMB_STRUCT_STAT st;
	int nLangDesc;
	return ln_get_pref_file(pFile, &st, &nLangDesc);
}
#endif /* I18N_SWAT */
