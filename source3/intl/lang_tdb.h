
/* The following definitions come from intl/lang_tdb.c  */

bool lang_tdb_init(const char *lang);
const char *lang_msg(const char *msgid);
void lang_msg_free(const char *msgstr);
char *lang_tdb_current(void);
