#include "admin_locl.h"
#include <sl.h>

static SL_cmd commands[] = {
    { "add_new_key",	add_new_key, "add_new_key principal",	"" },
    { "ank", 		NULL, NULL, 			NULL },
    { "modify_entry",	mod_entry, "modify_entry principal", "" },
    { "dump",		dump, "dump [file]",		""  },
    { "load",		load, "load file",		"" },
    { "merge",		merge, "merge file",		"" }, 
    { "help",		help, "help",			"" }, 
    { "?",		NULL, NULL,			NULL },
    { "init",		init, "init realm...",		"" },
    { "get_entry",	get_entry, "get_entry principal","" },
    { "delete",		del_entry, "delete principal", 	"" },
    { NULL,		NULL, NULL,			NULL }
};

krb5_context context;
char *database = HDB_DEFAULT_DB;

void
help(int argc, char **argv)
{
    sl_help(commands, argc, argv);
}

int
main(int argc, char **argv)
{

    krb5_init_context(&context);
    sl_loop(commands, "kdb_edit> ");
    return 0;
}
