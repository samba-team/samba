#include <stdio.h>
#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#endif
#ifdef HAVE_READLINE_H
#include <readline.h>
#endif
#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif
main()
{
	readline("");
}
