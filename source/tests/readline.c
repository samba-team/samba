#include <stdio.h>
#include <term.h>
#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#endif
#ifdef HAVE_READLINE_H
#include <readline.h>
#endif
#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif
#ifdef HAVE_HISTORY_H
#include <history.h>
#endif
main()
{
	fclose(stdin);
	readline("");
}
