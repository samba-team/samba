/*  $Revision$
**
**  Unix system-dependant routines for editline library.
*/
#include "editline.h"

#include <termios.h>

void
rl_ttyset(int Reset)
{
    static struct termios	old;
    struct termios		new;
    
    if (Reset == 0) {
	tcgetattr(0, &old);
	rl_erase = old.c_cc[VERASE];
	rl_kill = old.c_cc[VKILL];
	rl_eof = old.c_cc[VEOF];
	rl_intr = old.c_cc[VINTR];
	rl_quit = old.c_cc[VQUIT];

	new = old;
	new.c_cc[VINTR] = -1;
	new.c_cc[VQUIT] = -1;
	new.c_lflag &= ~(ECHO | ICANON);
	new.c_iflag &= ~(ISTRIP | INPCK);
	new.c_cc[VMIN] = 1;
	new.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new);
    }
    else
	tcsetattr(0, TCSANOW, &old);
}


void
rl_add_slash(char *path, char *p)
{
    struct stat	Sb;
    
    if (stat(path, &Sb) >= 0)
	strcat(p, S_ISDIR(Sb.st_mode) ? "/" : " ");
}
