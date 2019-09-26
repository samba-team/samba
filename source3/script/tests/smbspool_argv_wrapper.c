/*
   Wrapper for smbspool to test Device URI in argv[0]

   Copyright (C) Bryan Mason 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Before calling a backend like smbspool, CUPS will set argv[0] to
 * the Device URI.  This program wraps a program like smbspool and
 * sets argv[0] to the device URI before exec()ing the acutal backend
 * program.
 */

int main(int argc, char *argv[], char *envp[])
{
	char **new_argv;
	char *exec_path;
	int a;
	int rv;
/*
 * Expected parameters:
 *
 * smbspool_argv_wrapper smbspool uri job user title copies opts file(s)
 * argv[0]	       1	2   3   4    5     6      7    8
 *
 */
	/* Allocate memory for the new arguments (exit on failure). */
	new_argv = calloc(argc, sizeof(char *));
	if (new_argv == 0) {
		exit(ENOMEM);
	}

	/* Save the path to the smbspool executable */
	exec_path = argv[1];

	/*
	 * Shift the rest of the args so smbspool is called with:
	 *
	 * uri     job user title copies opts file(s)
	 * argv[0] 1   2    3     4      5    6
	 */

	for (a = 2; a < argc-1; a++) {
		new_argv[a-2] = argv[a];
	}

	/* Execute smbspool with new arguments */
	rv = execve(exec_path, new_argv, envp);
	if (rv == -1) {
		exit(errno);
	}

	/* Avoid compiler error/warning */
	return 0;
}
