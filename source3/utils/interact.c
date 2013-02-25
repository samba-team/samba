/*
 * Samba Unix/Linux SMB client library
 *
 * Copyright (C) Gregor Beck 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @brief  Functions to interact with an user.
 * @author Gregor Beck <gb@sernet.de>
 * @date   Aug 2011
 *
 */

#include "includes.h"
#include "system/filesys.h"

#include "interact.h"

#include <termios.h>

static const char* get_editor(void) {
	static char editor[64] = {0};

	if (editor[0] == '\0') {
		const char *tmp = getenv("VISUAL");
		if (tmp == NULL) {
			tmp = getenv("EDITOR");
		}
		if (tmp == NULL) {
			tmp = "vi";
		}
		snprintf(editor, sizeof(editor), "%s", tmp);
	}

	return editor;
}

int interact_prompt(const char* msg, const char* acc, char def) {
	struct termios old_tio, new_tio;
	int c;

	tcgetattr(STDIN_FILENO, &old_tio);
	new_tio=old_tio;
	new_tio.c_lflag &=(~ICANON & ~ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);

	do {
		d_printf("%s? [%c]\n", msg, def);
		fflush(stdout);
		c = getchar();
		if (c == '\n') {
			c = def;
			break;
		}
		else if (strchr(acc, tolower(c)) != NULL) {
			break;
		}
		d_printf("Invalid input '%c'\n", c);
	} while(c != EOF);
	tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
	return c;
}


char* interact_edit(TALLOC_CTX* mem_ctx, const char* str) {
	char fname[] = "/tmp/net_idmap_check.XXXXXX";
	char buf[128];
	char* ret = NULL;
	FILE* file;
	mode_t mask;
	int fd;

	mask = umask(S_IRWXO | S_IRWXG);
	fd = mkstemp(fname);
	umask(mask);
	if (fd == -1) {
		DEBUG(0, ("failed to mkstemp %s: %s\n", fname,
			  strerror(errno)));
		return NULL;
	}

	file  = fdopen(fd, "w");
	if (!file) {
		DEBUG(0, ("failed to open %s for writing: %s\n", fname,
			  strerror(errno)));
		close(fd);
		unlink(fname);
		return NULL;
	}

	fprintf(file, "%s", str);
	fclose(file);

	snprintf(buf, sizeof(buf), "%s %s\n", get_editor(), fname);
	if (system(buf) != 0) {
		DEBUG(0, ("failed to start editor %s: %s\n", buf,
			  strerror(errno)));
		unlink(fname);
		return NULL;
	}

	file = fopen(fname, "r");
	if (!file) {
		DEBUG(0, ("failed to open %s for reading: %s\n", fname,
			  strerror(errno)));
		unlink(fname);
		return NULL;
	}
	while ( fgets(buf, sizeof(buf), file) ) {
		ret = talloc_strdup_append(ret, buf);
	}
	fclose(file);
	unlink(fname);

	return talloc_steal(mem_ctx, ret);
}



/*Local Variables:*/
/*mode: c*/
/*End:*/
