/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   some simple CGI helper routines
   Copyright (C) Andrew Tridgell 1997
   
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
*/


#include "includes.h"

#define MAX_VARIABLES 512

struct var {
	char *name;
	char *value;
};

static struct var variables[MAX_VARIABLES];
static int num_variables;


static int grab_line(int *cl, char *line, int maxsize)
{
	int i = 0;

	while ((*cl)) {
		int c = fgetc(stdin);
		(*cl)--;

		if (c == EOF) {
			(*cl) = 0;
			break;
		}
		
		if (c == '+') {
			c = ' ';
		}

		if (c == '\r') continue;

		if (strchr("\n&", c)) break;

		if (c == '%' && (*cl) >= 2) {
			int c1, c2;
			c1 = fgetc(stdin);
			c2 = fgetc(stdin);
			(*cl) -= 2;
			if (c1 == EOF || c2 == EOF) break;
			if (c1 >= '0' && c1 <= '9')
				c1 = c1 - '0';
			else if (c1 >= 'A' && c1 <= 'F')
				c1 = 10 + c1 - 'A';
			else if (c1 >= 'a' && c1 <= 'f')
				c1 = 10 + c1 - 'a';
			else break;

			if (c2 >= '0' && c2 <= '9')
				c2 = c2 - '0';
			else if (c2 >= 'A' && c2 <= 'F')
				c2 = 10 + c2 - 'A';
			else if (c2 >= 'a' && c2 <= 'f')
				c2 = 10 + c2 - 'a';
			else break;
			
			c = (c1<<4) | c2;
		}

		line[i++] = c;

		if (i == maxsize) break;
	}

	/* now unescape the line */
	

	line[i] = 0;
	return 1;
}


/***************************************************************************
  load all the variables passed to the CGI program
  ***************************************************************************/
void cgi_load_variables(void)
{
	static pstring line;
	char *p;	
	int len;

	if (!(p=getenv("CONTENT_LENGTH"))) return;

	len = atoi(p);

	if (len <= 0) return;

	

	while (len && grab_line(&len, line, sizeof(line)-1)) {		
		p = strchr(line,'=');
		if (!p) continue;

		*p = 0;

		variables[num_variables].name = strdup(line);
		variables[num_variables].value = strdup(p+1);
		
		if (!variables[num_variables].name || 
		    !variables[num_variables].value)
			continue;

#if 0
		printf("%s=%s<br>\n", 
		       variables[num_variables].name,
		       variables[num_variables].value);
#endif

		num_variables++;
		if (num_variables == MAX_VARIABLES) break;
	}

	fclose(stdin);
}


/***************************************************************************
  find a variable passed via CGI
  ***************************************************************************/
char *cgi_variable(char *name)
{
	int i;

	for (i=0;i<num_variables;i++)
		if (strcmp(variables[i].name, name) == 0)
			return variables[i].value;
	return NULL;
}


/***************************************************************************
  return the value of a CGI boolean variable.
  ***************************************************************************/
int cgi_boolean(char *name, int def)
{
	char *p = cgi_variable(name);

	if (!p) return def;

	return strcmp(p, "1") == 0;
}
