/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Jean François Micouleau      1998-2002.
   
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
#include "wins_repl.h"

fd_set *listen_set = NULL;
int listen_number = 0;
int *sock_array = NULL;

/*******************************************************************
  Add an fd from the sock_array
******************************************************************/
void add_fd_to_sock_array(int fd)
{
	int *temp_sock=NULL;

	temp_sock=(int *)Realloc(sock_array, (listen_number+1)*sizeof(int));
	if (temp_sock==NULL)
		return;

	sock_array=temp_sock;
	sock_array[listen_number]=fd;
	listen_number++;
}


/*******************************************************************
  Remove an fd from the sock_array
******************************************************************/
void remove_fd_from_sock_array(int fd)
{
	int i,j;

	for (i=0; sock_array[i]!=fd && i<listen_number; i++)
		;
	
	if (i==listen_number) {
		DEBUG(0,("remove_fd_from_sock_array: unknown fd: %d\n", fd));
		return;
	}
	
	if (i==listen_number-1) {
		sock_array=(int *)Realloc(sock_array, --listen_number*sizeof(int));
		return;
	}

	for (j=i; j<listen_number-1; j++)
		sock_array[j]=sock_array[j+1];
	
	sock_array=(int *)Realloc(sock_array, --listen_number*sizeof(int));	
}
