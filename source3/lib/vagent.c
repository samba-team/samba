/* 
   Unix SMB/Netbios implementation.
   Version 2
   SMB agent/socket plugin
   Copyright (C) Andrew Tridgell 1999
   
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
#include "smb.h"

extern int DEBUGLEVEL;


/****************************************************************************
terminate socket connection
****************************************************************************/
static void sock_redir_free(struct vagent_ops *va, struct sock_redir *sock)
{
	if (sock->c != -1)
	{
		close(sock->c);
		sock->c = -1;
	}
	if (sock->n != NULL)
	{
		va->free_sock(sock->n);
		sock->n = NULL;
	}
	free(sock);
}

/****************************************************************************
free a sockent array
****************************************************************************/
static void free_sock_array(struct vagent_ops*va)
{
	void(*fn)(void*) = (void(*)(void*))&va->free_sock;
	free_void_array(va->num_socks, (void**)va->socks, *fn);
}

/****************************************************************************
add a sockent state to the array
****************************************************************************/
static struct sock_redir* add_sock_to_array(uint32 *len,
				struct sock_redir ***array,
				struct sock_redir *sock)
{
	int i;
	for (i = 0; i < (*len); i++)
	{
		if ((*array)[i] == NULL)
		{
			(*array)[i] = sock;
			return sock;
		}
	}

	return (struct sock_redir*)add_item_to_array(len,
	                     (void***)array, (void*)sock);
				
}

/****************************************************************************
initiate sockent array
****************************************************************************/
void init_sock_redir(struct vagent_ops*va)
{
	va->socks = NULL;
	va->num_socks = 0;
}

/****************************************************************************
terminate sockent array
****************************************************************************/
void free_sock_redir(struct vagent_ops*va)
{
	free_sock_array(va);
	init_sock_redir(va);
}

/****************************************************************************
create a new sockent state from user credentials
****************************************************************************/
static struct sock_redir *sock_redir_get(struct vagent_ops *va, int fd)
{
	struct sock_redir *sock = (struct sock_redir*)malloc(sizeof(*sock));

	if (sock == NULL)
	{
		return NULL;
	}

	ZERO_STRUCTP(sock);

	sock->c = fd;
	sock->n = NULL;

	DEBUG(10,("sock_redir_get:\tfd:\t%d\n", fd));

	return sock;
}
/****************************************************************************
init sock state
****************************************************************************/
static void sock_add(struct vagent_ops *va, int fd)
{
	struct sock_redir *sock;
	sock = sock_redir_get(va, fd);
	if (sock != NULL)
	{
		add_sock_to_array(&va->num_socks, &va->socks, sock);
	}
}

/****************************************************************************
delete a sockent state
****************************************************************************/
static BOOL sock_del(struct vagent_ops *va, int fd)
{
	int i;

	for (i = 0; i < va->num_socks; i++)
	{
		if (va->socks[i] == NULL) continue;
		if (va->socks[i]->c == fd) 
		{
			sock_redir_free(va, va->socks[i]);
			va->socks[i] = NULL;
			return True;
		}
	}

	return False;
}

void start_agent(struct vagent_ops *va)
{
	int s, c;

	s = va->get_agent_sock(va->id);

	while (1)
	{
		int i;
		fd_set fds;
		int num;
		struct sockaddr_un addr;
		int in_addrlen = sizeof(addr);
		int maxfd = s;
		
		FD_ZERO(&fds);
		FD_SET(s, &fds);

		for (i = 0; i < va->num_socks; i++)
		{
			if (va->socks[i] != NULL)
			{
				int fd = va->socks[i]->c;
				FD_SET(fd, &fds);
				maxfd = MAX(maxfd, fd);

				if (va->socks[i]->n != NULL)
				{
					fd = va->socks[i]->s;
					FD_SET(fd, &fds);
					maxfd = MAX(fd, maxfd);
				}
			}
		}

		dbgflush();
		num = sys_select(maxfd+1,&fds,NULL, NULL);

		if (num <= 0)
		{
			continue;
		}

		if (FD_ISSET(s, &fds))
		{
			FD_CLR(s, &fds);
			c = accept(s, (struct sockaddr*)&addr, &in_addrlen);
			if (c != -1)
			{
				sock_add(va, c);
			}
		}

		for (i = 0; i < va->num_socks; i++)
		{
			if (va->socks[i] == NULL)
			{
				continue;
			}
			if (FD_ISSET(va->socks[i]->c, &fds))
			{
				FD_CLR(va->socks[i]->c, &fds);
				if (!va->process_cli_sock(va->socks,
				                          va->num_socks,
				                          va->socks[i]))
				{
					sock_redir_free(va, va->socks[i]);
					va->socks[i] = NULL;
				}
			}
			if (va->socks[i] == NULL)
			{
				continue;
			}
			if (va->socks[i]->n == NULL)
			{
				continue;
			}
			if (FD_ISSET(va->socks[i]->s, &fds))
			{
				FD_CLR(va->socks[i]->s, &fds);
				if (!va->process_srv_sock(va->socks,
				                          va->num_socks,
				                          va->socks[i]->s))
				{
					sock_redir_free(va, va->socks[i]);
					va->socks[i] = NULL;
				}
			}
		}
	}
}

