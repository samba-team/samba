#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <roken.h>

void
mini_inetd (int port)
{
     struct sockaddr_in sa;
     int s = socket(AF_INET, SOCK_STREAM, 0);
     int s2;
     int one = 1;
     if(s < 0){
	  perror("socket");
	  exit(1);
     }
     if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
		   sizeof(one)) < 0){
	  perror("setsockopt");
	  exit(1);
     }
     memset(&sa, 0, sizeof(sa));
     sa.sin_port = port;
     sa.sin_addr.s_addr = INADDR_ANY;
     if(bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0){
	  perror("bind");
	  exit(1);
     }
     if(listen(s, SOMAXCONN) < 0){
	  perror("listen");
	  exit(1);
     }
     s2 = accept(s, NULL, 0);
     if(s2 < 0){
	  perror("accept");
	  exit(1);
     }
     close(s);
     dup2(s2, STDIN_FILENO);
     dup2(s2, STDOUT_FILENO);
     close(s2);
}
