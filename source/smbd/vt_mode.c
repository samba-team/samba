/* vt_mode.c */
/*
support vtp-sessions

(C) written by Christian A. Lademann <cal@zls.com>
*/

/*
02.05.95:cal:ported to samba-1.9.13
*/

#define	__vt_mode_c__


/* #include	<stdio.h> */
/* #include	<fcntl.h> */
/* #include	<sys/types.h> */
/* #include	<unistd.h> */
/* #include	<signal.h> */
/* #include	<errno.h> */
/* #include	<ctype.h> */
/* #include	<utmp.h> */
/* #include	<sys/param.h> */
/* #include	<sys/ioctl.h> */
/* #include	<stdlib.h> */
/* #include	<string.h> */

#include	"includes.h"
#include	"vt_mode.h"
#include	<utmp.h>

#ifdef SCO
	extern char	*strdup();
#endif

extern int Client;

#ifdef LINUX
#	define	HAS_VTY
#endif

#ifdef SCO
#	define	HAS_PTY
#	define	HAS_VTY

#	include	<sys/tty.h>
#endif

extern int	DEBUGLEVEL;
extern char	*InBuffer, *OutBuffer;
extern int	done_become_user;

fstring	master_name, slave_name;
int		master, slave, i, o, e;

int		ms_type = MS_NONE,
		ms_poll = 0;


/*
VT_Check: test incoming packet for "vtp" or "iVT1\0"
*/
int	VT_Check(char	*buffer)
{
	DEBUG(3,("Checking packet: <%10s...>\n", buffer+4));
	if((strncmp(buffer+4, "vtp", 3) == 0 && smb_len(buffer) == 3) || (strncmp(buffer+4, "iVT1\0", 5) == 0 && smb_len(buffer) == 5))
		return(1);
	else
		return(0);
}


/*
VT_Start_utmp: prepare /etc/utmp for /bin/login
*/
int VT_Start_utmp(void)
{
	struct utmp	u, *v;
	char		*tt;


	setutent();

	fstrcpy(u.ut_line, VT_Line);

	if((v = getutline(&u)) == NULL) {
		if(strncmp(VT_Line, "tty", 3) == 0)
			tt = VT_Line + 3;
		else if(strlen(VT_Line) > 4)
			tt = VT_Line + strlen(VT_Line) - 4;
		else
			tt = VT_Line;

		fstrcpy(u.ut_id, tt);
		u.ut_time = time((time_t*)0);
	}

	fstrcpy(u.ut_user, "LOGIN");
	fstrcpy(u.ut_line, VT_Line);
	u.ut_pid = getpid();
	u.ut_type = LOGIN_PROCESS;
	pututline(&u);

	endutent();

	return(0);
}


/*
VT_Stop_utmp: prepare /etc/utmp for other processes
*/
int VT_Stop_utmp(void)
{
	struct utmp	u, *v;


	if(VT_Line != NULL) {
		setutent();

		fstrcpy(u.ut_line, VT_Line);

		if((v = getutline(&u)) != NULL) {
			fstrcpy(v->ut_user, "");
			v->ut_type = DEAD_PROCESS;
			v->ut_time = time((time_t*)0);
			pututline(v);
		}

		endutent();
	}

	return(0);
}


/*
VT_AtExit: Things to do when the program exits
*/
void	VT_AtExit(void)
{
	if(VT_ChildPID > 0) {
		kill(VT_ChildPID, SIGHUP);
		(void)wait(NULL);
	}

	VT_Stop_utmp();
}


/*
VT_SigCLD: signalhandler for SIGCLD: set flag if child-process died
*/
void	VT_SigCLD(int	sig)
{
	if(wait(NULL) == VT_ChildPID)
		VT_ChildDied = True;
	else
		signal(SIGCLD, VT_SigCLD);
}


/*
VT_SigEXIT: signalhandler for signals that cause the process to exit
*/
void	VT_SigEXIT(int	sig)
{
	VT_AtExit();

	exit(1);
}


/*
VT_Start: initialize vt-specific data, alloc pty, spawn shell and send ACK
*/
int	VT_Start(void)
{
	char	OutBuf [64], *X, *Y;


	ms_type = MS_NONE;
	master = slave = -1;

#ifdef HAS_VTY
#ifdef LINUX
#	define	MASTER_TMPL	"/dev/pty  "
#	define	SLAVE_TMPL	"/dev/tty  "
#	define	LETTER1		"pqrs"
#	define	POS1		8
#	define	LETTER2		"0123456789abcdef"
#	define	POS2		9
#endif

#ifdef SCO
#	define	MASTER_TMPL	"/dev/ptyp_  "
#	define	SLAVE_TMPL	"/dev/ttyp_  "
#	define	LETTER1		"0123456"
#	define	POS1		10
#	define	LETTER2		"0123456789abcdef"
#	define	POS2		11
#endif

	if(ms_poll == MS_VTY || ms_poll == 0) {
		fstrcpy(master_name, MASTER_TMPL);
		fstrcpy(slave_name, SLAVE_TMPL);

		for(X = LETTER1; *X && master < 0; X++)
			for(Y = LETTER2; *Y && master < 0; Y++) {
				master_name [POS1] = *X;
				master_name [POS2] = *Y;
				if((master = open(master_name, O_RDWR)) >= 0) {
					slave_name [POS1] = *X;
					slave_name [POS2] = *Y;
					if((slave = open(slave_name, O_RDWR)) < 0)
						close(master);
				}
			}

		if(master >= 0 && slave >= 0)
			ms_type = MS_VTY;
	}

#	undef	MASTER_TMPL
#	undef	SLAVE_TMPL
#	undef	LETTER1
#	undef	LETTER2
#	undef	POS1
#	undef	POS2
#endif


#ifdef HAS_PTY
#ifdef SCO
#	define	MASTER_TMPL	"/dev/ptyp%d"
#	define	SLAVE_TMPL	"/dev/ttyp%d"
#	define	MIN_I		0
#	define	MAX_I		63
#endif

	if(ms_poll == MS_PTY || ms_poll == 0) {
		int	i;

		for(i = MIN_I; i <= MAX_I && master < 0; i++) {
			slprintf(master_name, sizeof(master_name) - 1, MASTER_TMPL, i);
			if((master = open(master_name, O_RDWR)) >= 0) {
				slprintf(slave_name, sizeof(slave_name) - 1, SLAVE_TMPL, i);
				if((slave = open(slave_name, O_RDWR)) < 0)
					close(master);
			}
		}

		if(master >= 0 && slave >= 0)
			ms_type = MS_PTY;
	}

#	undef	MASTER_TMPL
#	undef	SLAVE_TMPL
#	undef	MIN_I
#	undef	MAX_I
#endif


	if(! ms_type)
		return(-1);

	VT_Line = strdup(strrchr(slave_name, '/') + 1);

	switch((VT_ChildPID = fork())) {
	case -1:
		return(-1);
		break;

	case 0:
#ifdef SCO
		setsid();
#endif
		close(0);
		close(1);
		close(2);

		i = open(slave_name, O_RDWR);
		o = open(slave_name, O_RDWR);
		e = open(slave_name, O_RDWR);

#ifdef LINUX
		setsid();
		if (ioctl(slave, TIOCSCTTY, (char *)NULL) == -1)
			exit(1);
#endif
#ifdef SCO
		tcsetpgrp(0, getpid());
#endif

		VT_Start_utmp();

		system("stty sane");
		execlp("/bin/login", "login", "-c", (char*)0);
		exit(1);
		break;

	default:
		VT_Mode = True;
		VT_Status = VT_OPEN;
		VT_ChildDied = False;
		VT_Fd = master;

		signal(SIGCLD, VT_SigCLD);

		signal(SIGHUP, VT_SigEXIT);
		signal(SIGTERM, VT_SigEXIT);
		signal(SIGINT, VT_SigEXIT);
		signal(SIGQUIT, VT_SigEXIT);

		memset(OutBuf, 0, sizeof(OutBuf));
		OutBuf [4] = 0x06;
		_smb_setlen(OutBuf, 1);

		send_smb(Client,OutBuf);

		return(0);
		break;
	}
}


/*
VT_Output: transport data from socket to pty
*/
int	VT_Output(char	*Buffer)
{
	int		i, len, nb;


	if(VT_Status != VT_OPEN)
		return(-1);

	len = smb_len(Buffer);

	nb = write(VT_Fd, Buffer + 4, len);

	return((nb == len) ? 0 : -1);
}


/*
VT_Input: transport data from pty to socket
*/
int	VT_Input(char	*Buffer,int		Size)
{
	int		len;


	if(VT_Status != VT_OPEN)
		return(-1);

	memset(Buffer, 0, Size);
	len = read(VT_Fd, Buffer + 4, MIN(VT_MAXREAD, Size));

	_smb_setlen(Buffer, len);

	return(len + 4);
}


/*
VT_Process: main loop while in vt-mode
*/
void VT_Process(void)
{
	static int	trans_num = 0;
	extern int	Client;
	int			nread;


	VT_Start();

	atexit(VT_AtExit);

	while (True) {
		int32			len;      
		int				msg_type;
		int				msg_flags;
		int				counter;
		int				last_keepalive=0;
		struct fd_set	si;
		struct timeval	to, *top;
		int				n, ret, t;


		errno = 0;
		t = SMBD_SELECT_LOOP*1000;


		FD_ZERO(&si);
		FD_SET(Client, &si);

		FD_SET(VT_Fd, &si);

		if(t >= 0) {
			to.tv_sec = t / 1000;
			to.tv_usec = t - (to.tv_sec * 1000);

			top = &to;
		} else
			top = NULL;

		if(VT_ChildDied)
			goto leave_VT_Process;

		n = select(MAX(VT_Fd, Client) + 1, &si, NULL, NULL, top);

		if(VT_ChildDied)
			goto leave_VT_Process;
	
		if(n == 0) {
			int i;
			time_t t;
			BOOL allidle = True;
			extern int keepalive;
	
			counter += SMBD_SELECT_LOOP;

			t = time(NULL);
	
			if (keepalive && (counter-last_keepalive)>keepalive) {
				if (!send_keepalive(Client))
					goto leave_VT_Process;
				last_keepalive = counter;
			}
		} else if(n > 0) {
			counter = 0;

			if(FD_ISSET(VT_Fd, &si)) {
				/* got input from vt */
				nread = VT_Input(OutBuffer, MIN(BUFFER_SIZE,lp_maxxmit()));

				if(nread > 0)
					send_smb(Client,OutBuffer);
			}

			if(FD_ISSET(Client, &si)) {
				/* got input from socket */

				if(receive_smb(Client,InBuffer, 0)) {
					msg_type = CVAL(InBuffer,0);
					msg_flags = CVAL(InBuffer,1);
	
					len = smb_len(InBuffer);
	
					DEBUG(6,("got message type 0x%x of len 0x%x\n",msg_type,len));
	
					nread = len + 4;
     	 
					DEBUG(3,("%s Transaction %d of length %d\n",timestring(),trans_num,nread));
	
					if(msg_type == 0)
						VT_Output(InBuffer);
					else {
						nread = construct_reply(InBuffer,OutBuffer,nread,MIN(BUFFER_SIZE,lp_maxxmit()));
     	
						if(nread > 0) {
							if (nread != smb_len(OutBuffer) + 4) {
								DEBUG(0,("ERROR: Invalid message response size! %d %d\n",
									nread,
									smb_len(OutBuffer)));
							} else
								send_smb(Client,OutBuffer);
						}
					}
				} else
					if(errno == EBADF)
						goto leave_VT_Process;
			}
		}

		trans_num++;
	}

	leave_VT_Process:
/*
		if(VT_ChildPID > 0)
			kill(VT_ChildPID, SIGHUP);

		VT_Stop_utmp(VT_Line);
		return;
*/
		close_sockets();
		exit(0);
}
