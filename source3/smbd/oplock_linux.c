#define OLD_NTDOMAIN 1

/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   kernel oplock processing for Linux
   Copyright (C) Andrew Tridgell 2000
   
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

#if HAVE_KERNEL_OPLOCKS_LINUX

extern int DEBUGLEVEL;

static unsigned signals_received;
static unsigned signals_processed;
static int fd_pending; /* the fd of the current pending signal */

#ifndef F_SETLEASE
#define F_SETLEASE	1024
#endif

#ifndef F_GETLEASE
#define F_GETLEASE	1025
#endif

#ifndef CAP_LEASE
#define CAP_LEASE 28
#endif

#ifndef RT_SIGNAL_LEASE
#define RT_SIGNAL_LEASE 33
#endif

#ifndef F_SETSIG
#define F_SETSIG 10
#endif

/****************************************************************************
handle a LEASE signal, incrementing the signals_received and blocking the signal
****************************************************************************/
static void signal_handler(int signal, siginfo_t *info, void *unused)
{
	BlockSignals(True, signal);
	fd_pending = info->si_fd;
	signals_received++;
	sys_select_signal();
}

/****************************************************************************
try to gain a linux capability
****************************************************************************/static void set_capability(unsigned capability)
{
#ifndef _LINUX_CAPABILITY_VERSION
#define _LINUX_CAPABILITY_VERSION 0x19980330
#endif
	/* these can be removed when they are in glibc headers */
	struct  {
		uint32 version;
		int pid;
	} header;
	struct {
		uint32 effective;
		uint32 permitted;
		uint32 inheritable;
	} data;

	header.version = _LINUX_CAPABILITY_VERSION;
	header.pid = 0;

	if (capget(&header, &data) == -1) {
		DEBUG(3,("Unable to get kernel capabilities (%s)\n", strerror(errno)));
		return;
	}

	data.effective |= (1<<capability);

	if (capset(&header, &data) == -1) {
		DEBUG(3,("Unable to set %d capability (%s)\n", 
			 capability, strerror(errno)));
	}
}


/****************************************************************************
call SETLEASE. If we get EACCES then we try setting up the right capability and
try again
****************************************************************************/
static int linux_setlease(int fd, int leasetype)
{
	int ret;

	if (fcntl(fd, F_SETSIG, RT_SIGNAL_LEASE) == -1) {
		DEBUG(3,("Failed to set signal handler for kernel lease\n"));
		return -1;
	}

	ret = fcntl(fd, F_SETLEASE, leasetype);
	if (ret == -1 && errno == EACCES) {
		set_capability(CAP_LEASE);
		ret = fcntl(fd, F_SETLEASE, leasetype);
	}

	return ret;
}


/****************************************************************************
 * Deal with the Linux kernel <--> smbd
 * oplock break protocol.
****************************************************************************/
static BOOL linux_oplock_receive_message(fd_set *fds, char *buffer, int buffer_len)
{
	SMB_DEV_T dev;
	SMB_INO_T inode;
	SMB_STRUCT_STAT sbuf;
	BOOL ret;

	if (signals_received == signals_processed) return False;

	if (sys_fstat(fd_pending,&sbuf) == -1) {
		DEBUG(0,("Invalid file descriptor %d in kernel oplock break!\n", fd_pending));
		ret = False;
		goto out;
	}

	dev = sbuf.st_dev;
	inode = sbuf.st_ino;
     
	DEBUG(3,("receive_local_message: kernel oplock break request received for \
dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode ));
     
	/*
	 * Create a kernel oplock break message.
	 */
     
	/* Setup the message header */
	SIVAL(buffer,OPBRK_CMD_LEN_OFFSET,KERNEL_OPLOCK_BREAK_MSG_LEN);
	SSVAL(buffer,OPBRK_CMD_PORT_OFFSET,0);
     
	buffer += OPBRK_CMD_HEADER_LEN;
     
	SSVAL(buffer,OPBRK_MESSAGE_CMD_OFFSET,KERNEL_OPLOCK_BREAK_CMD);
     
	memcpy(buffer + KERNEL_OPLOCK_BREAK_DEV_OFFSET, (char *)&dev, sizeof(dev));
	memcpy(buffer + KERNEL_OPLOCK_BREAK_INODE_OFFSET, (char *)&inode, sizeof(inode));	

 out:
	/* now we can receive more signals */
	fd_pending = -1;
	signals_processed++;
	BlockSignals(False, RT_SIGNAL_LEASE);
     
	return True;
}


/****************************************************************************
 Attempt to set an kernel oplock on a file.
****************************************************************************/
static BOOL linux_set_kernel_oplock(files_struct *fsp, int oplock_type)
{
	if (linux_setlease(fsp->fd, F_WRLCK) == -1) {
		DEBUG(3,("set_file_oplock: Refused oplock on file %s, fd = %d, dev = %x, \
inode = %.0f. (%s)\n",
			 fsp->fsp_name, fsp->fd, 
			 (unsigned int)fsp->dev, (double)fsp->inode, strerror(errno)));
		return False;
	}
	
	DEBUG(3,("set_file_oplock: got kernel oplock on file %s, dev = %x, inode = %.0f\n",
		  fsp->fsp_name, (unsigned int)fsp->dev, (double)fsp->inode));

	return True;
}


/****************************************************************************
 Release a kernel oplock on a file.
****************************************************************************/
static void linux_release_kernel_oplock(files_struct *fsp)
{
	if (DEBUGLVL(10)) {
		/*
		 * Check and print out the current kernel
		 * oplock state of this file.
		 */
		int state = fcntl(fsp->fd, F_GETLEASE, 0);
		dbgtext("release_kernel_oplock: file %s, dev = %x, inode = %.0f has kernel \
oplock state of %x.\n", fsp->fsp_name, (unsigned int)fsp->dev,
                        (double)fsp->inode, state );
	}

	/*
	 * Remove the kernel oplock on this file.
	 */
	if (linux_setlease(fsp->fd, F_UNLCK) == -1) {
		if (DEBUGLVL(0)) {
			dbgtext("release_kernel_oplock: Error when removing kernel oplock on file " );
			dbgtext("%s, dev = %x, inode = %.0f. Error was %s\n",
				fsp->fsp_name, (unsigned int)fsp->dev, 
				(double)fsp->inode, strerror(errno) );
		}
	}
}


/****************************************************************************
parse a kernel oplock message
****************************************************************************/
static BOOL linux_kernel_oplock_parse(char *msg_start, int msg_len, SMB_INO_T *inode, SMB_DEV_T *dev)
{
	/* Ensure that the msg length is correct. */
	if (msg_len != KERNEL_OPLOCK_BREAK_MSG_LEN) {
		DEBUG(0,("incorrect length for KERNEL_OPLOCK_BREAK_CMD (was %d, should be %d).\n", 
			 msg_len, KERNEL_OPLOCK_BREAK_MSG_LEN));
		return False;
	}

        memcpy((char *)inode, msg_start+KERNEL_OPLOCK_BREAK_INODE_OFFSET, sizeof(*inode));
        memcpy((char *)dev, msg_start+KERNEL_OPLOCK_BREAK_DEV_OFFSET, sizeof(*dev));

        DEBUG(3,("kernel oplock break request for file dev = %x, inode = %.0f\n", 
		 (unsigned int)*dev, (double)*inode));

	return True;
}


/****************************************************************************
see if a oplock message is waiting
****************************************************************************/
static BOOL linux_oplock_msg_waiting(fd_set *fds)
{
	return signals_processed != signals_received;
}

/****************************************************************************
see if the kernel supports oplocks
****************************************************************************/
static BOOL linux_oplocks_available(void)
{
	int fd, ret;
	fd = open("/dev/null", O_RDONLY);
	if (fd == -1) return False; /* uggh! */
	ret = fcntl(fd, F_GETLEASE, 0);
	close(fd);
	return ret == F_UNLCK;
}


/****************************************************************************
setup kernel oplocks
****************************************************************************/
struct kernel_oplocks *linux_init_kernel_oplocks(void) 
{
	static struct kernel_oplocks koplocks;
        struct sigaction act;

	if (!linux_oplocks_available()) {
		DEBUG(3,("Linux kernel oplocks not available\n"));
		return NULL;
	}

        act.sa_handler = NULL;
        act.sa_sigaction = signal_handler;
        act.sa_flags = SA_SIGINFO;
        if (sigaction(RT_SIGNAL_LEASE, &act, NULL) != 0) {
		DEBUG(0,("Failed to setup RT_SIGNAL_LEASE handler\n"));
		return NULL;
        }

	koplocks.receive_message = linux_oplock_receive_message;
	koplocks.set_oplock = linux_set_kernel_oplock;
	koplocks.release_oplock = linux_release_kernel_oplock;
	koplocks.parse_message = linux_kernel_oplock_parse;
	koplocks.msg_waiting = linux_oplock_msg_waiting;
	koplocks.notification_fd = -1;

	DEBUG(3,("Linux kernel oplocks enabled\n"));

	return &koplocks;
}



#else
 void oplock_linux_dummy(void) {}
#endif /* HAVE_KERNEL_OPLOCKS_LINUX */

#undef OLD_NTDOMAIN

