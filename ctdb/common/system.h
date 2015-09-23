/*
   System specific code

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_SYSTEM_H__
#define __CTDB_SYSTEM_H__

/* From system_common.c */

uint32_t uint16_checksum(uint16_t *data, size_t n);
bool ctdb_sys_have_ip(ctdb_sock_addr *_addr);
char *ctdb_sys_find_ifname(ctdb_sock_addr *addr);

/* From system_<os>.c */

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface);
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest,
		      const ctdb_sock_addr *src,
		      uint32_t seq, uint32_t ack, int rst);
int ctdb_sys_open_capture_socket(const char *iface, void **private_data);
int ctdb_sys_close_capture_socket(void *private_data);
int ctdb_sys_read_tcp_packet(int s, void *private_data,
			ctdb_sock_addr *src, ctdb_sock_addr *dst,
			uint32_t *ack_seq, uint32_t *seq);
bool ctdb_sys_check_iface_exists(const char *iface);
int ctdb_get_peer_pid(const int fd, pid_t *peer_pid);

/* From system_util.c */

bool set_scheduler(void);
void reset_scheduler(void);
void set_nonblocking(int fd);
void set_close_on_exec(int fd);

bool parse_ipv4(const char *s, unsigned port, struct sockaddr_in *sin);
bool parse_ip(const char *addr, const char *ifaces, unsigned port,
	      ctdb_sock_addr *saddr);
bool parse_ip_mask(const char *str, const char *ifaces, ctdb_sock_addr *addr,
		   unsigned *mask);
bool parse_ip_port(const char *addr, ctdb_sock_addr *saddr);

void lockdown_memory(bool valgrinding);

int mkdir_p(const char *dir, int mode);
void mkdir_p_or_die(const char *dir, int mode);

ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);

#endif /* __CTDB_SYSTEM_H__ */
