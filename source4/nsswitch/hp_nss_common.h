#ifndef _HP_NSS_COMMON_H
#define _HP_NSS_COMMON_H
 
/*
   Unix SMB/CIFS implementation.
 
   Donated by HP to enable Winbindd to build on HPUX 11.x.
   Copyright (C) Jeremy Allison 2002.
 
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
 
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
 
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.
*/
 
#ifdef HAVE_SYNCH_H
#include <synch.h>
#endif
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
 
typedef enum {
	NSS_SUCCESS,
	NSS_NOTFOUND,
	NSS_UNAVAIL,
	NSS_TRYAGAIN
} nss_status_t;
 
struct nss_backend;
 
typedef nss_status_t (*nss_backend_op_t)(struct nss_backend *, void *args);
 
struct nss_backend {
	nss_backend_op_t *ops;
	int n_ops;
};
typedef struct nss_backend nss_backend_t;
typedef int nss_dbop_t;

#endif /* _HP_NSS_COMMON_H */
