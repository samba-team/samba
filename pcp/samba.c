/*
 * Samba, configurable PMDA
 *
 * Copyright (c) 2000 Silicon Graphics, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * Contact information: Silicon Graphics, Inc., 1600 Amphitheatre Pkwy,
 * Mountain View, CA  94043, or:
 *
 * http://www.sgi.com
 *
 * For further information regarding this notice, see:
 *
 * http://oss.sgi.com/projects/GenInfo/SGIGPLNoticeExplan/
 */

typedef int BOOL;

#define IRIX 1

#include <stdio.h>
#include <sys/shm.h>
#include <pcp/pmapi.h>
#ifdef IRIX
#include <pcp/impl.h>
#endif
#include <pcp/pmda.h>
#include "domain.h"
#include "profile.h"

/*
 * lifted definitions from the samba source
 */

#define MAX_OPEN_FILES 10000	/* from local.h */

/*
 * all metrics supported in this PMDA - one table entry for each
 */
static pmdaMetric metrictab[] = {
/* smbd.smb_count */
    { NULL, { PMDA_PMID(0,0), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* smbd.uid_changes */
    { NULL, { PMDA_PMID(0,1), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.opendir */
    { NULL, { PMDA_PMID(1,2), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.opendir_time */
    { NULL, { PMDA_PMID(1,3), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.readdir */
    { NULL, { PMDA_PMID(1,4), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.readdir_time */
    { NULL, { PMDA_PMID(1,5), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.mkdir */
    { NULL, { PMDA_PMID(1,6), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.mkdir_time */
    { NULL, { PMDA_PMID(1,7), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.rmdir */
    { NULL, { PMDA_PMID(1,8), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.rmdir_time */
    { NULL, { PMDA_PMID(1,9), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.closedir */
    { NULL, { PMDA_PMID(1,10), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.closedir_time */
    { NULL, { PMDA_PMID(1,11), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.open */
    { NULL, { PMDA_PMID(1,12), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.open_time */
    { NULL, { PMDA_PMID(1,13), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.close */
    { NULL, { PMDA_PMID(1,14), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.close_time */
    { NULL, { PMDA_PMID(1,15), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.read_count */
    { NULL, { PMDA_PMID(1,16), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.read_time */
    { NULL, { PMDA_PMID(1,17), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.read_bytes */
    { NULL, { PMDA_PMID(1,18), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 1,0,0,PM_SPACE_BYTE,0,0} }, },
/* syscalls.write_count */
    { NULL, { PMDA_PMID(1,19), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.write_time */
    { NULL, { PMDA_PMID(1,20), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.write_bytes */
    { NULL, { PMDA_PMID(1,21), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 1,0,0,PM_SPACE_BYTE,0,0} }, },
/* syscalls.lseek */
    { NULL, { PMDA_PMID(1,22), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.lseek_time */
    { NULL, { PMDA_PMID(1,23), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.rename */
    { NULL, { PMDA_PMID(1,24), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.rename_time */
    { NULL, { PMDA_PMID(1,25), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.fsync */
    { NULL, { PMDA_PMID(1,26), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.fsync_time */
    { NULL, { PMDA_PMID(1,27), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.stat */
    { NULL, { PMDA_PMID(1,28), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.stat_time */
    { NULL, { PMDA_PMID(1,29), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.fstat */
    { NULL, { PMDA_PMID(1,30), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.fstat_time */
    { NULL, { PMDA_PMID(1,31), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.lstat */
    { NULL, { PMDA_PMID(1,32), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.lstat_time */
    { NULL, { PMDA_PMID(1,33), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.unlink */
    { NULL, { PMDA_PMID(1,34), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.unlink_time */
    { NULL, { PMDA_PMID(1,35), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.chmod */
    { NULL, { PMDA_PMID(1,36), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.chmod_time */
    { NULL, { PMDA_PMID(1,37), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.chown */
    { NULL, { PMDA_PMID(1,38), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.chown_time */
    { NULL, { PMDA_PMID(1,39), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.chdir */
    { NULL, { PMDA_PMID(1,40), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.chdir_time */
    { NULL, { PMDA_PMID(1,41), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.getwd */
    { NULL, { PMDA_PMID(1,42), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.getwd_time */
    { NULL, { PMDA_PMID(1,43), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.utime */
    { NULL, { PMDA_PMID(1,44), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.utime_time */
    { NULL, { PMDA_PMID(1,45), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.ftruncate */
    { NULL, { PMDA_PMID(1,46), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.ftruncate_time */
    { NULL, { PMDA_PMID(1,47), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* syscalls.fcntl_lock */
    { NULL, { PMDA_PMID(1,48), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* syscalls.fcntl_time */
    { NULL, { PMDA_PMID(1,49), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* statcache.lookups */
    { NULL, { PMDA_PMID(2,50), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* statcache.misses */
    { NULL, { PMDA_PMID(2,51), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* statcache.hits */
    { NULL, { PMDA_PMID(2,52), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.num_caches */
    { NULL, { PMDA_PMID(3,53), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.allocated_caches */
    { NULL, { PMDA_PMID(3,54), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_INSTANT, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.read_hits */
    { NULL, { PMDA_PMID(3,55), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.total_writes */
    { NULL, { PMDA_PMID(3,56), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.init_writes */
    { NULL, { PMDA_PMID(3,57), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.abutted_writes */
    { NULL, { PMDA_PMID(3,58), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.perfect_writes */
    { NULL, { PMDA_PMID(3,59), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.direct_writes */
    { NULL, { PMDA_PMID(3,60), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.non_oplock_writes */
    { NULL, { PMDA_PMID(3,61), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.seek_flush */
    { NULL, { PMDA_PMID(3,62), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.read_flush */
    { NULL, { PMDA_PMID(3,63), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.write_flush */
    { NULL, { PMDA_PMID(3,64), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.readraw_flush */
    { NULL, { PMDA_PMID(3,65), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.oplock_rel_flush */
    { NULL, { PMDA_PMID(3,66), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.close_flush */
    { NULL, { PMDA_PMID(3,67), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.sync_flush */
    { NULL, { PMDA_PMID(3,68), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* writecache.size_change_flush */
    { NULL, { PMDA_PMID(3,69), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_mkdir */
    { NULL, { PMDA_PMID(4,70), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_mkdir_time */
    { NULL, { PMDA_PMID(4,71), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_rmdir */
    { NULL, { PMDA_PMID(4,72), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_rmdir_time */
    { NULL, { PMDA_PMID(4,73), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_open */
    { NULL, { PMDA_PMID(4,74), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_open_time */
    { NULL, { PMDA_PMID(4,75), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_create */
    { NULL, { PMDA_PMID(4,76), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_create_time */
    { NULL, { PMDA_PMID(4,77), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_close */
    { NULL, { PMDA_PMID(4,78), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_close_time */
    { NULL, { PMDA_PMID(4,79), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_flush */
    { NULL, { PMDA_PMID(4,80), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_flush_time */
    { NULL, { PMDA_PMID(4,81), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_unlink */
    { NULL, { PMDA_PMID(4,82), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_unlink_time */
    { NULL, { PMDA_PMID(4,83), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_mv */
    { NULL, { PMDA_PMID(4,84), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_mv_time */
    { NULL, { PMDA_PMID(4,85), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_getattr */
    { NULL, { PMDA_PMID(4,86), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_getattr_time */
    { NULL, { PMDA_PMID(4,87), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_setattr */
    { NULL, { PMDA_PMID(4,88), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_setattr_time */
    { NULL, { PMDA_PMID(4,89), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_read */
    { NULL, { PMDA_PMID(4,90), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_read_time */
    { NULL, { PMDA_PMID(4,91), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_write */
    { NULL, { PMDA_PMID(4,92), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_write_time */
    { NULL, { PMDA_PMID(4,93), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_lock */
    { NULL, { PMDA_PMID(4,94), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_lock_time */
    { NULL, { PMDA_PMID(4,95), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_unlock */
    { NULL, { PMDA_PMID(4,96), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_unlock_time */
    { NULL, { PMDA_PMID(4,97), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_ctemp */
    { NULL, { PMDA_PMID(4,98), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_ctemp_time */
    { NULL, { PMDA_PMID(4,99), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_mknew */
    { NULL, { PMDA_PMID(4,100), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_mknew_time */
    { NULL, { PMDA_PMID(4,101), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_chkpth */
    { NULL, { PMDA_PMID(4,102), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_chkpth_time */
    { NULL, { PMDA_PMID(4,103), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_exit */
    { NULL, { PMDA_PMID(4,104), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_exit_time */
    { NULL, { PMDA_PMID(4,105), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_lseek */
    { NULL, { PMDA_PMID(4,106), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_lseek_time */
    { NULL, { PMDA_PMID(4,107), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_lockread */
    { NULL, { PMDA_PMID(4,108), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_lockread_time */
    { NULL, { PMDA_PMID(4,109), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeunlock */
    { NULL, { PMDA_PMID(4,110), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeunlock_time */
    { NULL, { PMDA_PMID(4,111), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_readBraw */
    { NULL, { PMDA_PMID(4,112), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_readBraw_time */
    { NULL, { PMDA_PMID(4,113), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_readBmpx */
    { NULL, { PMDA_PMID(4,114), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_readBmpx_time */
    { NULL, { PMDA_PMID(4,115), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_readBs */
    { NULL, { PMDA_PMID(4,116), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_readBs_time */
    { NULL, { PMDA_PMID(4,117), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeBraw */
    { NULL, { PMDA_PMID(4,118), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeBraw_time */
    { NULL, { PMDA_PMID(4,119), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeBmpx */
    { NULL, { PMDA_PMID(4,120), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeBmpx_time */
    { NULL, { PMDA_PMID(4,121), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeBs */
    { NULL, { PMDA_PMID(4,122), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeBs_time */
    { NULL, { PMDA_PMID(4,123), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writec */
    { NULL, { PMDA_PMID(4,124), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writec_time */
    { NULL, { PMDA_PMID(4,125), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_setattrE */
    { NULL, { PMDA_PMID(4,126), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_setattrE_time */
    { NULL, { PMDA_PMID(4,127), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_getattrE */
    { NULL, { PMDA_PMID(4,128), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_getattrE_time */
    { NULL, { PMDA_PMID(4,129), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_lockingX */
    { NULL, { PMDA_PMID(4,130), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_lockingX_time */
    { NULL, { PMDA_PMID(4,131), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_trans */
    { NULL, { PMDA_PMID(4,132), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_trans_time */
    { NULL, { PMDA_PMID(4,133), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_transs */
    { NULL, { PMDA_PMID(4,134), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_transs_time */
    { NULL, { PMDA_PMID(4,135), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_ioctl */
    { NULL, { PMDA_PMID(4,136), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_ioctl_time */
    { NULL, { PMDA_PMID(4,137), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_ioctls */
    { NULL, { PMDA_PMID(4,138), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_ioctls_time */
    { NULL, { PMDA_PMID(4,139), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_copy */
    { NULL, { PMDA_PMID(4,140), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_copy_time */
    { NULL, { PMDA_PMID(4,141), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_move */
    { NULL, { PMDA_PMID(4,142), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_move_time */
    { NULL, { PMDA_PMID(4,143), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_echo */
    { NULL, { PMDA_PMID(4,144), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_echo_time */
    { NULL, { PMDA_PMID(4,145), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeclose */
    { NULL, { PMDA_PMID(4,146), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeclose_time */
    { NULL, { PMDA_PMID(4,147), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_openX */
    { NULL, { PMDA_PMID(4,148), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_openX_time */
    { NULL, { PMDA_PMID(4,149), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_readX */
    { NULL, { PMDA_PMID(4,150), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_readX_time */
    { NULL, { PMDA_PMID(4,151), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_writeX */
    { NULL, { PMDA_PMID(4,152), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_writeX_time */
    { NULL, { PMDA_PMID(4,153), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_trans2 */
    { NULL, { PMDA_PMID(4,154), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_trans2_time */
    { NULL, { PMDA_PMID(4,155), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_transs2 */
    { NULL, { PMDA_PMID(4,156), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_transs2_time */
    { NULL, { PMDA_PMID(4,157), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_findclose */
    { NULL, { PMDA_PMID(4,158), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_findclose_time */
    { NULL, { PMDA_PMID(4,159), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_findNclose */
    { NULL, { PMDA_PMID(4,160), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_findNclose_time */
    { NULL, { PMDA_PMID(4,161), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_tcon */
    { NULL, { PMDA_PMID(4,162), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_tcon_time */
    { NULL, { PMDA_PMID(4,163), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_tdis */
    { NULL, { PMDA_PMID(4,164), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_tdis_time */
    { NULL, { PMDA_PMID(4,165), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_negprot */
    { NULL, { PMDA_PMID(4,166), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_negprot_time */
    { NULL, { PMDA_PMID(4,167), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sessetupX */
    { NULL, { PMDA_PMID(4,168), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sessetupX_time */
    { NULL, { PMDA_PMID(4,169), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_ulogoffX */
    { NULL, { PMDA_PMID(4,170), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_ulogoffX_time */
    { NULL, { PMDA_PMID(4,171), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_tconX */
    { NULL, { PMDA_PMID(4,172), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_tconX_time */
    { NULL, { PMDA_PMID(4,173), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_dskattr */
    { NULL, { PMDA_PMID(4,174), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_dskattr_time */
    { NULL, { PMDA_PMID(4,175), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_search */
    { NULL, { PMDA_PMID(4,176), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_search_time */
    { NULL, { PMDA_PMID(4,177), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_ffisrst */
    { NULL, { PMDA_PMID(4,178), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_ffisrst_time */
    { NULL, { PMDA_PMID(4,179), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_funique */
    { NULL, { PMDA_PMID(4,180), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_funique_time */
    { NULL, { PMDA_PMID(4,181), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_fclose */
    { NULL, { PMDA_PMID(4,182), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_fclose_time */
    { NULL, { PMDA_PMID(4,183), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_NTtrans */
    { NULL, { PMDA_PMID(4,184), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_NTtrans_time */
    { NULL, { PMDA_PMID(4,185), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_NTtranss */
    { NULL, { PMDA_PMID(4,186), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_NTtranss_time */
    { NULL, { PMDA_PMID(4,187), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_NTcreateX */
    { NULL, { PMDA_PMID(4,188), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_NTcreateX_time */
    { NULL, { PMDA_PMID(4,189), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_NTcancel */
    { NULL, { PMDA_PMID(4,190), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_NTcancel_time */
    { NULL, { PMDA_PMID(4,191), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_splopen */
    { NULL, { PMDA_PMID(4,192), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_splopen_time */
    { NULL, { PMDA_PMID(4,193), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_splwrite */
    { NULL, { PMDA_PMID(4,194), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_splwrite_time */
    { NULL, { PMDA_PMID(4,195), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_splclose */
    { NULL, { PMDA_PMID(4,196), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_splclose_time */
    { NULL, { PMDA_PMID(4,197), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_splretq */
    { NULL, { PMDA_PMID(4,198), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_splretq_time */
    { NULL, { PMDA_PMID(4,199), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sends */
    { NULL, { PMDA_PMID(4,200), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sends_time */
    { NULL, { PMDA_PMID(4,201), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sendb */
    { NULL, { PMDA_PMID(4,202), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sendb_time */
    { NULL, { PMDA_PMID(4,203), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_fwdname */
    { NULL, { PMDA_PMID(4,204), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_fwdname_time */
    { NULL, { PMDA_PMID(4,205), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_cancelf */
    { NULL, { PMDA_PMID(4,206), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_cancelf_time */
    { NULL, { PMDA_PMID(4,207), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_getmach */
    { NULL, { PMDA_PMID(4,208), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_getmach_time */
    { NULL, { PMDA_PMID(4,209), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sendstrt */
    { NULL, { PMDA_PMID(4,210), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sendstrt_time */
    { NULL, { PMDA_PMID(4,211), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sendend */
    { NULL, { PMDA_PMID(4,212), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sendend_time */
    { NULL, { PMDA_PMID(4,213), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_sendtxt */
    { NULL, { PMDA_PMID(4,214), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_sendtxt_time */
    { NULL, { PMDA_PMID(4,215), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.SMB_invalid */
    { NULL, { PMDA_PMID(4,216), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.SMB_invalid_time */
    { NULL, { PMDA_PMID(4,217), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.PATHWORK_setdir */
    { NULL, { PMDA_PMID(4,218), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.PATHWORK_setdir_time */
    { NULL, { PMDA_PMID(4,219), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_open */
    { NULL, { PMDA_PMID(4,220), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_open_time */
    { NULL, { PMDA_PMID(4,221), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_ffirst */
    { NULL, { PMDA_PMID(4,222), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_ffirst_time */
    { NULL, { PMDA_PMID(4,223), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_fnext */
    { NULL, { PMDA_PMID(4,224), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_fnext_time */
    { NULL, { PMDA_PMID(4,225), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_qfsinfo */
    { NULL, { PMDA_PMID(4,226), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_qfsinfo_time */
    { NULL, { PMDA_PMID(4,227), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_sfsinfo */
    { NULL, { PMDA_PMID(4,228), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_sfsinfo_time */
    { NULL, { PMDA_PMID(4,229), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_qpathinfo */
    { NULL, { PMDA_PMID(4,230), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_qpathinfo_time */
    { NULL, { PMDA_PMID(4,231), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_spathinfo */
    { NULL, { PMDA_PMID(4,232), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_spathinfo_time */
    { NULL, { PMDA_PMID(4,233), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_qfileinfo */
    { NULL, { PMDA_PMID(4,234), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_qfileinfo_time */
    { NULL, { PMDA_PMID(4,235), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_sfileinfo */
    { NULL, { PMDA_PMID(4,236), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_sfileinfo_time */
    { NULL, { PMDA_PMID(4,237), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_fsctl */
    { NULL, { PMDA_PMID(4,238), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_fsctl_time */
    { NULL, { PMDA_PMID(4,239), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_ioctl */
    { NULL, { PMDA_PMID(4,240), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_ioctl_time */
    { NULL, { PMDA_PMID(4,241), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_fnotifyfirst */
    { NULL, { PMDA_PMID(4,242), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_fnotifyfirst_time */
    { NULL, { PMDA_PMID(4,243), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_fnotifynext */
    { NULL, { PMDA_PMID(4,244), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_fnotifynext_time */
    { NULL, { PMDA_PMID(4,245), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_mkdir */
    { NULL, { PMDA_PMID(4,246), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_mkdir_time */
    { NULL, { PMDA_PMID(4,247), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_sessetup */
    { NULL, { PMDA_PMID(4,248), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_sessetup_time */
    { NULL, { PMDA_PMID(4,249), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_getDFSref */
    { NULL, { PMDA_PMID(4,250), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_getDFSref_time */
    { NULL, { PMDA_PMID(4,251), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.TRANS2_rptDFSinconsist */
    { NULL, { PMDA_PMID(4,252), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.TRANS2_rptDFSinconsist_time */
    { NULL, { PMDA_PMID(4,253), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_create */
    { NULL, { PMDA_PMID(4,254), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_create_time */
    { NULL, { PMDA_PMID(4,255), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_ioctl */
    { NULL, { PMDA_PMID(4,256), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_ioctl_time */
    { NULL, { PMDA_PMID(4,257), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_setsecdesc */
    { NULL, { PMDA_PMID(4,258), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_setsecdesc_time */
    { NULL, { PMDA_PMID(4,259), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_notifychange */
    { NULL, { PMDA_PMID(4,260), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_notifychange_time */
    { NULL, { PMDA_PMID(4,261), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_rename */
    { NULL, { PMDA_PMID(4,262), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_rename_time */
    { NULL, { PMDA_PMID(4,263), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, },
/* SMB.NTTRANS_qsecdesc */
    { NULL, { PMDA_PMID(4,264), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,0,1,0,0,PM_COUNT_ONE} }, },
/* SMB.NTTRANS_qsecdesc_time */
    { NULL, { PMDA_PMID(4,265), PM_TYPE_U32, PM_INDOM_NULL, PM_SEM_COUNTER, 
		{ 0,1,0,0,PM_TIME_USEC,0} }, }
};

extern int	errno;
struct profile_stats	*stats;
struct profile_header	*shmheader;
int		shmid = -1;


int
samba_fetchCallBack(pmdaMetric *mdesc, unsigned int inst, pmAtomValue *atom)
{
    __pmID_int		*idp = (__pmID_int *)&(mdesc->m_desc.pmid);

    if (inst != PM_IN_NULL && mdesc->m_desc.indom == PM_INDOM_NULL)
	return PM_ERR_INST;

    if (idp->cluster == 0) {
	switch (idp->item) {
	    case 0:			/* smbd.smb_count */
		atom->ul = stats->smb_count;
		break;
	    case 1:			/* smb.uid_changes */
		atom->ul = stats->uid_changes;
		break;
	    default:
		return PM_ERR_PMID;
	}
    }
    else if (idp->cluster == 1) {
	switch (idp->item) {
	    case 2:			/* syscalls.opendir */
		atom->ul = stats->syscall_opendir_count;
		break;
	    case 3:			/* syscalls.opendir */
		atom->ul = stats->syscall_opendir_time;
		break;
	    case 4:			/* syscalls.readdir */
		atom->ul = stats->syscall_readdir_count;
		break;
	    case 5:			/* syscalls.readdir */
		atom->ul = stats->syscall_readdir_time;
		break;
	    case 6:			/* syscalls.mkdir */
		atom->ul = stats->syscall_mkdir_count;
		break;
	    case 7:			/* syscalls.mkdir */
		atom->ul = stats->syscall_mkdir_time;
		break;
	    case 8:			/* syscalls.rmdir */
		atom->ul = stats->syscall_rmdir_count;
		break;
	    case 9:			/* syscalls.rmdir */
		atom->ul = stats->syscall_rmdir_time;
		break;
	    case 10:			/* syscalls.closedir */
		atom->ul = stats->syscall_closedir_count;
		break;
	    case 11:			/* syscalls.closedir */
		atom->ul = stats->syscall_closedir_time;
		break;
	    case 12:			/* syscalls.open */
		atom->ul = stats->syscall_open_count;
		break;
	    case 13:			/* syscalls.open */
		atom->ul = stats->syscall_open_time;
		break;
	    case 14:			/* syscalls.close */
		atom->ul = stats->syscall_close_count;
		break;
	    case 15:			/* syscalls.close */
		atom->ul = stats->syscall_close_time;
		break;
	    case 16:			/* syscalls.read */
		atom->ul = stats->syscall_read_count;
		break;
	    case 17:			/* syscalls.read */
		atom->ul = stats->syscall_read_time;
		break;
	    case 18:			/* syscalls.read */
		atom->ul = stats->syscall_read_bytes;
		break;
	    case 19:			/* syscalls.write */
		atom->ul = stats->syscall_write_count;
		break;
	    case 20:			/* syscalls.write */
		atom->ul = stats->syscall_write_time;
		break;
	    case 21:			/* syscalls.write */
		atom->ul = stats->syscall_write_bytes;
		break;
	    case 22:			/* syscalls.lseek */
		atom->ul = stats->syscall_lseek_count;
		break;
	    case 23:			/* syscalls.lseek */
		atom->ul = stats->syscall_lseek_time;
		break;
	    case 24:			/* syscalls.rename */
		atom->ul = stats->syscall_rename_count;
		break;
	    case 25:			/* syscalls.rename */
		atom->ul = stats->syscall_rename_time;
		break;
	    case 26:			/* syscalls.fsync */
		atom->ul = stats->syscall_fsync_count;
		break;
	    case 27:			/* syscalls.fsync */
		atom->ul = stats->syscall_fsync_time;
		break;
	    case 28:			/* syscalls.stat */
		atom->ul = stats->syscall_stat_count;
		break;
	    case 29:			/* syscalls.stat */
		atom->ul = stats->syscall_stat_time;
		break;
	    case 30:			/* syscalls.fstat */
		atom->ul = stats->syscall_fstat_count;
		break;
	    case 31:			/* syscalls.fstat */
		atom->ul = stats->syscall_fstat_time;
		break;
	    case 32:			/* syscalls.lstat */
		atom->ul = stats->syscall_lstat_count;
		break;
	    case 33:			/* syscalls.lstat */
		atom->ul = stats->syscall_lstat_time;
		break;
	    case 34:			/* syscalls.unlink */
		atom->ul = stats->syscall_unlink_count;
		break;
	    case 35:			/* syscalls.unlink */
		atom->ul = stats->syscall_unlink_time;
		break;
	    case 36:			/* syscalls.chmod */
		atom->ul = stats->syscall_chmod_count;
		break;
	    case 37:			/* syscalls.chmod */
		atom->ul = stats->syscall_chmod_time;
		break;
	    case 38:			/* syscalls.chown */
		atom->ul = stats->syscall_chown_count;
		break;
	    case 39:			/* syscalls.chown */
		atom->ul = stats->syscall_chown_time;
		break;
	    case 40:			/* syscalls.chdir */
		atom->ul = stats->syscall_chdir_count;
		break;
	    case 41:			/* syscalls.chdir */
		atom->ul = stats->syscall_chdir_time;
		break;
	    case 42:			/* syscalls.getwd */
		atom->ul = stats->syscall_getwd_count;
		break;
	    case 43:			/* syscalls.getwd */
		atom->ul = stats->syscall_getwd_time;
		break;
	    case 44:			/* syscalls.utime */
		atom->ul = stats->syscall_utime_count;
		break;
	    case 45:			/* syscalls.utime */
		atom->ul = stats->syscall_utime_time;
		break;
	    case 46:			/* syscalls.ftruncate */
		atom->ul = stats->syscall_ftruncate_count;
		break;
	    case 47:			/* syscalls.ftruncate */
		atom->ul = stats->syscall_ftruncate_time;
		break;
	    case 48:			/* syscalls.fcntl_lock */
		atom->ul = stats->syscall_fcntl_lock_count;
		break;
	    case 49:			/* syscalls.fcntl_lock */
		atom->ul = stats->syscall_fcntl_lock_time;
		break;
	    default:
		return PM_ERR_PMID;
	}
    }
    else if (idp->cluster == 2) {
	switch (idp->item) {
	    case 50:			/* statcache.lookups */
		atom->ul = stats->statcache_lookups;
		break;
	    case 51:			/* statcache.misses */
		atom->ul = stats->statcache_misses;
		break;
	    case 52:			/* statcache.hits */
		atom->ul = stats->statcache_hits;
		break;
	    default:
		return PM_ERR_PMID;
	}
    }
    else if (idp->cluster == 3) {
	switch (idp->item) {
	    case 53:			/* writecache.num_caches */
		atom->ul = stats->writecache_num_write_caches;
		break;
	    case 54:			/* writecache.allocated_caches */
		atom->ul = stats->writecache_allocated_write_caches;
		break;
	    case 55:			/* writecache.read_hits */
		atom->ul = stats->writecache_read_hits;
		break;
	    case 56:			/* writecache.total_writes */
		atom->ul = stats->writecache_total_writes;
		break;
	    case 57:			/* writecache.init_writes */
		atom->ul = stats->writecache_init_writes;
		break;
	    case 58:			/* writecache.abutted_writes */
		atom->ul = stats->writecache_abutted_writes;
		break;
	    case 59:			/* writecache.perfect_writes */
		atom->ul = stats->writecache_num_perfect_writes;
		break;
	    case 60:			/* writecache.direct_writes */
		atom->ul = stats->writecache_direct_writes;
		break;
	    case 61:			/* writecache.non_oplock_writes */
		atom->ul = stats->writecache_non_oplock_writes;
		break;
	    case 62:			/* writecache.seek_flush */
		atom->ul = stats->writecache_flushed_writes[SEEK_FLUSH];
		break;
	    case 63:			/* writecache.read_flush */
		atom->ul = stats->writecache_flushed_writes[READ_FLUSH];
		break;
	    case 64:			/* writecache.write_flush */
		atom->ul = stats->writecache_flushed_writes[WRITE_FLUSH];
		break;
	    case 65:			/* writecache.readraw_flush */
		atom->ul = stats->writecache_flushed_writes[READRAW_FLUSH];
		break;
	    case 66:			/* writecache.oplock_rel_flush */
		atom->ul = stats->writecache_flushed_writes[OPLOCK_RELEASE_FLUSH];
		break;
	    case 67:			/* writecache.close_flush */
		atom->ul = stats->writecache_flushed_writes[CLOSE_FLUSH];
		break;
	    case 68:			/* writecache.sync_flush */
		atom->ul = stats->writecache_flushed_writes[SYNC_FLUSH];
		break;
	    case 69:			/* writecache.size_change_flush */
		atom->ul = stats->writecache_flushed_writes[SIZECHANGE_FLUSH];
		break;
	    default:
		return PM_ERR_PMID;
	}
    }
    else if (idp->cluster == 4) {
	switch (idp->item) {
	    case 70:			/* SMB.SMB_mkdir */
		atom->ul = stats->SMBmkdir_count;
		break;
	    case 71:			/* SMB.SMB_mkdir */
		atom->ul = stats->SMBmkdir_time;
		break;
	    case 72:			/* SMB.SMB_rmdir */
		atom->ul = stats->SMBrmdir_count;
		break;
	    case 73:			/* SMB.SMB_rmdir */
		atom->ul = stats->SMBrmdir_time;
		break;
	    case 74:			/* SMB.SMB_open */
		atom->ul = stats->SMBopen_count;
		break;
	    case 75:			/* SMB.SMB_open */
		atom->ul = stats->SMBopen_time;
		break;
	    case 76:			/* SMB.SMB_create */
		atom->ul = stats->SMBcreate_count;
		break;
	    case 77:			/* SMB.SMB_create */
		atom->ul = stats->SMBcreate_time;
		break;
	    case 78:			/* SMB.SMB_close */
		atom->ul = stats->SMBclose_count;
		break;
	    case 79:			/* SMB.SMB_close */
		atom->ul = stats->SMBclose_time;
		break;
	    case 80:			/* SMB.SMB_flush */
		atom->ul = stats->SMBflush_count;
		break;
	    case 81:			/* SMB.SMB_flush */
		atom->ul = stats->SMBflush_time;
		break;
	    case 82:			/* SMB.SMB_unlink */
		atom->ul = stats->SMBunlink_count;
		break;
	    case 83:			/* SMB.SMB_unlink */
		atom->ul = stats->SMBunlink_time;
		break;
	    case 84:			/* SMB.SMB_mv */
		atom->ul = stats->SMBmv_count;
		break;
	    case 85:			/* SMB.SMB_mv */
		atom->ul = stats->SMBmv_time;
		break;
	    case 86:			/* SMB.SMB_getatr */
		atom->ul = stats->SMBgetatr_count;
		break;
	    case 87:			/* SMB.SMB_getatr */
		atom->ul = stats->SMBgetatr_time;
		break;
	    case 88:			/* SMB.SMB_setatr */
		atom->ul = stats->SMBsetatr_count;
		break;
	    case 89:			/* SMB.SMB_setatr */
		atom->ul = stats->SMBsetatr_time;
		break;
	    case 90:			/* SMB.SMB_read */
		atom->ul = stats->SMBread_count;
		break;
	    case 91:			/* SMB.SMB_read */
		atom->ul = stats->SMBread_time;
		break;
	    case 92:			/* SMB.SMB_write */
		atom->ul = stats->SMBwrite_count;
		break;
	    case 93:			/* SMB.SMB_write */
		atom->ul = stats->SMBwrite_time;
		break;
	    case 94:			/* SMB.SMB_lock */
		atom->ul = stats->SMBlock_count;
		break;
	    case 95:			/* SMB.SMB_lock */
		atom->ul = stats->SMBlock_time;
		break;
	    case 96:			/* SMB.SMB_unlock */
		atom->ul = stats->SMBunlock_count;
		break;
	    case 97:			/* SMB.SMB_unlock */
		atom->ul = stats->SMBunlock_time;
		break;
	    case 98:			/* SMB.SMB_ctemp */
		atom->ul = stats->SMBctemp_count;
		break;
	    case 99:			/* SMB.SMB_ctemp */
		atom->ul = stats->SMBctemp_time;
		break;
	    case 100:			/* SMB.SMB_mknew */
		atom->ul = stats->SMBmknew_count;
		break;
	    case 101:			/* SMB.SMB_mknew */
		atom->ul = stats->SMBmknew_time;
		break;
	    case 102:			/* SMB.SMB_chkpth */
		atom->ul = stats->SMBchkpth_count;
		break;
	    case 103:			/* SMB.SMB_chkpth */
		atom->ul = stats->SMBchkpth_time;
		break;
	    case 104:			/* SMB.SMB_exit */
		atom->ul = stats->SMBexit_count;
		break;
	    case 105:			/* SMB.SMB_exit */
		atom->ul = stats->SMBexit_time;
		break;
	    case 106:			/* SMB.SMB_lseek */
		atom->ul = stats->SMBlseek_count;
		break;
	    case 107:			/* SMB.SMB_lseek */
		atom->ul = stats->SMBlseek_time;
		break;
	    case 108:			/* SMB.SMB_lockread */
		atom->ul = stats->SMBlockread_count;
		break;
	    case 109:			/* SMB.SMB_lockread */
		atom->ul = stats->SMBlockread_time;
		break;
	    case 110:			/* SMB.SMB_writeunlock */
		atom->ul = stats->SMBwriteunlock_count;
		break;
	    case 111:			/* SMB.SMB_writeunlock */
		atom->ul = stats->SMBwriteunlock_time;
		break;
	    case 112:			/* SMB.SMB_readbraw */
		atom->ul = stats->SMBreadbraw_count;
		break;
	    case 113:			/* SMB.SMB_readbraw */
		atom->ul = stats->SMBreadbraw_time;
		break;
	    case 114:			/* SMB.SMB_readBmpx */
		atom->ul = stats->SMBreadBmpx_count;
		break;
	    case 115:			/* SMB.SMB_readBmpx */
		atom->ul = stats->SMBreadBmpx_time;
		break;
	    case 116:			/* SMB.SMB_readBs */
		atom->ul = stats->SMBreadBs_count;
		break;
	    case 117:			/* SMB.SMB_readBs */
		atom->ul = stats->SMBreadBs_time;
		break;
	    case 118:			/* SMB.SMB_writebraw */
		atom->ul = stats->SMBwritebraw_count;
		break;
	    case 119:			/* SMB.SMB_writebraw */
		atom->ul = stats->SMBwritebraw_time;
		break;
	    case 120:			/* SMB.SMB_writeBmpx */
		atom->ul = stats->SMBwriteBmpx_count;
		break;
	    case 121:			/* SMB.SMB_writeBmpx */
		atom->ul = stats->SMBwriteBmpx_time;
		break;
	    case 122:			/* SMB.SMB_writeBs */
		atom->ul = stats->SMBwriteBs_count;
		break;
	    case 123:			/* SMB.SMB_writeBs */
		atom->ul = stats->SMBwriteBs_time;
		break;
	    case 124:			/* SMB.SMB_writec */
		atom->ul = stats->SMBwritec_count;
		break;
	    case 125:			/* SMB.SMB_writec */
		atom->ul = stats->SMBwritec_time;
		break;
	    case 126:			/* SMB.SMB_setattrE */
		atom->ul = stats->SMBsetattrE_count;
		break;
	    case 127:			/* SMB.SMB_setattrE */
		atom->ul = stats->SMBsetattrE_time;
		break;
	    case 128:			/* SMB.SMB_getattrE */
		atom->ul = stats->SMBgetattrE_count;
		break;
	    case 129:			/* SMB.SMB_getattrE */
		atom->ul = stats->SMBgetattrE_time;
		break;
	    case 130:			/* SMB.SMB_lockingX */
		atom->ul = stats->SMBlockingX_count;
		break;
	    case 131:			/* SMB.SMB_lockingX */
		atom->ul = stats->SMBlockingX_time;
		break;
	    case 132:			/* SMB.SMB_trans */
		atom->ul = stats->SMBtrans_count;
		break;
	    case 133:			/* SMB.SMB_trans */
		atom->ul = stats->SMBtrans_time;
		break;
	    case 134:			/* SMB.SMB_transs */
		atom->ul = stats->SMBtranss_count;
		break;
	    case 135:			/* SMB.SMB_transs */
		atom->ul = stats->SMBtranss_time;
		break;
	    case 136:			/* SMB.SMB_ioctl */
		atom->ul = stats->SMBioctl_count;
		break;
	    case 137:			/* SMB.SMB_ioctl */
		atom->ul = stats->SMBioctl_time;
		break;
	    case 138:			/* SMB.SMB_ioctls */
		atom->ul = stats->SMBioctls_count;
		break;
	    case 139:			/* SMB.SMB_ioctls */
		atom->ul = stats->SMBioctls_time;
		break;
	    case 140:			/* SMB.SMB_copy */
		atom->ul = stats->SMBcopy_count;
		break;
	    case 141:			/* SMB.SMB_copy */
		atom->ul = stats->SMBcopy_time;
		break;
	    case 142:			/* SMB.SMB_move */
		atom->ul = stats->SMBmove_count;
		break;
	    case 143:			/* SMB.SMB_move */
		atom->ul = stats->SMBmove_time;
		break;
	    case 144:			/* SMB.SMB_echo */
		atom->ul = stats->SMBecho_count;
		break;
	    case 145:			/* SMB.SMB_echo */
		atom->ul = stats->SMBecho_time;
		break;
	    case 146:			/* SMB.SMB_writeclose */
		atom->ul = stats->SMBwriteclose_count;
		break;
	    case 147:			/* SMB.SMB_writeclose */
		atom->ul = stats->SMBwriteclose_time;
		break;
	    case 148:			/* SMB.SMB_openX */
		atom->ul = stats->SMBopenX_count;
		break;
	    case 149:			/* SMB.SMB_openX */
		atom->ul = stats->SMBopenX_time;
		break;
	    case 150:			/* SMB.SMB_readX */
		atom->ul = stats->SMBreadX_count;
		break;
	    case 151:			/* SMB.SMB_readX */
		atom->ul = stats->SMBreadX_time;
		break;
	    case 152:			/* SMB.SMB_writeX */
		atom->ul = stats->SMBwriteX_count;
		break;
	    case 153:			/* SMB.SMB_writeX */
		atom->ul = stats->SMBwriteX_time;
		break;
	    case 154:			/* SMB.SMB_trans2 */
		atom->ul = stats->SMBtrans2_count;
		break;
	    case 155:			/* SMB.SMB_trans2 */
		atom->ul = stats->SMBtrans2_time;
		break;
	    case 156:			/* SMB.SMB_transs2 */
		atom->ul = stats->SMBtranss2_count;
		break;
	    case 157:			/* SMB.SMB_transs2 */
		atom->ul = stats->SMBtranss2_time;
		break;
	    case 158:			/* SMB.SMB_findclose */
		atom->ul = stats->SMBfindclose_count;
		break;
	    case 159:			/* SMB.SMB_findclose */
		atom->ul = stats->SMBfindclose_time;
		break;
	    case 160:			/* SMB.SMB_findnclose */
		atom->ul = stats->SMBfindnclose_count;
		break;
	    case 161:			/* SMB.SMB_findnclose */
		atom->ul = stats->SMBfindnclose_time;
		break;
	    case 162:			/* SMB.SMB_tcon */
		atom->ul = stats->SMBtcon_count;
		break;
	    case 163:			/* SMB.SMB_tcon */
		atom->ul = stats->SMBtcon_time;
		break;
	    case 164:			/* SMB.SMB_tdis */
		atom->ul = stats->SMBtdis_count;
		break;
	    case 165:			/* SMB.SMB_tdis */
		atom->ul = stats->SMBtdis_time;
		break;
	    case 166:			/* SMB.SMB_negprot */
		atom->ul = stats->SMBnegprot_count;
		break;
	    case 167:			/* SMB.SMB_negprot */
		atom->ul = stats->SMBnegprot_time;
		break;
	    case 168:			/* SMB.SMB_sesssetupX */
		atom->ul = stats->SMBsesssetupX_count;
		break;
	    case 169:			/* SMB.SMB_sesssetupX */
		atom->ul = stats->SMBsesssetupX_time;
		break;
	    case 170:			/* SMB.SMB_ulogoffX */
		atom->ul = stats->SMBulogoffX_count;
		break;
	    case 171:			/* SMB.SMB_ulogoffX */
		atom->ul = stats->SMBulogoffX_time;
		break;
	    case 172:			/* SMB.SMB_tconX */
		atom->ul = stats->SMBtconX_count;
		break;
	    case 173:			/* SMB.SMB_tconX */
		atom->ul = stats->SMBtconX_time;
		break;
	    case 174:			/* SMB.SMB_dskattr */
		atom->ul = stats->SMBdskattr_count;
		break;
	    case 175:			/* SMB.SMB_dskattr */
		atom->ul = stats->SMBdskattr_time;
		break;
	    case 176:			/* SMB.SMB_search */
		atom->ul = stats->SMBsearch_count;
		break;
	    case 177:			/* SMB.SMB_search */
		atom->ul = stats->SMBsearch_time;
		break;
	    case 178:			/* SMB.SMB_ffirst */
		atom->ul = stats->SMBffirst_count;
		break;
	    case 179:			/* SMB.SMB_ffirst */
		atom->ul = stats->SMBffirst_time;
		break;
	    case 180:			/* SMB.SMB_funique */
		atom->ul = stats->SMBfunique_count;
		break;
	    case 181:			/* SMB.SMB_funique */
		atom->ul = stats->SMBfunique_time;
		break;
	    case 182:			/* SMB.SMB_fclose */
		atom->ul = stats->SMBfclose_count;
		break;
	    case 183:			/* SMB.SMB_fclose */
		atom->ul = stats->SMBfclose_time;
		break;
	    case 184:			/* SMB.SMB_nttrans */
		atom->ul = stats->SMBnttrans_count;
		break;
	    case 185:			/* SMB.SMB_nttrans */
		atom->ul = stats->SMBnttrans_time;
		break;
	    case 186:			/* SMB.SMB_nttranss */
		atom->ul = stats->SMBnttranss_count;
		break;
	    case 187:			/* SMB.SMB_nttranss */
		atom->ul = stats->SMBnttranss_time;
		break;
	    case 188:			/* SMB.SMB_ntcreateX */
		atom->ul = stats->SMBntcreateX_count;
		break;
	    case 189:			/* SMB.SMB_ntcreateX */
		atom->ul = stats->SMBntcreateX_time;
		break;
	    case 190:			/* SMB.SMB_ntcancel */
		atom->ul = stats->SMBntcancel_count;
		break;
	    case 191:			/* SMB.SMB_ntcancel */
		atom->ul = stats->SMBntcancel_time;
		break;
	    case 192:			/* SMB.SMB_splopen */
		atom->ul = stats->SMBsplopen_count;
		break;
	    case 193:			/* SMB.SMB_splopen */
		atom->ul = stats->SMBsplopen_time;
		break;
	    case 194:			/* SMB.SMB_splwrite */
		atom->ul = stats->SMBsplwr_count;
		break;
	    case 195:			/* SMB.SMB_splwrite */
		atom->ul = stats->SMBsplwr_time;
		break;
	    case 196:			/* SMB.SMB_splclose */
		atom->ul = stats->SMBsplclose_count;
		break;
	    case 197:			/* SMB.SMB_splclose */
		atom->ul = stats->SMBsplclose_time;
		break;
	    case 198:			/* SMB.SMB_splretq */
		atom->ul = stats->SMBsplretq_count;
		break;
	    case 199:			/* SMB.SMB_splretq */
		atom->ul = stats->SMBsplretq_time;
		break;
	    case 200:			/* SMB.SMB_sends */
		atom->ul = stats->SMBsends_count;
		break;
	    case 201:			/* SMB.SMB_sends */
		atom->ul = stats->SMBsends_time;
		break;
	    case 202:			/* SMB.SMB_sendb */
		atom->ul = stats->SMBsendb_count;
		break;
	    case 203:			/* SMB.SMB_sendb */
		atom->ul = stats->SMBsendb_time;
		break;
	    case 204:			/* SMB.SMB_fwdname */
		atom->ul = stats->SMBfwdname_count;
		break;
	    case 205:			/* SMB.SMB_fwdname */
		atom->ul = stats->SMBfwdname_time;
		break;
	    case 206:			/* SMB.SMB_cancelf */
		atom->ul = stats->SMBcancelf_count;
		break;
	    case 207:			/* SMB.SMB_cancelf */
		atom->ul = stats->SMBcancelf_time;
		break;
	    case 208:			/* SMB.SMB_getmach */
		atom->ul = stats->SMBgetmac_count;
		break;
	    case 209:			/* SMB.SMB_getmach */
		atom->ul = stats->SMBgetmac_time;
		break;
	    case 210:			/* SMB.SMB_sendstrt */
		atom->ul = stats->SMBsendstrt_count;
		break;
	    case 211:			/* SMB.SMB_sendstrt */
		atom->ul = stats->SMBsendstrt_time;
		break;
	    case 212:			/* SMB.SMB_sendend */
		atom->ul = stats->SMBsendend_count;
		break;
	    case 213:			/* SMB.SMB_sendend */
		atom->ul = stats->SMBsendend_time;
		break;
	    case 214:			/* SMB.SMB_sendtxt */
		atom->ul = stats->SMBsendtxt_count;
		break;
	    case 215:			/* SMB.SMB_sendtxt */
		atom->ul = stats->SMBsendtxt_time;
		break;
	    case 216:			/* SMB.SMB_invalid */
		atom->ul = stats->SMBinvalid_count;
		break;
	    case 217:			/* SMB.SMB_invalid */
		atom->ul = stats->SMBinvalid_time;
		break;
	    case 218:			/* SMB.PATHWORK_setdir */
		atom->ul = stats->pathworks_setdir_count;
		break;
	    case 219:			/* SMB.PATHWORK_setdir */
		atom->ul = stats->pathworks_setdir_time;
		break;
	    case 220:			/* SMB.TRANS2_open */
		atom->ul = stats->Trans2_open_count;
		break;
	    case 221:			/* SMB.TRANS2_open */
		atom->ul = stats->Trans2_open_time;
		break;
	    case 222:			/* SMB.TRANS2_findfirst */
		atom->ul = stats->Trans2_findfirst_count;
		break;
	    case 223:			/* SMB.TRANS2_findfirst */
		atom->ul = stats->Trans2_findfirst_time;
		break;
	    case 224:			/* SMB.TRANS2_findnext */
		atom->ul = stats->Trans2_findnext_count;
		break;
	    case 225:			/* SMB.TRANS2_findnext */
		atom->ul = stats->Trans2_findnext_time;
		break;
	    case 226:			/* SMB.TRANS2_qfsinfo */
		atom->ul = stats->Trans2_qfsinfo_count;
		break;
	    case 227:			/* SMB.TRANS2_qfsinfo */
		atom->ul = stats->Trans2_qfsinfo_time;
		break;
	    case 228:			/* SMB.TRANS2_setfsinfo */
		atom->ul = stats->Trans2_setfsinfo_count;
		break;
	    case 229:			/* SMB.TRANS2_setfsinfo */
		atom->ul = stats->Trans2_setfsinfo_time;
		break;
	    case 230:			/* SMB.TRANS2_qpathinfo */
		atom->ul = stats->Trans2_qpathinfo_count;
		break;
	    case 231:			/* SMB.TRANS2_qpathinfo */
		atom->ul = stats->Trans2_qpathinfo_time;
		break;
	    case 232:			/* SMB.TRANS2_setpathinfo */
		atom->ul = stats->Trans2_setpathinfo_count;
		break;
	    case 233:			/* SMB.TRANS2_setpathinfo */
		atom->ul = stats->Trans2_setpathinfo_time;
		break;
	    case 234:			/* SMB.TRANS2_qfileinfo */
		atom->ul = stats->Trans2_qfileinfo_count;
		break;
	    case 235:			/* SMB.TRANS2_qfileinfo */
		atom->ul = stats->Trans2_qfileinfo_time;
		break;
	    case 236:			/* SMB.TRANS2_setfileinfo */
		atom->ul = stats->Trans2_setfileinfo_count;
		break;
	    case 237:			/* SMB.TRANS2_setfileinfo */
		atom->ul = stats->Trans2_setfileinfo_time;
		break;
	    case 238:			/* SMB.TRANS2_fsctl */
		atom->ul = stats->Trans2_fsctl_count;
		break;
	    case 239:			/* SMB.TRANS2_fsctl */
		atom->ul = stats->Trans2_fsctl_time;
		break;
	    case 240:			/* SMB.TRANS2_ioctl */
		atom->ul = stats->Trans2_ioctl_count;
		break;
	    case 241:			/* SMB.TRANS2_ioctl */
		atom->ul = stats->Trans2_ioctl_time;
		break;
	    case 242:			/* SMB.TRANS2_findnotifyfirst */
		atom->ul = stats->Trans2_findnotifyfirst_count;
		break;
	    case 243:			/* SMB.TRANS2_findnotifyfirst */
		atom->ul = stats->Trans2_findnotifyfirst_time;
		break;
	    case 244:			/* SMB.TRANS2_findnotifynext */
		atom->ul = stats->Trans2_findnotifynext_count;
		break;
	    case 245:			/* SMB.TRANS2_findnotifynext */
		atom->ul = stats->Trans2_findnotifynext_time;
		break;
	    case 246:			/* SMB.TRANS2_mkdir */
		atom->ul = stats->Trans2_mkdir_count;
		break;
	    case 247:			/* SMB.TRANS2_mkdir */
		atom->ul = stats->Trans2_mkdir_time;
		break;
	    case 248:			/* SMB.TRANS2_session_setup */
		atom->ul = stats->Trans2_session_setup_count;
		break;
	    case 249:			/* SMB.TRANS2_session_setup */
		atom->ul = stats->Trans2_session_setup_time;
		break;
	    case 250:			/* SMB.TRANS2_get_dfs_referral */
		atom->ul = stats->Trans2_get_dfs_referral_count;
		break;
	    case 251:			/* SMB.TRANS2_get_dfs_referral */
		atom->ul = stats->Trans2_get_dfs_referral_time;
		break;
	    case 252:			/* SMB.TRANS2_report_dfs_inconsistancy */
		atom->ul = stats->Trans2_report_dfs_inconsistancy_count;
		break;
	    case 253:			/* SMB.TRANS2_report_dfs_inconsistancy */
		atom->ul = stats->Trans2_report_dfs_inconsistancy_time;
		break;
	    case 254:			/* SMB.NTTRANS_create */
		atom->ul = stats->NT_transact_create_count;
		break;
	    case 255:			/* SMB.NTTRANS_create */
		atom->ul = stats->NT_transact_create_time;
		break;
	    case 256:			/* SMB.NTTRANS_ioctl */
		atom->ul = stats->NT_transact_ioctl_count;
		break;
	    case 257:			/* SMB.NTTRANS_ioctl */
		atom->ul = stats->NT_transact_ioctl_time;
		break;
	    case 258:			/* SMB.NTTRANS_set_security_desc */
		atom->ul = stats->NT_transact_set_security_desc_count;
		break;
	    case 259:			/* SMB.NTTRANS_set_security_desc */
		atom->ul = stats->NT_transact_set_security_desc_time;
		break;
	    case 260:			/* SMB.NTTRANS_notify_change */
		atom->ul = stats->NT_transact_notify_change_count;
		break;
	    case 261:			/* SMB.NTTRANS_notify_change */
		atom->ul = stats->NT_transact_notify_change_time;
		break;
	    case 262:			/* SMB.NTTRANS_rename */
		atom->ul = stats->NT_transact_rename_count;
		break;
	    case 263:			/* SMB.NTTRANS_rename */
		atom->ul = stats->NT_transact_rename_time;
		break;
	    case 264:			/* SMB.NTTRANS_query_security_desc */
		atom->ul = stats->NT_transact_query_security_desc_count;
		break;
	    case 265:			/* SMB.NTTRANS_query_security_desc */
		atom->ul = stats->NT_transact_query_security_desc_time;
		break;
	    default:
		return PM_ERR_PMID;
	}
    }
    else
	return PM_ERR_PMID;
    return 0;
}


void 
samba_init(pmdaInterface *dp)
{
    if (dp->status != 0)
	return;

    pmdaSetFetchCallBack(dp, samba_fetchCallBack);
    pmdaInit(dp, NULL, 0, metrictab, sizeof(metrictab)/sizeof(metrictab[0]));

    if ((shmid = shmget(PROF_SHMEM_KEY, 0, 0)) == -1) {
	fprintf(stderr, "shmid: %s\n", strerror(errno));
	fprintf(stderr, "samba not compiled with profile support or not running\n");
	exit(1);
    }
    shmheader = (struct profile_header *)shmat(shmid, NULL, SHM_RDONLY);
    if ((int)shmheader == -1) {
	fprintf(stderr, "shmat: %s\n", strerror(errno));
	exit(1);
    }

    /* validate the data */
    if (!shmheader)	/* not mapped yet */
	fprintf(stderr, "samba_init: shmem not mapped\n");
    else if (shmheader->prof_shm_magic != PROF_SHM_MAGIC)
	fprintf(stderr, "samba_init: bad magic\n");
    else if (shmheader->prof_shm_version != PROF_SHM_VERSION)
	fprintf(stderr, "samba_init: bad version %X\n",
			shmheader->prof_shm_version);
    else {
	stats = &shmheader->stats;
	return;		/* looks OK */
    }
    exit(1);
}


int
main(int argc, char **argv)
{
    int			err = 0;
    char		*p;
    pmdaInterface	dispatch;

    for (p = pmProgname = argv[0]; *p; p++)
	if (*p == '/') pmProgname = p+1;

    pmdaDaemon(&dispatch, PMDA_INTERFACE_2, pmProgname, SAMBA,
		"samba.log", "/var/pcp/pmdas/samba/help");

    if (pmdaGetOpt(argc, argv, "D:d:l:?", &dispatch, &err) != EOF) {
	fprintf(stderr, "Usage: %s [options]\n\n\
Options:\n\
  -d domain    use domain (numeric) for metrics domain of PMDA\n\
  -l logfile   write log into logfile rather than using default log name\n",
	pmProgname);
	exit(1);
    }

    pmdaOpenLog(&dispatch);
    samba_init(&dispatch);
    pmdaConnect(&dispatch);
    pmdaMain(&dispatch);

    exit(0);
    /*NOTREACHED*/
}
