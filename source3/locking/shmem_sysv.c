/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Shared memory functions - SYSV IPC implementation
   Copyright (C) Erik Devriendt 1996-1997
   
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


#ifdef USE_SYSV_IPC

extern int DEBUGLEVEL;

#define SHMEM_KEY ((key_t)0x280267)
#define SEMAPHORE_KEY (SHMEM_KEY+2)

#define SHM_MAGIC 0x53484100
#define SHM_VERSION 2

#ifdef SHM_R
#define IPC_PERMS ((SHM_R | SHM_W) | (SHM_R>>3) | (SHM_R>>6))
#else
#define IPC_PERMS 0644
#endif

static int shm_id;
static int sem_id;
static int shm_size;
static int hash_size;
static int global_lock_count;

struct ShmHeader {
   int shm_magic;
   int shm_version;
   int total_size;	/* in bytes */
   BOOL consistent;
   int first_free_off;
   int userdef_off;    /* a userdefined offset. can be used to store
			  root of tree or list */
   struct {		/* a cell is a range of bytes of sizeof(struct
			   ShmBlockDesc) size */
	   int cells_free;
	   int cells_used;
	   int cells_system; /* number of cells used as allocated
				block descriptors */
   } statistics;
};

#define SHM_NOT_FREE_OFF (-1)
struct ShmBlockDesc
{
   int next;	/* offset of next block in the free list or
		   SHM_NOT_FREE_OFF when block in use */
   int          size;   /* user size in BlockDescSize units */
};

#define	EOList_Addr	(struct ShmBlockDesc *)( 0 )
#define EOList_Off      (NULL_OFFSET)

#define	CellSize	sizeof(struct ShmBlockDesc)

/* HeaderSize aligned on 8 byte boundary */
#define	AlignedHeaderSize  	((sizeof(struct ShmHeader)+7) & ~7)

static struct ShmHeader *shm_header_p = (struct ShmHeader *)0;

static BOOL shm_initialize_called = False;

static int read_only;

static BOOL sem_lock(int i)
{
	struct sembuf sb;
	if (read_only) return True;
	
	sb.sem_num = i;
	sb.sem_op = -1;
	sb.sem_flg = SEM_UNDO;

	if (semop(sem_id, &sb, 1) != 0) {
		DEBUG(0,("ERROR: IPC lock failed on semaphore %d\n", i));
		return False;
	}

	return True;
}

static BOOL sem_unlock(int i)
{
	struct sembuf sb;
	if (read_only) return True;

	sb.sem_num = i;
	sb.sem_op = 1;
	sb.sem_flg = SEM_UNDO;

	if (semop(sem_id, &sb, 1) != 0) {
		DEBUG(0,("ERROR: IPC unlock failed on semaphore %d\n", i));
		return False;
	}

	return True;
}

static BOOL global_lock(void)
{
	global_lock_count++;
	if (global_lock_count == 1)
		return sem_lock(0);
	return True;
}

static BOOL global_unlock(void)
{
	global_lock_count--;
	if (global_lock_count == 0)
		return sem_unlock(0);
	return True;
}

static void *shm_offset2addr(int offset)
{
   if (offset == NULL_OFFSET )
      return (void *)(0);
   
   if (!shm_header_p)
      return (void *)(0);
   
   return (void *)((char *)shm_header_p + offset );
}

static int shm_addr2offset(void *addr)
{
   if (!addr)
      return NULL_OFFSET;
   
   if (!shm_header_p)
      return NULL_OFFSET;
   
   return (int)((char *)addr - (char *)shm_header_p);
}


static int shm_alloc(int size)
{
	unsigned num_cells ;
	struct ShmBlockDesc *scanner_p;
	struct ShmBlockDesc *prev_p;
	struct ShmBlockDesc *new_p;
	int result_offset;
   
   
	if (!shm_header_p) {
		/* not mapped yet */
		DEBUG(0,("ERROR shm_alloc : shmem not mapped\n"));
		return NULL_OFFSET;
	}
	
	global_lock();
	
	if (!shm_header_p->consistent) {
		DEBUG(0,("ERROR shm_alloc : shmem not consistent\n"));
		global_unlock();
		return NULL_OFFSET;
	}
	
	/* calculate	the number of cells */
	num_cells = (size + CellSize -1) / CellSize;
	
	/* set start	of scan */
	prev_p = (struct ShmBlockDesc *)shm_offset2addr(shm_header_p->first_free_off);
	scanner_p =	prev_p ;
	
	/* scan the free list to find a matching free space */
	while ((scanner_p != EOList_Addr) && (scanner_p->size < num_cells)) {
		prev_p = scanner_p;
		scanner_p = (struct ShmBlockDesc *)shm_offset2addr(scanner_p->next);
	}
   
	/* at this point scanner point to a block header or to the end of
	   the list */
	if (scanner_p == EOList_Addr) {
		DEBUG(0,("ERROR shm_alloc : alloc of %d bytes failed, no free space found\n",size));
		global_unlock();
		return (NULL_OFFSET);
	}
   
	/* going to modify shared mem */
	shm_header_p->consistent = False;
	
	/* if we found a good one : scanner == the good one */
	if (scanner_p->size <= num_cells + 2) {
		/* there is no use in making a new one, it will be too small anyway 
		 *	 we will link out scanner
		 */
		if ( prev_p == scanner_p ) {
			shm_header_p->first_free_off = scanner_p->next ;
		} else {
			prev_p->next = scanner_p->next ;
		}
		shm_header_p->statistics.cells_free -= scanner_p->size;
		shm_header_p->statistics.cells_used += scanner_p->size;
	} else {
		/* Make a new one */
		new_p = scanner_p + 1 + num_cells;
		new_p->size = scanner_p->size - num_cells - 1;
		new_p->next = scanner_p->next;
		scanner_p->size = num_cells;
		scanner_p->next = shm_addr2offset(new_p);
		
		if (prev_p != scanner_p) {
			prev_p->next	   = shm_addr2offset(new_p)  ;
		} else {
			shm_header_p->first_free_off = shm_addr2offset(new_p);
		}
		shm_header_p->statistics.cells_free -= num_cells+1;
		shm_header_p->statistics.cells_used += num_cells;
		shm_header_p->statistics.cells_system += 1;
	}

	result_offset = shm_addr2offset( &(scanner_p[1]) );
	scanner_p->next =	SHM_NOT_FREE_OFF ;

	/* end modification of shared mem */
	shm_header_p->consistent = True;
	
	DEBUG(6,("shm_alloc : request for %d bytes, allocated %d bytes at offset %d\n",size,scanner_p->size*CellSize,result_offset ));

	global_unlock();
	return result_offset;
}   



/* 
 * Function to create the hash table for the share mode entries. Called
 * when smb shared memory is global locked.
 */
static BOOL shm_create_hash_table( unsigned int size )
{
	size *= sizeof(int);

	global_lock();
	shm_header_p->userdef_off = shm_alloc( size );

	if(shm_header_p->userdef_off == NULL_OFFSET) {
		DEBUG(0,("shm_create_hash_table: Failed to create hash table of size %d\n",size));
		global_unlock();
		return False;
	}

	/* Clear hash buckets. */
	memset( shm_offset2addr(shm_header_p->userdef_off), '\0', size);
	global_unlock();
	return True;
}

static BOOL shm_validate_header(int size)
{
	if( !shm_header_p ) {
		/* not mapped yet */
		DEBUG(0,("ERROR shm_validate_header : shmem not mapped\n"));
		return False;
	}
   
	if(shm_header_p->shm_magic != SHM_MAGIC) {
		DEBUG(0,("ERROR shm_validate_header : bad magic\n"));
		return False;
	}

	if(shm_header_p->shm_version != SHM_VERSION) {
		DEBUG(0,("ERROR shm_validate_header : bad version %X\n",shm_header_p->shm_version));
		return False;
	}
   
	if(shm_header_p->total_size != size) {
		DEBUG(0,("ERROR shm_validate_header : shmem size mismatch (old = %d, new = %d)\n",shm_header_p->total_size,size));
		return False;
	}

	if(!shm_header_p->consistent) {
		DEBUG(0,("ERROR shm_validate_header : shmem not consistent\n"));
		return False;
	}
	return True;
}

static BOOL shm_initialize(int size)
{
	struct ShmBlockDesc * first_free_block_p;
	
	DEBUG(5,("shm_initialize : initializing shmem file of size %d\n",size));
   
	if( !shm_header_p ) {
		/* not mapped yet */
		DEBUG(0,("ERROR shm_initialize : shmem not mapped\n"));
		return False;
	}
   
	shm_header_p->shm_magic = SHM_MAGIC;
	shm_header_p->shm_version = SHM_VERSION;
	shm_header_p->total_size = size;
	shm_header_p->first_free_off = AlignedHeaderSize;
	shm_header_p->userdef_off = NULL_OFFSET;
	
	first_free_block_p = (struct ShmBlockDesc *)shm_offset2addr(shm_header_p->first_free_off);
	first_free_block_p->next = EOList_Off;
	first_free_block_p->size = ( size - AlignedHeaderSize - CellSize ) / CellSize ;
   
	shm_header_p->statistics.cells_free = first_free_block_p->size;
	shm_header_p->statistics.cells_used = 0;
	shm_header_p->statistics.cells_system = 1;
   
	shm_header_p->consistent = True;
   
	shm_initialize_called = True;

	return True;
}
   
static void shm_solve_neighbors(struct ShmBlockDesc *head_p )
{
	struct ShmBlockDesc *next_p;
   
	/* Check if head_p and head_p->next are neighbors and if so
           join them */
	if ( head_p == EOList_Addr ) return ;
	if ( head_p->next == EOList_Off ) return ;
   
	next_p = (struct ShmBlockDesc *)shm_offset2addr(head_p->next);
	if ( ( head_p + head_p->size + 1 ) == next_p) {
		head_p->size += next_p->size +1 ;	/* adapt size */
		head_p->next = next_p->next	  ; /* link out */
      
		shm_header_p->statistics.cells_free += 1;
		shm_header_p->statistics.cells_system -= 1;
	}
}




static BOOL shm_close( void )
{
	return True;
}


static BOOL shm_free(int offset)
{
	struct ShmBlockDesc *header_p; /* pointer to header of
					       block to free */
	struct ShmBlockDesc *scanner_p; /* used to scan the list */
	struct ShmBlockDesc *prev_p; /* holds previous in the
					   list */
   
	if (!shm_header_p) {
		/* not mapped yet */
		DEBUG(0,("ERROR shm_free : shmem not mapped\n"));
		return False;
	}
	
	global_lock();
	
	if (!shm_header_p->consistent) {
		DEBUG(0,("ERROR shm_free : shmem not consistent\n"));
		global_unlock();
		return False;
	}
	
	/* make pointer to header of block */
	header_p = ((struct ShmBlockDesc *)shm_offset2addr(offset) - 1); 
	
	if (header_p->next != SHM_NOT_FREE_OFF) {
		DEBUG(0,("ERROR shm_free : bad offset (%d)\n",offset));
		global_unlock();
		return False;
	}
	
	/* find a place in the free_list to put the header in */
	
	/* set scanner and previous pointer to start of list */
	prev_p = (struct ShmBlockDesc *)shm_offset2addr(shm_header_p->first_free_off);
	scanner_p = prev_p ;
	
	while ((scanner_p != EOList_Addr) && 
	       (scanner_p < header_p)) { 
		/* while we didn't scan past its position */
		prev_p = scanner_p ;
		scanner_p = (struct ShmBlockDesc *)shm_offset2addr(scanner_p->next);
	}
	
	shm_header_p->consistent = False;
	
	DEBUG(6,("shm_free : freeing %d bytes at offset %d\n",
		 header_p->size*CellSize,offset));
	
	if (scanner_p == prev_p) {
		shm_header_p->statistics.cells_free += header_p->size;
		shm_header_p->statistics.cells_used -= header_p->size;
		
		/* we must free it at the beginning of the list */
		shm_header_p->first_free_off = shm_addr2offset(header_p);						 /*	set	the free_list_pointer to this block_header */
		
		/* scanner is the one that was first in the list */
		header_p->next = shm_addr2offset(scanner_p);
		shm_solve_neighbors( header_p ); /* if neighbors then link them */
		
		shm_header_p->consistent = True;
	} else {
		shm_header_p->statistics.cells_free += header_p->size;
		shm_header_p->statistics.cells_used -= header_p->size;
		
		prev_p->next = shm_addr2offset(header_p);
		header_p->next = shm_addr2offset(scanner_p);
		shm_solve_neighbors(header_p) ;
		shm_solve_neighbors(prev_p) ;
	   
		shm_header_p->consistent = True;
	}

	global_unlock();
	return True;
}


static int shm_get_userdef_off(void)
{
   if (!shm_header_p)
      return NULL_OFFSET;
   else
      return shm_header_p->userdef_off;
}

/*******************************************************************
  Lock a particular hash bucket entry.
  ******************************************************************/
static BOOL shm_lock_hash_entry(unsigned int entry)
{
	DEBUG(0,("hash lock %d\n", entry));
	return sem_lock(entry+1);
}

/*******************************************************************
  Unlock a particular hash bucket entry.
  ******************************************************************/
static BOOL shm_unlock_hash_entry(unsigned int entry)
{
	DEBUG(0,("hash unlock %d\n", entry));
	return sem_unlock(entry+1);
}


/*******************************************************************
  Gather statistics on shared memory usage.
  ******************************************************************/
static BOOL shm_get_usage(int *bytes_free,
			  int *bytes_used,
			  int *bytes_overhead)
{
	if(!shm_header_p) {
		/* not mapped yet */
		DEBUG(0,("ERROR shm_free : shmem not mapped\n"));
		return False;
	}

	*bytes_free = shm_header_p->statistics.cells_free * CellSize;
	*bytes_used = shm_header_p->statistics.cells_used * CellSize;
	*bytes_overhead = shm_header_p->statistics.cells_system * CellSize + AlignedHeaderSize;
	
	return True;
}

static struct shmem_ops shmops = {
	shm_close,
	shm_alloc,
	shm_free,
	shm_get_userdef_off,
	shm_offset2addr,
	shm_addr2offset,
	shm_lock_hash_entry,
	shm_unlock_hash_entry,
	shm_get_usage,
};

/*******************************************************************
  open the shared memory
  ******************************************************************/
struct shmem_ops *sysv_shm_open(int size, int ronly)
{
	BOOL created_new = False;
	BOOL other_processes;
	struct shmid_ds shm_ds;
	struct semid_ds sem_ds;
	union semun su;
	int i;

	read_only = ronly;

	shm_size = size;

	DEBUG(4,("Trying sysv shmem open of size %d\n", size));

	/* first the semaphore */
	sem_id = semget(SEMAPHORE_KEY, 0, 0);
	if (sem_id == -1) {
		if (read_only) return NULL;

		sem_id = semget(SEMAPHORE_KEY, lp_shmem_hash_size()+1, 
				IPC_CREAT | IPC_EXCL | IPC_PERMS);

		if (sem_id == -1) {
			DEBUG(0,("Can't create or use semaphore %s\n", 
				 strerror(errno)));
		}   

		if (sem_id != -1) {
			su.val = 1;
			for (i=0;i<lp_shmem_hash_size()+1;i++) {
				if (semctl(sem_id, i, SETVAL, su) != 0) {
					DEBUG(1,("Failed to init semaphore %d\n", i));
				}
			}
		}
	}
	if (shm_id == -1) {
		sem_id = semget(SEMAPHORE_KEY, 0, 0);
	}
	if (sem_id == -1) {
		DEBUG(0,("Can't create or use semaphore %s\n", 
			 strerror(errno)));
		return NULL;
	}   

	su.buf = &sem_ds;
	if (semctl(sem_id, 0, IPC_STAT, su) != 0) {
		DEBUG(0,("ERROR shm_open : can't IPC_STAT\n"));
	}
	hash_size = sem_ds.sem_nsems;
	if (hash_size != lp_shmem_hash_size()+1) {
		DEBUG(0,("WARNING: nsems=%d\n", hash_size));
	}
	
	if (!global_lock())
		return NULL;
	
	/* try to use an existing key */
	shm_id = shmget(SHMEM_KEY, shm_size, 0);
	
	/* if that failed then create one */
	if (shm_id == -1) {
		if (read_only) return NULL;
		shm_id = shmget(SHMEM_KEY, shm_size, IPC_CREAT | IPC_EXCL);
		created_new = (shm_id != -1);
	}
	
	if (shm_id == -1) {
		DEBUG(0,("Can't create or use IPC area\n"));
		global_unlock();
		return NULL;
	}   
	
	
	shm_header_p = (struct ShmHeader *)shmat(shm_id, 0, 
						 read_only?SHM_RDONLY:0);
	if ((int)shm_header_p == -1) {
		DEBUG(0,("Can't attach to IPC area\n"));
		global_unlock();
		return NULL;
	}

	/* to find out if some other process is already mapping the file,
	   we use a registration file containing the processids of the file
	   mapping processes */
	if (shmctl(shm_id, IPC_STAT, &shm_ds) != 0) {
		DEBUG(0,("ERROR shm_open : can't IPC_STAT\n"));
	}

	/* set the permissions */
	if (!read_only) {
		shm_ds.shm_perm.mode = IPC_PERMS;
		shmctl(shm_id, IPC_SET, &shm_ds);
	}

	other_processes = (shm_ds.shm_nattch > 1);

	if (!read_only && !other_processes) {
		memset((char *)shm_header_p, 0, shm_size);
		shm_initialize(shm_size);
		shm_create_hash_table(lp_shmem_hash_size());
		DEBUG(1,("Initialised IPC area of size %d\n", shm_size));
	} else if (!shm_validate_header(shm_size)) {
		/* existing file is corrupt, samba admin should remove
                   it by hand */
		DEBUG(0,("ERROR shm_open : corrupt IPC area - remove it!\n"));
		global_unlock();
		return NULL;
	}
   
	global_unlock();
	return &shmops;
}



#else 
 int ipc_dummy_procedure(void)
{return 0;}
#endif 
