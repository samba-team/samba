/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000
      
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

/****************************************************************************
 Read the machine SID from a file.
****************************************************************************/

static BOOL read_sid_from_file(int fd, char *sid_file)
{
  fstring fline;

  memset(fline, '\0', sizeof(fline));

  if(read(fd, fline, sizeof(fline) -1 ) < 0) {
    DEBUG(0,("unable to read file %s. Error was %s\n",
           sid_file, strerror(errno) ));
    return False;
  }

  /*
   * Convert to the machine SID.
   */

  fline[sizeof(fline)-1] = '\0';
  if(!string_to_sid( &global_sam_sid, fline)) {
    DEBUG(0,("unable to generate machine SID.\n"));
    return False;
  }

  return True;
}

/****************************************************************************
 Generate the global machine sid. Look for the MACHINE.SID file first, if
 not found then look in smb.conf and use it to create the MACHINE.SID file.
 Note this function will be replaced soon. JRA.
****************************************************************************/

BOOL pdb_generate_sam_sid(void)
{
	int fd;
	pstring sid_file;
	fstring sid_string;
	SMB_STRUCT_STAT st;
	BOOL overwrite_bad_sid = False;

	generate_wellknown_sids();

	get_private_directory(sid_file);

	if (!directory_exist(sid_file, NULL)) {
		if (mkdir(sid_file, 0700) != 0) {
			DEBUG(0,("can't create private directory %s : %s\n",
				 sid_file, strerror(errno)));
			return False;
		}
	}

	pstrcat(sid_file, "/MACHINE.SID");
    
	if((fd = sys_open(sid_file, O_RDWR | O_CREAT, 0644)) == -1) {
		DEBUG(0,("unable to open or create file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		return False;
	} 
  
	/*
	 * Check if the file contains data.
	 */
	
	if(sys_fstat( fd, &st) < 0) {
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if(st.st_size > 0) {
		/*
		 * We have a valid SID - read it.
		 */
		if(!read_sid_from_file( fd, sid_file)) {
			DEBUG(0,("unable to read file %s. Error was %s\n",
				 sid_file, strerror(errno) ));
			close(fd);
			return False;
		}

		/*
		 * JRA. Reversed the sense of this test now that I have
		 * actually done this test *personally*. One more reason
		 * to never trust third party information you have not
		 * independently verified.... sigh. JRA.
		 */

		if(global_sam_sid.num_auths > 0 && global_sam_sid.sub_auths[0] == 0x21) {
			/*
			 * Fix and re-write...
			 */
			overwrite_bad_sid = True;
			global_sam_sid.sub_auths[0] = 21;
			DEBUG(5,("pdb_generate_sam_sid: Old (incorrect) sid id_auth of hex 21 \
detected - re-writing to be decimal 21 instead.\n" ));
			sid_to_string(sid_string, &global_sam_sid);
			if(sys_lseek(fd, (SMB_OFF_T)0, SEEK_SET) != 0) {
				DEBUG(0,("unable to seek file file %s. Error was %s\n",
					 sid_file, strerror(errno) ));
				close(fd);
				return False;
			}
		} else {
			close(fd);
			return True;
		}
	} else {
		/*
		 * The file contains no data - we need to generate our
		 * own sid.
		 * Generate the new sid data & turn it into a string.
		 */
		int i;
		uchar raw_sid_data[12];
		DOM_SID mysid;

		memset((char *)&mysid, '\0', sizeof(DOM_SID));
		mysid.sid_rev_num = 1;
		mysid.id_auth[5] = 5;
		mysid.num_auths = 0;
		mysid.sub_auths[mysid.num_auths++] = 21;

		generate_random_buffer( raw_sid_data, 12, True);
		for( i = 0; i < 3; i++)
			mysid.sub_auths[mysid.num_auths++] = IVAL(raw_sid_data, i*4);

		sid_to_string(sid_string, &mysid);
	} 
	
	fstrcat(sid_string, "\n");
	
	/*
	 * Ensure our new SID is valid.
	 */
	
	if(!string_to_sid( &global_sam_sid, sid_string)) {
		DEBUG(0,("unable to generate machine SID.\n"));
		return False;
	} 
  
	/*
	 * Do an exclusive blocking lock on the file.
	 */
	
	if(!do_file_lock( fd, 60, F_WRLCK)) {
		DEBUG(0,("unable to lock file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
 
	if(!overwrite_bad_sid) {
		/*
		 * At this point we have a blocking lock on the SID
		 * file - check if in the meantime someone else wrote
		 * SID data into the file. If so - they were here first,
		 * use their data.
		 */
	
		if(sys_fstat( fd, &st) < 0) {
			DEBUG(0,("unable to stat file %s. Error was %s\n",
				 sid_file, strerror(errno) ));
			close(fd);
			return False;
		} 
  
		if(st.st_size > 0) {
			/*
			 * Unlock as soon as possible to reduce
			 * contention on the exclusive lock.
			 */ 
			do_file_lock( fd, 60, F_UNLCK);
		
			/*
			 * We have a valid SID - read it.
			 */
		
			if(!read_sid_from_file( fd, sid_file)) {
				DEBUG(0,("unable to read file %s. Error was %s\n",
					 sid_file, strerror(errno) ));
				close(fd);
				return False;
			}
			close(fd);
			return True;
		} 
	}
	
	/*
	 * The file is still empty and we have an exlusive lock on it,
	 * or we're fixing an earlier mistake.
	 * Write out out SID data into the file.
	 */

	/*
	 * Use chmod here as some (strange) UNIX's don't
	 * have fchmod. JRA.
	 */	

	if(chmod(sid_file, 0644) < 0) {
		DEBUG(0,("unable to set correct permissions on file %s. \
Error was %s\n", sid_file, strerror(errno) ));
		do_file_lock( fd, 60, F_UNLCK);
		close(fd);
		return False;
	} 
	
	if(write( fd, sid_string, strlen(sid_string)) != strlen(sid_string)) {
		DEBUG(0,("unable to write file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		do_file_lock( fd, 60, F_UNLCK);
		close(fd);
		return False;
	} 
	
	/*
	 * Unlock & exit.
	 */
	
	do_file_lock( fd, 60, F_UNLCK);
	close(fd);
	return True;
}   


