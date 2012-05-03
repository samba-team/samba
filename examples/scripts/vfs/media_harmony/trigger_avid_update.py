#!/usr/bin/python
import os, socket, sys, stat

######################################################################
##
##  trigger_avid_update.py for media_harmony VFS module.
##
##  Copyright (C) Andrew Klaassen	2012.
##
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, see <http://www.gnu.org/licenses/>.
##
######################################################################


#
# Change avid_shares and ip_prefix as appropriate for your network.
#

avid_shares = (
	'\\\\mediaharmony01\\project1\\',
	'\\\\mediaharmony01\\project2\\',
	'\\\\mediaharmony01\\project3\\',
)

ip_prefix = '192.168.1.'


if __name__ == "__main__":
	my_ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if ip[:len(ip_prefix)] == ip_prefix]
	if not my_ips:
		print 'No IP address found.  Aborting.'
		dummy = raw_input("\nPress Enter to finish: ")
		sys.exit()

	my_ip = my_ips[0]
	my_name = os.environ.get('USERNAME')

	for avid_share in avid_shares:
		media_dirs = []
		omfi_dir = os.path.join(avid_share, 'OMFI MediaFiles')
		if os.path.exists(omfi_dir):
			media_dirs.append(omfi_dir)
		mxf_root = os.path.join(avid_share, 'Avid MediaFiles', 'MXF')
		if os.path.exists(mxf_root):
			mxf_children = os.listdir(mxf_root)
			for child in mxf_children:
				fullpath = os.path.join(mxf_root, child)
				if os.path.isdir(fullpath):
					media_dirs.append(fullpath)

		for media_dir in media_dirs:

			print '\nChecking %s...' % media_dir

			fakepath = '%s_%s_%s' % (media_dir, my_ip, my_name)
			print '...fakepath: %s' % fakepath

			db = os.path.join(media_dir, 'msmMMOB.mdb')
			print '...Checking for %s' % db
			if os.path.exists(db):
				print '......found %s.' % db
				db_mtime = os.stat(db)[stat.ST_MTIME]
				newer_file = False
				for child in os.listdir(media_dir):
					if child == 'msmMMOB.mdb' or child == 'msmFMID.pmr':
						continue
					child_mtime = os.stat(os.path.join(media_dir, child))[stat.ST_MTIME]
					if child_mtime > db_mtime:
						print '......found newer file %s' % child
						newer_file = True
						break
			else:
				print '......no %s.' % db
				newer_file = True

			if newer_file:
				utime = None # Sets to current time.
				print '...Setting fake mtime to NOW.  Will trigger re-index.'
			else:
				mtime = os.stat(media_dir)[stat.ST_MTIME]
				utime = (mtime, mtime)
				print '...Setting fake mtime to media_dir mtime.  No re-index.'

			if not os.path.exists(fakepath):
				tmp_fakepath = '%s.tmp' % fakepath
				open(tmp_fakepath, 'a').close()
				os.utime(tmp_fakepath, utime)
				os.rename(tmp_fakepath, fakepath)
			else:
				os.utime(fakepath, utime)

	dummy = raw_input("\nPress Enter to finish: ")
