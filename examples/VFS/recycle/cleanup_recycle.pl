# !/usr/bin/perl -w
#
# this script looks for all files with an access date older than
# $maxage days and deletes them.
# Empty directories will be deleted afterwards
#

$dirpath = "/data/.recycle";
$maxage = 2;

# delete all old files
@a=`find $dirpath -atime +$maxage`;
foreach (@a)
	{
	print "deleting file: $_";
	$r = `rm -f $_ 2> /dev/zero`;
	}

# delete all empty directories
@a=`find $dirpath -type d | sort -r`;
foreach (@a)
	{
	print "deleting directory: $_";
	$r = `rmdir $_ 2> /dev/zero`;
	}
