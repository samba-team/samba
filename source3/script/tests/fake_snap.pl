#!/usr/bin/perl -w

use strict;

use File::Path qw(rmtree);
use POSIX ();

sub _create_snapshot
{
	my ($base_path) = @_;
	my $time_str = POSIX::strftime("%Y.%m.%d-%H.%M.%S" , localtime());
	my $snap_path = $base_path . "/.snapshots/\@GMT-" . $time_str;
	my $ret;

	POSIX::mkdir($base_path . "/.snapshots", 0777);

	# add trailing slash to src path to ensure that only contents is copied
	$ret = system("rsync", "-a", "--exclude=.snapshots/", "${base_path}/",
		      $snap_path);
	if ($ret != 0) {
		print STDERR "rsync failed with $ret\n";
	} else {
		print "$snap_path\n";
	}

	return $ret;
}

sub _delete_snapshot
{
	my ($base_path, $snap_path) = @_;

	# we're doing a recursive delete, so do some sanity checks
	if ((index($snap_path, $base_path) != 0) || (index($snap_path, ".snapshots") == -1)) {
		print STDERR "invalid snap_path: $snap_path\n";
		return -1;
	}

	rmtree($snap_path, {error => \my $err});
	if (@$err) {
		for my $diag (@$err) {
			my ($file, $message) = %$diag;
			if ($file eq '') {
				print STDERR "rmtree error: $message\n";
			} else {
				print STDERR "rmtree error $file: $message\n";
			}
		}
		return -1;
	}

	return 0;
}

my $ret;
my $num_args = $#ARGV + 1;
my $cmd = shift;

if (($num_args == 2) && ($cmd eq "--check")) {
	$ret = 0;
} elsif (($num_args == 2) && ($cmd eq "--create")) {
	$ret = _create_snapshot($ARGV[0]);
} elsif (($num_args == 3) && ($cmd eq "--delete")) {
	$ret = _delete_snapshot($ARGV[0], $ARGV[1]);
} else {
	print STDERR "invalid script argument\n";
	$ret = -1;
}

exit $ret;
