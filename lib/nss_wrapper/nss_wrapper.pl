#!/usr/bin/perl
#

use strict;

use Getopt::Long;
use Cwd qw(abs_path);

my $opt_help = 0;
my $opt_path = undef;
my $opt_action = undef;
my $opt_type = undef;
my $opt_name = undef;

my $passwdfn = undef;
my $groupfn = undef;
my $actionfn = undef;

sub passwd_add($$);
sub passwd_delete($$);
sub group_add($$);
sub group_delete($$);

my $result = GetOptions(
	'help|h|?'	=> \$opt_help,
	'path=s'	=> \$opt_path,
	'action=s'	=> \$opt_action,
	'type=s'	=> \$opt_type,
	'name=s'	=> \$opt_name
);

sub usage($;$)
{
	my ($ret, $msg) = @_;

	print $msg."\n\n" if defined($msg);

	print "usage:

	--help|-h|-?		Show this help.

	--path <path>		Path of the 'passwd' or 'group' file.

	--type <type>		Only 'passwd' is supported yet,
				but 'group' and maybe 'member' will be added
				in future.

	--action <action>	'add' or 'delete'.

	--name <name>		The name of the object.
";
	exit($ret);
}

usage(1) if (not $result);

usage(0) if ($opt_help);

if (not defined($opt_path)) {
	usage(1, "missing: --path <path>");
}
if ($opt_path eq "" or $opt_path eq "/") {
	usage(1, "invalid: --path <path>: '$opt_path'");
}
my $opt_fullpath = abs_path($opt_path);
if (not defined($opt_fullpath)) {
	usage(1, "invalid: --path <path>: '$opt_path'");
}


if (not defined($opt_action)) {
	usage(1, "missing: --action [add|delete]");
}
if ($opt_action eq "add") {
	$passwdfn = \&passwd_add;
	$groupfn = \&group_add;
} elsif ($opt_action eq "delete") {
	$passwdfn = \&passwd_delete;
	$groupfn = \&group_delete;
} else {
	usage(1, "invalid: --action [add|delete]: '$opt_action'");
}

if (not defined($opt_type)) {
	usage(1, "missing: --type [passwd|group]");
}
if ($opt_type eq "passwd") {
	$actionfn = $passwdfn;
} elsif ($opt_type eq "group") {
	$actionfn = $groupfn;
} else {
	usage(1, "invalid: --type [passwd|group]: '$opt_type'")
}

if (not defined($opt_name)) {
	usage(1, "missing: --name <name>");
}
if ($opt_name eq "") {
	usage(1, "invalid: --name <name>");
}

exit $actionfn->($opt_fullpath, $opt_name);

sub passwd_add_entry($$);

sub passwd_load($)
{
	my ($path) = @_;
	my @lines;
	my $passwd = undef;

	open(PWD, "<$path") or die("Unable to open '$path' for read");
	@lines = <PWD>;
	close(PWD);

	$passwd->{array} = ();
	$passwd->{name} = {};
	$passwd->{uid} = {};
	$passwd->{path} = $path;

	foreach my $line (@lines) {
		passwd_add_entry($passwd, $line);
	}

	return $passwd;
}

sub passwd_lookup_name($$)
{
	my ($passwd, $name) = @_;

	return undef unless defined($passwd->{name}{$name});

	return $passwd->{name}{$name};
}

sub passwd_lookup_uid($$)
{
	my ($passwd, $uid) = @_;

	return undef unless defined($passwd->{uid}{$uid});

	return $passwd->{uid}{$uid};
}

sub passwd_get_free_uid($)
{
	my ($passwd) = @_;
	my $uid = 1000;

	while (passwd_lookup_uid($passwd, $uid)) {
		$uid++;
	}

	return $uid;
}

sub passwd_add_entry($$)
{
	my ($passwd, $str) = @_;

	chomp $str;
	my @e = split(':', $str);

	push(@{$passwd->{array}}, \@e);
	$passwd->{name}{$e[0]} = \@e;
	$passwd->{uid}{$e[2]} = \@e;
}

sub passwd_remove_entry($$)
{
	my ($passwd, $eref) = @_;

	for (my $i = 0; defined($passwd->{array}[$i]); $i++) {
		if ($eref == $passwd->{array}[$i]) {
			$passwd->{array}[$i] = undef;
		}
	}

	delete $passwd->{name}{${$eref}[0]};
	delete $passwd->{uid}{${$eref}[2]};
}

sub passwd_save($)
{
	my ($passwd) = @_;
	my @lines = ();
	my $path = $passwd->{path};
	my $tmppath = $path.$$;

	foreach my $eref (@{$passwd->{array}}) {
		next unless defined($eref);

		my $line = join(':', @{$eref});
		push(@lines, $line);
	}

	open(PWD, ">$tmppath") or die("Unable to open '$tmppath' for write");
	print PWD join("\n", @lines)."\n";
	close(PWD);
	rename($tmppath, $path) or die("Unable to rename $tmppath => $path");
}

sub passwd_add($$)
{
	my ($path, $name) = @_;

	#print "passwd_add: '$name' in '$path'\n";

	my $passwd = passwd_load($path);

	my $e = passwd_lookup_name($passwd, $name);
	die("account[$name] already exists in '$path'") if defined($e);

	my $uid = passwd_get_free_uid($passwd);
	my $gid = 65534;# nogroup gid

	my $pwent = $name.":x:".$uid.":".$gid.":".$name." gecos:/nodir:/bin/false";

	passwd_add_entry($passwd, $pwent);

	passwd_save($passwd);

	return 0;
}

sub passwd_delete($$)
{
	my ($path, $name) = @_;

	#print "passwd_delete: '$name' in '$path'\n";

	my $passwd = passwd_load($path);

	my $e = passwd_lookup_name($passwd, $name);
	die("account[$name] does not exists in '$path'") unless defined($e);

	passwd_remove_entry($passwd, $e);

	passwd_save($passwd);

	return 0;
}

sub group_add($$)
{
	my ($path, $name) = @_;

	#print "group_add: '$name' in '$path'\n";

	die("group_add: not implemented yet!");

	return 0;
}

sub group_delete($$)
{
	my ($path, $name) = @_;

	#print "group_delete: '$name' in '$path'\n";

	die("group_delete: not implemented yet!");

	return 0;
}
