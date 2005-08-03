###########################################################
### SMB Build System					###
### - config.mk parsing functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

package config_mk;
use smb_build::input;

use strict;

my %attribute_types = (
	"NOPROTO" => "bool",
   	"REQUIRED_SUBSYSTEMS" => "list",
	"OUTPUT_TYPE" => "string",
	"INIT_OBJ_FILES" => "list",
	"ADD_OBJ_FILES" => "list",
	"OBJ_FILES" => "list",
	"SUBSYSTEM" => "string",
	"CFLAGS" => "list",
	"CPPFLAGS" => "list",
	"LDFLAGS" => "list",
	"INSTALLDIR" => "string",
	"LIBS" => "list",
	"INIT_FUNCTION" => "string",
	"MAJOR_VERSION" => "string",
	"MINOR_VERSION" => "string",
	"RELEASE_VERSION" => "string",
	"ENABLE" => "bool",
	"CMD" => "string",
	"MANPAGE" => "string"
);

###########################################################
# The parsing function which parses the file
#
# $result = _parse_config_mk($filename)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $result -	the resulting structure
#
# $result->{ERROR_CODE} -	the error_code, '0' means success
# $result->{ERROR_STR} -	the error string
#
# $result->{$key}{KEY} -	the key == the variable which was parsed
# $result->{$key}{VAL} -	the value of the variable
sub _parse_config_mk($)
{
	my $filename = shift;
	my $result;
	my $linenum = -1;
	my $waiting = 0;
	my $section = "GLOBAL";
	my $makefile = "";

	open(CONFIG_MK, "<$filename") or die("Can't open `$filename'\n");

	while (<CONFIG_MK>) {
		my $line = $_;

		$linenum++;

		# lines beginning with '#' are ignored
		next if ($line =~ /^\#.*$/);

		if (not $waiting and ($line =~ /^\[([a-zA-Z0-9_:]+)\][\t ]*$/)) 
		{
			$section = $1;
			next;
		}

		# empty line
		if ($line =~ /^[ \t]*$/) {
			$waiting = 0;
			$section = "GLOBAL";
			next;
		}

		# global stuff is considered part of the makefile
		if ($section eq "GLOBAL") {
			$makefile .= $line;
			next;
		}
		
		# Assignment
		if (not $waiting and 
			($line =~ /^([a-zA-Z0-9_]+)([\t ]*)=(.*)$/)) {
			my $key = $1;
			my $val = $3;

			# Continuing lines
			if ($val =~ /^(.*)\\$/) {
				$val = $1;
				($val.= " $1") while(($line = <CONFIG_MK>) =~ /^[\t ]*(.*)\\$/);
				$val .= $line;
			}

			$result->{$section}{$key}{KEY} = $key;
			$result->{$section}{$key}{VAL} = $val;
		
			next;
		}

		die("$filename:$linenum: Bad line while parsing $filename");
	}

	close(CONFIG_MK);

	return ($result,$makefile);
}

sub import_file($$)
{
	my ($input, $filename) = @_;

	my ($result, $makefile) = _parse_config_mk($filename);

	foreach my $section (keys %{$result}) {
		my ($type, $name) = split(/::/, $section, 2);
		
		$input->{$name}{NAME} = $name;
		$input->{$name}{TYPE} = $type;

		foreach my $key (values %{$result->{$section}}) {
			$key->{VAL} = smb_build::input::strtrim($key->{VAL});
			my $vartype = $attribute_types{$key->{KEY}};
			if (not defined($vartype)) {
				die("$filename:Unknown attribute $key->{KEY} with value $key->{VAL} in section $section");
			}
			if ($vartype eq "string") {
				$input->{$name}{$key->{KEY}} = $key->{VAL};
			} elsif ($vartype eq "list") {
				$input->{$name}{$key->{KEY}} = [smb_build::input::str2array($key->{VAL})];
			} elsif ($vartype eq "bool") {
				if (($key->{VAL} ne "YES") and ($key->{VAL} ne "NO")) {
					die("Invalid value for bool attribute $key->{KEY}: $key->{VAL} in section $section");
				}
				$input->{$name}{$key->{KEY}} = $key->{VAL};
			}
		}
	}
	
	return $makefile;
}

sub import_files($$)
{
	my ($input, $config_list) = @_;

	open(IN, $config_list) or die("Can't open $config_list: $!");
	my @mkfiles = grep{!/^#/} <IN>;
	close(IN);

	$| = 1;
	my $makefragment = "";

	foreach (@mkfiles) {
		s/\n//g;
		$makefragment.= import_file($input, $_);
	}
	return $makefragment;
}
1;
