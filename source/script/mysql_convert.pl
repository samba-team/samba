#!/bin/env perl
#
#  MYSQL Convert - Creates and initialises mysql tables for use by samba
#
#  Copyright (C) Benjamin Kuit                     1999,
#  Copyright (C) Andrew Tridgell              1992-1999,
#  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
#  Converts smbpasswd files into MySQL tables.
#  Can understand Samba 1.19 and Samba 2.0 file formats.
#  Assumes table structure:
#           unix_name            char(20) not null,
#           unix_uid             int(10)  unsigned not null,
#           nt_name              char(20) not null,
#           user_rid             int(10)  unsigned not null,
#           smb_passwd           char(32),
#           smb_nt_passwd        char(32),
#           acct_ctrl            int(10) unsigned not null,
#           pass_last_set_time   int(10) unsigned not null,
#           unique (unix_name),
#           unique (unix_uid)
#  When given the --create option, mysql_convert will generate this
#  statement.
# 
#  To move from flat file smbpasswd directly into a mysql table:
#
#  mysql_convert.pl --db=samba --table=smbpasswd --user=samba --create --infile=smbpasswd
#
#  Assumes mysql server on localhost, use --host if otherwise.
#  To convert back to flat file:
#
#  mysql_convert.pl --db=samba --table=smbpasswd --user=samba --outfile=smbpasswd
#
#  If smbpasswd file already exists, use --file=append or --file=trash
#  to determine whether to append or over-right the file.
#
#  In converting from NT Server PDC to Samba PDC:
#  Run pwdump on NT Server to generate an smbpasswd file (Samba 1.19 format),
#  called say NTpasslist.
#  then:
#
#  mysql_convert.pl --db=samba --table=smbpasswd --user=samba --infile=NTpasslist --create --check
#
#  The --check option will change the unix_uid field to the real uid
#  value of respective users, also filter out users that dont exist on
#  the system.
#
#  If dont have mysql perl module:
#
#  mysql_convert.pl --table=smbpasswd --infile=NTpasslist --outfile=mysql.txt
#
#  Then use the mysql client:
#
#  mysql -u samba < mysql.txt
#

$ACB_DISABLED=0x0001;
$ACB_HOMDIRREQ=0x0002;
$ACB_PWNOTREQ=0x0004;
$ACB_TEMPDUP=0x0008;
$ACB_NORMAL=0x0010;
$ACB_MNS=0x0020;
$ACB_DOMTRUST=0x0040;
$ACB_WSTRUST=0x0080;
$ACB_SVRTRUST=0x0100;
$ACB_PWNOEXP=0x0200;
$ACB_AUTOLOCK=0x0400;

sub getoptionval {
	my ($option) = @_;

	my ($value) = ($option =~ /^[^=]+=\s*(\S.*\S)\s*$/ );

	return $value;
}

sub usage {

print <<EOUSAGE;
$0 [options]
options:
   --infile=<filename>          # smbpasswd style file to read entries from
   --outfile=<filename>         # file to dump results to, format depending
				#   on --infile:
				# With --infile: Dump mysql script queries
				# Without --infile: Dump smbpasswd format
				#                from reading mysql database
   --host=<hostname>            # Mysql Server name (default: localhost)
   --db=<database>		# Mysql Database name
   --user=<user>                # Mysql User
   --password[=<password>]      # Mysql password for --user
   --table=<table>              # Mysql table
   --create			# Generate 'create table' query
   --file=[trash|append]	# Action to take if --outfile file exists
   --check                      # Do not alter or skip bad uids

EOUSAGE
exit 0;
}

sub getpass {
	my($prompt)=@_;
	my($ret);

	print $prompt;
	system "stty -echo";
	chomp($ret=<STDIN>);
	system "stty echo";
	print "\n";
	$ret;
}

sub next_entry {
	my ($name,$uid,$lm,$nt,$f,$lct) = ();

	$name="";
	if ( not $infile ) {
		($name,$uid,$lm,$nt,$f,$lct) = $mysqlquery->fetchrow();
	}
	else {
		my $line=<INFILE>;

		return () if ( not $line );

		chomp($line);

		next if ( $line !~ /^[^: ]+:\d+:/ );

		($name,$uid,$lm,$nt,$f,$lct) = split(/:/,$line);

		if ( $lct =~ /^LCT-/ ) {
			# New Format smbpasswd file
			my $flags=0;

			$flags |= $ACB_PWNOTREQ if ( $f =~ /N/ );
			$flags |= $ACB_DISABLED if ( $f =~ /D/ );
			$flags |= $ACB_HOMDIRREQ if ( $f =~ /H/ );
			$flags |= $ACB_TEMPDUP if ( $f =~ /T/ );
			$flags |= $ACB_NORMAL if ( $f =~ /U/ );
			$flags |= $ACB_MNS if ( $f =~ /M/ );
			$flags |= $ACB_WSTRUST if ( $f =~ /W/ );
			$flags |= $ACB_SVRTRUST if ( $f =~ /S/ );
			$flags |= $ACB_AUTOLOCK if ( $f =~ /L/ );
			$flags |= $ACB_PWNOEXP if ( $f =~ /X/ );
			$flags |= $ACB_DOMTRUST if ( $f =~ /I/ );

			$f = $flags;

			$f = $ACB_NORMAL if ( not $f );

			$lct =~ s/LCT-//;
			$lct = (unpack("L",pack("H8",$lct)))[0];
		}
		else {
			# Old Format smbpasswd file
			$f = 0;
			$lct = time();
			if ( $lm =~ /^NO PASS/ ) {
				$f |= $ACB_PWNOTREQ;
				$lm = "";
				$nt = "";
			}
			elsif ( $lm =~ /^XX/ ) {
				$f |= $ACB_DISABLED;

				$lm = "";
				$nt = "";
			}

			if ( $name =~ /\$$/ ) {
				$f |= $ACB_WSTRUST;
			}

			$f = $ACB_NORMAL if ( not $f );
		}
	}
	return () if ( not $name );
	($name,$uid,$lm,$nt,$f,$lct);
}

sub do_query {
	my ( $query ) = @_;

	chomp($query);
	if ( $outfile ) {
		print OUTFILE "$query;\n";
	}
	else {
		if ( not $mysqldb->query($query) ) {
			print "$query: $Mysql::db_errstr\n";
		}
	}
}

sub do_file {
	my ($file,$name,$uid,$lm,$nt,$f,$lct)=@_;

	my $strings = "";

	$strings .= "N" if ( $f & $ACB_PWNOTREQ );
	$strings .= "D" if ( $f & $ACB_DISABLED );
	$strings .= "H" if ( $f & $ACB_HOMDIRREQ );
	$strings .= "T" if ( $f & $ACB_TEMPDUP );
	$strings .= "U" if ( $f & $ACB_NORMAL );
	$strings .= "M" if ( $f & $ACB_MNS );
	$strings .= "W" if ( $f & $ACB_WSTRUST );
	$strings .= "S" if ( $f & $ACB_SVRTRUST );
	$strings .= "L" if ( $f & $ACB_AUTOLOCK );
	$strings .= "X" if ( $f & $ACB_PWNOEXP );
	$strings .= "I" if ( $f & $ACB_DOMTRUST );

	$f = sprintf( "[%-11s]", $strings );

	$lct=uc("LCT-".(unpack("H8",pack("L","$lct")))[0]);

	$lm = "X"x32 if ( not $lm );
	$nt = "X"x32 if ( not $nt );

	print $file "$name:$uid:$lm:$nt:$f:$lct\n";
}

$dbhost = "localhost";

for $option ( @ARGV ) {
	if ( $option =~ /--outfile=/ ) {
		$outfile = getoptionval($option);
	}
	elsif ( $option =~ /--infile=/ ) {
		$infile = getoptionval($option);
	}
	elsif ( $option =~ /--db=/ ) {
		$dbname = getoptionval($option);
	}
	elsif ( $option =~ /--user=/ ) {
		$dbuser = getoptionval($option);
	}
	elsif ( $option =~ /--host=/ ) {
		$dbhost = getoptionval($option);
	}
	elsif ( $option =~ /--password/ ) {
		$dbpasswd = getoptionval($option);
		$need_password = "yes"
	}
	elsif ( $option =~ /--table=/ ) {
		$dbtable = getoptionval($option);
	}
	elsif ( $option =~ /--create/ ) {
		$create_table = "yes";
	}
	elsif ( $option =~ /--file=/ ) {
		$file_action = getoptionval($option);
	}
	elsif ( $option =~ /--check/ ) {
		$check = "yes";
	}
	else {
		print "Unknown option: $option\n";
		$unknown = "yes";
	}
}

&usage if ( $unknown eq "yes" );

if ( ( not $infile ) && ( not $outfile ) && ( $create_table ne "yes" ) ) {
	print "Need file to read from or write to\n";
	&usage;
}
elsif ( $infile && $outfile ) {
	if ( not $dbtable ) {
		print "Need --table to create queries\n";
		exit 1;
	}

	# Reading a smbpasswd file, dumping queries into an file which
	# can be used for a mysql script
	# --db* options are ignored.

	$ignored = "";
	$ignored .= " --db" if ( $dbname );
	$ignored .= " --user" if ( $dbuser );
	$ignored .= " --password" if ( $dbuser );

	if ( $ignored ) {
		print "Ignoring options: $ignored\n";
	}
}
elsif ( (not $dbname) || (not $dbtable) || (not $dbuser) ) {
	print "Missing database particulars:\n";
	print "  --db=??\n" if ( not $dbname );
	print "  --user=??\n" if ( not $dbuser );
	print "  --table=??\n" if ( not $dbtable );
	&usage;
}
else {
	use Mysql;

	if ( ($need_password eq "yes") && ( not $dbpasswd )) {
		$dbpasswd = getpass("Enter MySQL password for $dbuser: ");
	}
	$mysqldb = Connect Mysql($dbhost,$dbname,$dbuser,$dbpasswd);

	if ( not $mysqldb ) {
		print "Cannot connect to database: $Mysql::db_errstr\n";
		exit 1;
	}

	if ( $outfile ) {
		$mysqlquery = $mysqldb->query("select unix_name,unix_uid,smb_passwd,smb_nt_passwd,acct_ctrl,pass_last_set_time from $dbtable");

		if ( not $mysqlquery ) {
			print "MySQL Query failed: $Mysql::db_errstr\n";
			exit 1;
		}
	}
}

if ( $create_table eq "yes" ) {
	$create_table_query=<<EOSQL;
create table $dbtable (
unix_name            char(20) not null,
unix_uid             int(10)  unsigned not null,
nt_name              char(20) not null,
user_rid             int(10)  unsigned not null,
smb_passwd           char(32),
smb_nt_passwd        char(32),
acct_ctrl            int(10) unsigned not null,
pass_last_set_time   int(10) unsigned not null,
unique (unix_name),
unique (unix_uid)
)
EOSQL
	print "$create_table_query\n";
}
if ( $infile ) {
	if ( not open(INFILE,$infile) ) {
		print "$infile: $!\n";
		exit 1;
	}
}

if ( $outfile ) {
	if ( ! -f $outfile ) {
		$open_string=">$outfile";
	}
	elsif ( not $file_action ) {
		print "File $outfile exists:\n";
		print "Please use --file=[trash|append] option to determine destiny of file\n";
		exit 1;
	}
	elsif ( $file_action eq "append" ) {
		$open_string = ">>$outfile";
	}
	else {
		$open_string = ">$outfile";
	}

	if ( not open(OUTFILE,$open_string) ) {
		print "$outfile: $!\n";
		exit 1;
	}
}

do_query($create_table_query) if ( $create_table_query );

$linenum=1;
while (($name,$uid,$lm,$nt,$f,$lct)=next_entry()) {
	
	$| = 1;
	print "\r$linenum ";
	$linenum++;

	$nuid = "";

	$nuid = (getpwnam(lc($name)))[2];

	if ( $check ) {
		if ( not $nuid ) {
			# print "Removing $name: Does not exist\n";
			push(@removed,[$name,$uid,$lm,$nt,$f,$lct]);
			next;
		}
		else {
			# print "Changing uid of $name\n";
			$uid = $nuid;
		}
	}

	if ( $infile ) {
		if ( $lm ) {
			$lm = "'$lm'";
		}
		else {
			$lm = "NULL";
		}
		if ( $nt ) {
			$nt = "'$nt'";
		}
		else {
			$nt = "NULL";
		}
		$rid=(4*$uid)+1000;
		do_query("insert into $dbtable (unix_name,unix_uid,smb_passwd,smb_nt_passwd,acct_ctrl,pass_last_set_time,nt_name,user_rid) values ('$name',$uid,$lm,$nt,$f,$lct,'$name',$rid)");
	}
	else {
		do_file(OUTFILE,$name,$uid,$lm,$nt,$f,$lct);
	}
}

if ( @removed ) {
	print "\n\nIgnored entries because usernames do not exist\n";
	foreach $line ( @removed ) {
		do_file(STDOUT,@{ $line });
	}
}

close (OUTFILE) if ( $outfile );
close (INFILE) if ( $infile );
print "\n";
