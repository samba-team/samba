#!/usr/local/bin/perl
# 
#@(#) smb-wall.pl Description:
#@(#) A perl script which allows you to announce whatever you choose to
#@(#) every PC client currently connected to a Samba Server...
#@(#) ...using "smbclient -M" message to winpopup service.
#@(#) Default usage is to message every connected PC.
#@(#) Alternate usage is to message every pc on the argument list.
#@(#)	Hacked up by Keith Farrar <farrar@parc.xerox.com>
#
#=============================================================================
$smbstatus = "/usr/local/bin/smbstatus";
$smbclient = "/usr/local/bin/smbclient";

print STDOUT "\nEnter message for Samba clients of this host\n";
print STDOUT "(terminated with single '.' or end of file):\n";

while ( <STDIN> ) {
	/^\.$/ && last;
	push(@message,  $_);
}

if ( $ARGV[0] ne "" ) {
	$debug && print STDOUT "Was given args: \n\t @ARGV\n";
	foreach $client ( @ARGV ) {
		$pcclient{$client} = $client;
	}
} else {
	open( PCLIST, "$smbstatus | /bin/awk '/^[a-z]/ {print $5}' | /bin/sort | /bin/uniq|");
	while ( <PCLIST> ) {
		/^[a-z]+[a-z0-9A-Z-_]+.+/ || next;
		($share, $user, $group, $pid, $client, @junk) = split;
		$pcclient{$client} = $client;
	}
	close(PCLIST);
}

foreach $pc ( keys(%pcclient) ) {
	print STDOUT "Sending message ";
	$debug && print STDOUT " <@message> \n";
	print STDOUT "To <$pc>\n";
	open(SENDMSG,"|$smbclient -M $pc") || next;
	print SENDMSG @message;
	close(SENDMSG);
}
