#!/usr/bin/perl

################################################################################
#
# changepass.pl - A program to allow users to change their passwords
#                 via a web browser.
# Terry Davis
# 
# URLs
#	Net::LDAP - http://
#	usermod and this file - http://www.cloudamster.com/cloudmaster/projects
#
# Release History:
#	Version 0.1 - initial write
#
# ToDo:
#	... the ToDo section is on the ToDo list...
#
# Limitations:
#	The password cannot contain single and double quotes.....welcome to quoting hell....
#
# Notes:
#       This code is largely based on work done by Danny Sauer - http://www.cloudamster.com/cloudmaster/projects
#       His work is not licensed and is marked as 'freely distributable'.
#       Thank you to Danny for his hard work on the initial work.
#
################################################################################

use CGI qw(:standard);
use Net::LDAP;

# CONFIGURATION SECTION
$masterLDAP = "ldap.idealx.org";
$basedn = "dc=IDEALX,dc=org";
$masterPw = "";
$masterDN = "cn=manager,$basedn";
$ldap_path = "/usr/bin";
$ldap_opts = "-x";
$ldappasswd = "$ldap_path/ldappasswd $ldap_opts -h $masterLDAP -D '$masterDN' -w '$masterPw'";
$usersdn = "ou=Users,$basedn";
# END CONFIGURATION



# DONT EDIT ANYTHING BELOW THIS LINE
$logtag = "Login:";
$passtag = "Current password:";
$npasstag1 = "New password:";
$npasstag2 = "Retype new pasword:";
$error = "";
$color = "<FONT color='red'>";
$stopcolor = "</FONT>";

if(param()){
	nologin() unless ($username = param('login'));
	nopass() unless ($oldpass = param('oldpass'));
	nonewpass(1) unless ($newpass1 = param('newpass'));
	nonewpass(2) unless ($newpass2 = param('newpass2'));
	verifyuser($username) or die "bad user";
	verifypass($username, $oldpass) or die "bad pass";
	testnewpass($newpass1, $newpass2) or die "bad new pass";
	changepass($username, $newpass1) or die "couldn't change pass";
	printsuccess();
}else{
	printpage();
}
exit(0);

sub verifyuser{
	local $user = shift;
	$ldap = Net::LDAP->new($masterLDAP) or die "can't make new LDAP object: $@";
	$ldap->bind();
	if (0 < $ldap->search(base => $basedn, filter => "(uid=$user)")->count){
		return 1;
	}
	$logtag = $color . $logtag . $color;
	$error = "No such user";
	printpage();
	return 0;
}

sub verifypass{
	$uid = shift;
	$pass = shift;
	$ldap = Net::LDAP->new($masterLDAP) or die "can't make new LDAP object: $@";
	$binddn = "uid=$uid,ou=People,$basedn";
	return 1 if($ldap->bind( $binddn, password => $pass)->code == 0);
	if($ldap->bind()){
		$passtag = $color . $passtag . $color;
		$error = "Incorrect password";
		printpage();
		return 0;
	}else{
		print header, start_html(-title=>"LDAP dead");
		print h2("<CENTER>The LDAP server is temporarily unavailable."),
			p,"Please try again later</CENTER>";
		return 0;
	}die "Something (or someone) is defective, contact your friendly Systems Administrator";
}

sub testnewpass{
	$p1 = shift; $p2 = shift;
	if ($p1 ne $p2){
		$npasstag1 = $color . $npasstag1 . $color;
		$npasstag2 = $color . $npasstag2 . $color;
		$error = "Passwords don't match ($p1 vs $p2)";
		printpage();
		return 0;
	}
        if ($p1 =~ /"/ ){
                $npasstag1 = $color . $npasstag1 . $color;
                $npasstag2 = $color . $npasstag2 . $color;
                $error = "Passwords cannot contain double quotes. Sorry";
                printpage();
                return 0;
        }
        if ($p1 =~ /'/ ){
                $npasstag1 = $color . $npasstag1 . $color;
                $npasstag2 = $color . $npasstag2 . $color;
                $error = "Passwords cannot contain single quotes. Sorry";
                printpage();
                return 0;
        }
	return 1;
}

sub changepass{
	local $user = shift;
	local $newpass = shift;
	local $dn = "uid=$user,$usersdn";
	system "$ldappasswd $dn -s '$newpass' > /dev/null";
	`/usr/bin/sudo /usr/bin/smbpasswd $user "$newpass"`;	
	exit(1);
}

sub nologin{
	$logtag = $color . $logtag . $color;
	$error = "You need to enter a Login Name";
	printpage();
	exit(1);
}

sub nopass{
	$passtag = $color . $passtag . $color;
	$error = "Please enter your old password";
	printpage();
	exit(1);
}

sub nonewpass{
	$f=shift;
	$npasstag1 = $color . $npasstag1 . $color if($f==1);
	$npasstag2 = $color . $npasstag2 . $color if($f==2);
	$error = "You need to enter your new password";
	$error .= " twice" if($f==2);
	printpage();
	exit(1);
}

sub printpage{
	print header,
	      start_html(-title=> "Password Change Page",
	                 -author=> 'tdavis@birddog.com',
			 -BGCOLOR=> 'WHITE'),
	      h3('Password Change Page'),
	      startform(-method=>'POST'),
	      "<TABLE BORDER=0 WIDTH=50%>",
	      "<font size=2>",
	      "<TR><TD>",
	      $logtag,
	      "</TD><TD>",
	      textfield(-name=>'login', -default=>$login, 
	                -size=>15, -maxlength=>20),
	      "</TD><TR><TD>",
	      $passtag,
	      "</TD><TD>",
	      password_field(-name=>'oldpass', -size=>15, -maxlength=>25),
	      "</TD><TR><TD>",
	      $npasstag1,
	      "</TD><TD>",
	      password_field(-name=>'newpass', -size=>15, -maxlength=>25),
	      "</TD><TR><TD>",
	      $npasstag2,
	      "</TD><TD>",
	      password_field(-name=>'newpass2', -size=>15, -maxlength=>25),
	      "</TD><TR><TD></TD><TD>",
	      submit(-name=>"change"),reset(),
	      "</TD></TR></TABLE>",
	      "</font>",
	      endform(),
	      "<FONT color='red'>$error</FONT>",
	      end_html;
}

sub printsuccess(){
	print header,
	      start_html(-title=> "Success",
		             -BGCOLOR=> 'WHITE'),
		  h1("Password Succesfully Changed"),
		  "<br>",
		  end_html;
}
