#!/usr/bin/perl
# Update documents to the Samba DTD V1.0

undef $/;

while(<>) {
	s/<smbconfoption><name>(.*?)<\/name><value>(.*?)<\/value><\/smbconfoption>/<smbconfoption name=\"\1\">\2<\/smbconfoption>/g;
	s/<smbconfoption><name>(.*?)<\/name><\/smbconfoption>/<smbconfoption name=\"\1\"\/>/g;
	s/<smbconfsection>(.*?)<\/smbconfsection>/<smbconfsection name=\"\1\"\/>/g;
	s/xmlns:samba=\"http:\/\/samba.org\/common\"/xmlns:samba=\"http:\/\/www.samba.org\/samba\/DTD\/samba-doc\"/g;
	print $_;
}
