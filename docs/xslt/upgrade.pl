#!/usr/bin/perl
# Update documents to the Samba DTD V1.0

undef $/;

while(<>) {
	s/<smbconfoption><name>(.*?)<\/name><value>(.*?)<\/value><\/smbconfoption>/<smbconfoption name=\"\1\">\2<\/smbconfoption>/g;
	s/<smbconfoption><name>(.*?)<\/name><\/smbconfoption>/<smbconfoption name=\"\1\"\/>/g;
	print $_;
}
