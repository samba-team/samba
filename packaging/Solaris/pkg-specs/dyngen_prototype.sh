#!/bin/sh
# This script generates the dynamic part of the prototype file depending
# on the distribution tree
# The distr base directory is passed as $1
if [ $# != 1 ]; then
	echo "Dynamically generates prototype entries depending on the distribution tree.\nCalled from packaging.script.\nUsage: $0 base_directory"
	exit 1
fi

# First build the codepages and append codepage entries to prototype
echo "#\n# Codepages \n#"
echo d none samba/lib/codepages 0755 root other

CODEPAGELIST="437 737 850 852 861 932 866 949 950 936"
for p in $CODEPAGELIST; do
	$1/source/bin/make_smbcodepage c $p $1/source/codepages/codepage_def.$p $1/source/codepages/codepage.$p
	echo f none samba/lib/codepages/codepage.$p=source/codepages/codepage.$p 0644 root other
done

# Add the binaries, docs and SWAT files

echo "#\n# Binaries \n#"
cd $1/source/bin
for binfile in *
do
	if [ -f $binfile ]; then
		echo f none samba/bin/$binfile=source/bin/$binfile 0755 root other
	fi
done
echo "#\n# HTML documentation \n#"
echo d none samba/docs/htmldocs 0755 root other
cd $1/docs/htmldocs
for htmldoc in *
do
	if [ -f $htmldoc ]; then
		echo f none samba/docs/htmldocs/$htmldoc=docs/htmldocs/$htmldoc 0644 root other
	fi
done
echo "#\n# Text Docs \n#"
echo d none samba/docs/textdocs 0755 root other
cd $1/docs/textdocs
for textdoc in *
do 
	if [ -f $textdoc ]; then
		echo f none samba/docs/textdocs/$textdoc=docs/textdocs/$textdoc 0644 root other
	fi
done
echo "#\n# SWAT \n#"
cd $1
list=`find swat -type d`
for i in $list
do
	echo "d none samba/$i 0755 root other"
done
list=`find swat -type f`
for i in $list
do
	echo "f none samba/$i=$i 0644 root other"
done
