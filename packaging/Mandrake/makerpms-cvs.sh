#!/bin/bash
# makerpms-cvs.sh
# A quick script to build RPMs from cvs to test packaging
# Buchan Milne <bgmilne@cae.co.za>

[ $# -lt 1 ] &&  echo "Usage: $0 <Samba version>" && exit 1

VERSION=$1
RELEASE=0.`date +%Y%m%d`
shift

# Replace PRELEASE and PVERSION with release number in all files ending with
# .tmpl

FILES=$(find . -name "*.tmpl" -type f)

for i in $FILES;do 
	NEW=$(echo $i|sed -e 's/\.tmpl//g'); 
	cat $i |sed -e 's/PVERSION/'$VERSION'/g; s/PRELEASE/'$RELEASE'/g'> $NEW ;
done

#Change up three directories, rename directory to samba-$VERSION, change back
#then run makerpms.sh


CURRENT=$(pwd)
pushd $(dirname $(dirname $(dirname $CURRENT)))
SAMBA_DIR=$(basename $(dirname $(dirname $CURRENT)))
mv $SAMBA_DIR samba-$VERSION
pushd samba-$VERSION/source
./autogen.sh
popd
pushd samba-$VERSION/packaging/Mandrake
sh makerpms.sh $@
popd
mv samba-$VERSION $SAMBA_DIR
popd
