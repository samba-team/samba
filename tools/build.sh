#!/bin/sh
#
# Build many combinations of kth-krb/heimdal/openssl
#
# $Id$

heimdal_versions="0.5.2 0.6pre3"
krb4_versions="1.2.2"
openssl_versions="0.9.6i 0.9.7a 0.9.7b"
dont_build="openssl-0.9.7.*heimdal-0.5.* openssl-0.9.7.*krb4-.*"

# Allow override
for a in $HOME . /etc ; do 
    test -f $a/.heimdal-build && . $a/.heimdal-build
done

targetdir=${targetdir:-/scratch/heimdal-test}
logfile="${targetdir}/buildlog"

distdirs="${distdirs} /afs/e.kth.se/home/staff/lha/Public/openssl"
distdirs="${distdirs} /afs/pdc.kth.se/public/ftp/pub/heimdal/src"
distdirs="${distdirs} /afs/pdc.kth.se/public/ftp/pub/heimdal/src/snapshots"
distdirs="${distdirs} /afs/pdc.kth.se/public/ftp/pub/krb/src"
opt_n=#:


mkdir -p ${targetdir}/src
cd ${targetdir}/src || exit 1
rm -rf heimdal* openssl* krb4*

logprint () {
    d=`date '+%Y-%m-%d %H:%M:%S'`
    echo "${d}: $*"
    echo "${d}: --- $*" >> ${logfile}
}

logerror () {
    echo "$*"
    exit 1
}

do_build_p () {
    for a in ${dont_build} ; do
	expr "$1" : "${a}" > /dev/null 2>&1 && return 1
    done
    return 0
}

unpack_tar () {
    for a in ${distdirs} ; do
	if [ -f $a/$1 ] ; then
	    ${opt_n} gzip -dc ${a}/$1 | ${opt_n} tar xf -
	    return 0
	fi
    done
    logerror "did not find $1"
}

build () {
    real_ver=$1
    prog=$2
    ver=$3
    confprog=$4
    pv=${prog}-${ver}
    mkdir tmp || logerror "failed to build tmpdir"
    cd tmp || logerror "failed to change dir to tmpdir"
    do_build_p ${real_ver} || \
	{ cd .. ; rmdir tmp ; logprint "not building $1" && return 1 ; }
    cd .. || logerror "failed to change back from tmpdir"
    rmdir tmp || logerror "failed to remove tmpdir"
    logprint "preparing for ${pv}"
    ${opt_n} rm -rf ${targetdir}/${prog}-${ver}
    ${opt_n} rm -rf ${prog}-${ver}
    unpack_tar ${pv}.tar.gz
    ${opt_n} cd ${pv} || logerror directory ${pv} not there
    logprint "configure ${prog} ${ver} (${confprog})"
    ${opt_n} ./${confprog} \
	--prefix=${targetdir}/${prog}-${ver} >> ${logfile} 2>&1 || \
	    logerror failed to configure ${pv}
    logprint "make ${prog} ${ver}"
    ${opt_n} make >> ${logfile} 2>&1 || logerror failed to make ${pv}
    ${opt_n} make install >> ${logfile} 2>&1 || \
	logerror failed to install ${pv}
    ${opt_n} cd ..
    return 0
}

logprint clearing logfile
> ${logfile}

logprint === building openssl versions
for vo in ${openssl_versions} ; do
    build openssl-${vo} openssl $vo config
done

wssl="--with-openssl=${targetdir}/openssl"
wossl="--without-openssl"
wk4c="--with-krb4-config=${targetdir}/krb4"
bk4c="/bin/krb4-config"
wok4="--without-krb4"

logprint === building heimdal w/o krb4 versions
for vo in ${openssl_versions} ; do
    for vh in ${heimdal_versions} ; do
	build "openssl-${vo}-heimdal-${vh}" \
	    heimdal ${vh} \
	    "configure ${wok4} ${wssl}-${vo}" || continue
	( ${targetdir}/heimdal-${vh}/bin/krb5-config --libs | \
	    grep lcrypto) >/dev/null 2>&1 || \
	    logerror "failed to build with openssl"
    done
done

logprint === building krb4
for vo in ${openssl_versions} ; do
    for vk in ${krb4_versions} ; do
	build "openssl-${vo}-krb4-${vk}" \
	    krb4 ${vk} \
	    "configure ${wssl}-${vo}" || continue
	( ${targetdir}/krb4-${vk}/bin/krb4-config --libs | \
	    grep lcrypto) >/dev/null 2>&1 || \
	    logerror "failed to build with openssl"
    done
done

logprint === building heimdal with krb4 versions
for vo in ${openssl_versions} ; do
    for vk in ${krb4_versions} ; do
	for vh in ${heimdal_versions} ; do
	    build "openssl-${vo}-krb4-${vk}-heimdal-${vh}" \
		heimdal ${vh} \
		"configure ${wk4c}-${vk}${bk4c} ${wssl}-${vo}" || continue
	    ( ${targetdir}/heimdal-${vh}/bin/krb5-config --libs | \
		grep lcrypto) >/dev/null 2>&1 || \
		logerror "failed to build with openssl"
	    ( ${targetdir}/heimdal-${vh}/bin/krb5-config --libs | \
		grep krb4) >/dev/null 2>&1 || \
		logerror "failed to build with krb4"
	done
    done
done

logprint === building heimdal without krb4 and openssl versions
for vh in ${heimdal_versions} ; do
    build "des-heimdal-${vh}" \
	heimdal ${vh} \
	"configure ${wok4} ${wossl}" || continue
    ( ${targetdir}/heimdal-${vh}/bin/krb5-config --libs | \
	grep lcrypto) >/dev/null 2>&1 && \
	logerror "failed to build WITHOUT openssl"
    ( ${targetdir}/heimdal-${vh}/bin/krb5-config --libs | \
	grep krb4 ) >/dev/null 2>&1 && \
	logerror "failed to build WITHOUT krb4"
done

logprint all done
