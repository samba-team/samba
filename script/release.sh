#!/bin/bash
# make a release of Samba or a library

LC_ALL=C
export LC_ALL
LANG=C
export LANG
LANGUAGE=C
export LANGUAGE

set -u
set -e
umask 0022

CONF_REPO_URL="ssh://git.samba.org/data/git/samba.git"
CONF_UPLOAD_URL="samba-bugs@download-master.samba.org:/home/data/ftp/pub"
CONF_DOWNLOAD_URL="https://download.samba.org/pub"
CONF_HISTORY_URL="https://www.samba.org"

test -d ".git" || {
	echo "Run this script from the top-level directory in the"
	echo "repository"
	exit 1
}

usage() {
	echo "Usage: release.sh <PRODUCT> <COMMAND>"
	echo ""
	echo "PRODUCT: ldb, talloc, tevent, tdb, samba-rc, samba-stable"
	echo "COMMAND: fullrelease, create, push, upload, announce"
	echo ""
	return 0
}

check_args() {
	local cmd="$1"
	local got_args="$2"
	local take_args="$3"

	test x"${got_args}" = x"${take_args}" || {
		usage
		echo "cmd[${cmd}] takes ${take_args} instead of ${got_args}"
		return 1
	}

	return 0
}

min_args() {
	local cmd="$1"
	local got_args="$2"
	local min_args="$3"

	test "${got_args}" -ge "${min_args}" || {
		usage
		echo "cmd[${cmd}] takes at least ${min_args} instead of ${got_args}"
		return 1
	}

	return 0
}

min_args "$0" "$#" "2"

product="$1"
globalcmd="$2"
shift 2
oldtagname=""
tagname=""
patchfile=""
cmds=""
next_cmd=""

require_tagname() {
	min_args "${FUNCNAME}" "$#" "1" || return 1
	local cmd="$1"

	test -n "${tagname}" || {
		echo "cmd[${cmd}] requires '\${tagname}' variable to be set"
		return 1
	}

	local name=$(echo "${tagname}" | cut -d '-' -f1)
	test x"${name}" = x"${productbase}" || {
		echo "Invalid tagname[${tgzname}]"
		return 1
	}

	return 0
}

cmd_allowed() {
	min_args "${FUNCNAME}" "$#" "2" || return 1
	local cmd="$1"
	shift 1

	echo "$@" | grep -q "\<${cmd}\>" || {
		return 1
	}

	return 0
}

verify_samba_rc() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -f VERSION || {
		echo "VERSION doesn't exist"
		return 1
	}

	grep -q 'SAMBA_VERSION_IS_GIT_SNAPSHOT=no' VERSION || {
		echo "SAMBA_VERSION_IS_GIT_SNAPSHOT is not 'no'"
		return 1
	}

	grep -q '^SAMBA_VERSION_RC_RELEASE=' VERSION || {
		echo "SAMBA_VERSION_RC_RELEASE= missing"
		return 1
	}

	grep -q '^SAMBA_VERSION_RC_RELEASE=$' VERSION && {
		echo "SAMBA_VERSION_RC_RELEASE= missing the rc version"
		return 1
	}

	return 0
}

verify_samba_stable() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -f VERSION || {
		echo "VERSION doesn't exist"
		return 1
	}

	grep -q 'SAMBA_VERSION_IS_GIT_SNAPSHOT=no' VERSION || {
		echo "SAMBA_VERSION_IS_GIT_SNAPSHOT is not 'no'"
		return 1
	}

	local VARS=""
	VARS="${VARS} SAMBA_VERSION_REVISION"
	VARS="${VARS} SAMBA_VERSION_TP_RELEASE"
	VARS="${VARS} SAMBA_VERSION_ALPHA_RELEASE"
	VARS="${VARS} SAMBA_VERSION_BETA_RELEASE"
	VARS="${VARS} SAMBA_VERSION_PRE_RELEASE"
	VARS="${VARS} SAMBA_VERSION_RC_RELEASE"
	VARS="${VARS} SAMBA_VERSION_RELEASE_NICKNAME"
	VARS="${VARS} SAMBA_VERSION_VENDOR_SUFFIX"
	VARS="${VARS} SAMBA_VERSION_VENDOR_PATCH"
	for var in ${VARS}; do
		grep -q "^${var}" VERSION && {
			grep -q "^${var}=$" VERSION || {
				echo "${var} found in stable version"
				return 1
			}
		}
	done

	local SAMBA_VERSION_MAJOR=$(grep '^SAMBA_VERSION_MAJOR=' VERSION | cut -d '=' -f2 | xargs)
	local SAMBA_VERSION_MINOR=$(grep '^SAMBA_VERSION_MINOR=' VERSION | cut -d '=' -f2 | xargs)
	local SAMBA_VERSION_RELEASE=$(grep '^SAMBA_VERSION_RELEASE=' VERSION | cut -d '=' -f2 | xargs)

	test ${SAMBA_VERSION_RELEASE} -gt 0 || {
		return 0
	}

	local old_release=$(expr ${SAMBA_VERSION_RELEASE} - 1)
	oldtagname="${productbase}-${SAMBA_VERSION_MAJOR}.${SAMBA_VERSION_MINOR}.${old_release}"

	local verify_out="${TMPDIR}/verify-${oldtagname}.out"

	echo "Verifying oldtagname: ${oldtagname}"

	git tag -v "${oldtagname}" >${verify_out} 2>&1 || {
		echo "failed to verify old tag[${oldtagname}]"
		return 1
	}

	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "oldtagname[${oldtagname}] was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	echo "Verifying ${oldtagname}.tar.gz and ${oldtagname}.tar.asc"

	test -f "${oldtagname}.tar.gz" || {
		echo "${oldtagname}.tar.gz does not exist"
		return 1
	}

	test -f "${oldtagname}.tar.asc" || {
		echo "${oldtagname}.tar.asc does not exist"
		return 1
	}

	zcat "${oldtagname}.tar.gz" | gpg --verify "${oldtagname}.tar.asc" - 2>${verify_out} || {
		echo "Failed to verify ${oldtagname}.tar.asc"
		return 1
	}

	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "${oldtagname}.tar.asc was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	return 0
}

verify_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${verify_fn}" || {
		echo "verify_fn variable empty"
		return 1
	}

	echo "Running ${verify_fn}"
	${verify_fn}
}

create_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	echo "Releasing product ${product}"

	echo "Building release tarball"
	local tgzname=$(make dist 2>&1 | grep ^Created | cut -d' ' -f2)
	test -f "${tgzname}" || {
		echo "Failed to create tarball"
		return 1
	}
	CLEANUP_FILES="${CLEANUP_FILES} ${tgzname}"

	local name=$(echo "${tgzname}" | cut -d '-' -f1)
	test x"${name}" = x"${productbase}" || {
		echo "Invalid tgzname[${tgzname}]"
		return 1
	}

	local tarname=$(basename ${tgzname} .gz)
	echo "Tarball: ${tarname}"
	gunzip -f ${tgzname} || {
		echo "Failed to decompress tarball ${tarname}"
		return 1
	}
	test -f "${tarname}" || {
		echo "Failed to decompress tarball ${tarname}"
		return 1
	}
	CLEANUP_FILES="${CLEANUP_FILES} ${tarname}"

	# tagname is global
	tagname=$(basename ${tarname} .tar)
	echo "Tagging as ${tagname}"
	git tag -u ${GPG_KEYID} -s "${tagname}" -m "${productbase}: tag release ${tagname}" || {
		return 1
	}
	CLEANUP_TAGS="${CLEANUP_TAGS} ${tagname}"

	echo "Signing ${tarname} => ${tarname}.asc"
	rm -f "${tarname}.asc"
	gpg -u "${GPG_USER}" --detach-sign --armor ${tarname} || {
		return 1
	}
	test -f "${tarname}.asc" || {
		echo "Failed to create signature ${tarname}.asc"
		return 1
	}
	CLEANUP_FILES="${CLEANUP_FILES} ${tarname}.asc"
	echo "Compressing ${tarname} => ${tgzname}"
	gzip -f -9 ${tarname}
	test -f "${tgzname}" || {
		echo "Failed to compress ${tgzname}"
		return 1
	}

	return 0
}

patch_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	test -n "${oldtagname}" || {
		return 0
	}

	local oldversion=$(echo "${oldtagname}" | sed -e "s!^${productbase}-!!")
	local version=$(echo "${tagname}" | sed -e "s!^${productbase}-!!")

	local oldpwd=$(pwd)

	local patchfile="patch-${oldversion}-${version}.diffs"
	echo "Generating ${patchfile}"
	(
		pushd "${TMPDIR}"
		tar xfz "${oldpwd}/${oldtagname}.tar.gz"
		tar xfz "${oldpwd}/${tagname}.tar.gz"
		diff -Npur "${oldtagname}/" "${tagname}/" > "${patchfile}"
		popd
	)
	CLEANUP_FILES="${CLEANUP_FILES} ${patchfile}"
	mv "${TMPDIR}/${patchfile}" "${patchfile}" || {
		echo "failed cmd[mv ${TMPDIR}/${patchfile} ${patchfile}]"
		return 1
	}

	echo "Signing ${patchfile} => ${patchfile}.asc"
	rm -f "${patchfile}.asc"
	CLEANUP_FILES="${CLEANUP_FILES} ${patchfile}.asc"
	gpg -u "${GPG_USER}" --detach-sign --armor ${patchfile} || {
		return 1
	}
	test -f "${patchfile}.asc" || {
		echo "Failed to create signature ${patchfile}.asc"
		return 1
	}
	echo "Compressing ${patchfile} => ${patchfile}.gz"
	CLEANUP_FILES="${CLEANUP_FILES} ${patchfile}.gz"
	gzip -f -9 ${patchfile}
	test -f "${patchfile}.gz" || {
		echo "Failed to compress ${patchfile}.gz"
		return 1
	}

	return 0
}

whatsnew_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	echo "extract ${tagname}.WHATSNEW.txt"
	tar xf ${tagname}.tar.gz --to-stdout ${tagname}/WHATSNEW.txt > ${tagname}.WHATSNEW.txt
	CLEANUP_FILES="${CLEANUP_FILES} ${tagname}.WHATSNEW.txt"

	return 0
}

check_nopatch() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	git tag -v "${tagname}" || {
		echo "failed to verify tag[${tagname}]"
		return 1
	}

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	test -f "${tagname}.tar.asc" || {
		echo "${tagname}.tar.asc does not exist"
		return 1
	}

	ls -la ${tagname}.*

	return 0
}

check_withpatch() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	git tag -v "${tagname}" || {
		echo "failed to verify tag[${tagname}]"
		return 1
	}

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	test -f "${tagname}.tar.asc" || {
		echo "${tagname}.tar.asc does not exist"
		return 1
	}

	ls -la ${tagname}.*

	test -n "${patchfile}" || {
		return 0
	}

	test -f "${patchfile}.gz" || {
		echo "${patchfile}.gz does not exist"
		return 1
	}

	test -f "${patchfile}.asc" || {
		echo "${patchfile}.asc does not exist"
		return 1
	}

	return 0
}

check_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${check_fn}" || {
		echo "check_fn variable empty"
		return 1
	}

	echo "Running ${check_fn}"
	${check_fn}
}

push_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	echo "Push git tag ${tagname} to '${repo_url}'"
	git push "${repo_url}" "refs/tags/${tagname}:refs/tags/${tagname}" || {
		return 1
	}

	return 0
}

upload_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	echo "Upload ${tagname}.* to '${upload_url}'"
	rsync -Pav ${tagname}.* "${upload_url}/" || {
		return 1
	}
	rsync ${upload_url}/${tagname}.*

	return 0
}

announce_samba_rc() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	test -f "${tagname}.WHATSNEW.txt" || {
		echo "${tagname}.WHATSNEW.txt does not exist"
		return 1
	}

	local t=""
	local utcdate=$(date --utc +"%d %B %Y")
	local utctime=$(date --utc +"%Y%m%d-%H%M%S")
	local version=$(echo "${tagname}" | sed -e 's!^samba-!!')
	local href="#${version}"
	local series=$(echo "${version}" | cut -d '.' -f1-2)
	local rc=$(echo "${version}" | sed -e 's!.*rc\([0-9][0-9]*\)!\1!')
	local rcname="${rc}th"
	case "${rc}" in
	1)
		rcname="first"
		;;
	2)
		rcname="second"
		;;
	3)
		rcname="third"
		;;
	4)
		rcname="fourth"
		;;
	5)
		rcname="fifth"
		;;
	esac

	{
		echo "samba-announce@lists.samba.org, samba@lists.samba.org, samba-technical@lists.samba.org"
	} > announce.${tagname}.to.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.to.txt"

	{
		echo "[Announce] Samba ${version} Available for Download"
	} > announce.${tagname}.subject.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.subject.txt"

	{
		cat ${tagname}.WHATSNEW.txt
		echo ""
		echo "================"
		echo "Download Details"
		echo "================"
		echo ""
		echo "The uncompressed tarballs and patch files have been signed"
		echo "using GnuPG (ID 6568B7EA).  The source code can be downloaded"
		echo "from:"
		echo ""
		echo "        ${download_url}"
		echo ""
		echo "The release notes are available online at:"
		echo ""
		echo "        ${download_url}${tagname}.WHATSNEW.txt"
		echo ""
		echo "Our Code, Our Bugs, Our Responsibility."
		echo "(https://bugzilla.samba.org/)"
		echo ""
		echo "                        --Enjoy"
		echo "                        The Samba Team"
	} > announce.${tagname}.mail.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mail.txt"

	{
		echo -n "-i announce.${tagname}.mail.txt "
		echo -n "-s \"$(cat announce.${tagname}.subject.txt | xargs)\" "
		echo -n "$(cat announce.${tagname}.to.txt | xargs)"
	} > announce.${tagname}.mutt-arguments.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mutt-arguments.txt"

	local headlinefile="${utctime}.${version}.headline.html"
	{
		echo "<!-- BEGIN: posted_news/${headlinefile} -->"
		echo "<li> ${utcdate} <a href=\"${href}\">Samba ${version} Available for Download</a></li>"
		echo "<!-- END: posted_news/${headlinefile} -->"
	} > ${headlinefile}
	CLEANUP_FILES="${CLEANUP_FILES} ${headlinefile}"

	local bodyfile="${utctime}.${version}.body.html"
	{
		echo "<!-- BEGIN: posted_news/${bodyfile} -->"
		echo "<h5><a name=\"${version}\">${utcdate}</a></h5>"
		echo "<p class="headline">Samba ${version} Available for Download</p>"
		echo "<p>"
		echo "This is the ${rcname} release candidate of the upcoming Samba ${series} release series."
		echo "</p>"
		echo "<p>"
		echo "The uncompressed tarball has been signed using GnuPG (ID ${GPG_KEYID})."
		echo "The source code can be <a href=\"${download_url}${tagname}.tar.gz\">downloaded now</a>."
		echo "See <a href=\"${download_url}${tagname}.WHATSNEW.txt\">the release notes for more info</a>."
		echo "</p>"
		echo "<!-- END: posted_news/${bodyfile} -->"
		echo ""
	} > ${bodyfile}
	CLEANUP_FILES="${CLEANUP_FILES} ${bodyfile}"

	{
		ls -lart announce.${tagname}.* ${headlinefile} ${bodyfile}
		echo ""
		echo "NOTICE:"
		echo "You need to do the following manual steps in order"
		echo "to finish the announcement of ${tagname}!"
		echo ""
		echo "Copy the following files into the posted_news/"
		echo "subdirectory of the samba-web.git repository and commit them:"
		echo "  ${headlinefile}"
		echo "  ${bodyfile}"
		echo ""
		echo "  cp -a ${utctime}.${version}.*.html /path/to/samba-web/posted_news/"
		echo "  pushd /path/to/samba-web"
		echo "  git add posted_news/${utctime}.${version}.*.html"
		echo "  git commit --signoff --message \"NEWS[${version}]: Samba ${version} Available for Download\""
		echo "  git show -p --stat HEAD"
		echo "  git push ..."
		echo "  popd"
		echo ""
		echo "Once the resulting commit is pushed a cron job will update "
		echo "the content exported by the webserver every 5mins."
		echo ""
		echo "If the web content is updated, you need to send the announce mail (gpg signed)."
		echo "- announce.${tagname}.to.txt contains the mail's recipients for the To: header."
		echo "- announce.${tagname}.subject.txt contains the mail's subject line."
		echo "- announce.${tagname}.mail.txt contains the content of the mail body."
		echo "In case your're using mutt, you can use the following shortcut:"
		echo "  eval mutt \$(cat announce.${tagname}.mutt-arguments.txt)"
		echo ""
		echo "NOTICE: you're not done yet! Read the above instructions carefully!"
		echo "See: announce.${tagname}.todo.txt"
		echo ""
	} > announce.${tagname}.todo.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.todo.txt"

	cat announce.${tagname}.todo.txt

	return 0
}

announce_samba_stable() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	echo "extract WHATSNEW.txt"
	tar xf ${tagname}.tar.gz --to-stdout ${tagname}/WHATSNEW.txt > ${TMPDIR}/WHATSNEW.txt

	# TODO: up to '^Release notes for older releases follow:'
	cp -a ${TMPDIR}/WHATSNEW.txt ${TMPDIR}/WHATSNEW.top

	local t=""
	local utcdate=$(date --utc +"%d %B %Y")
	local utctime=$(date --utc +"%Y%m%d-%H%M%S")
	local version=$(echo "${tagname}" | sed -e 's!^samba-!!')
	local href="#${version}"
	local series=$(echo "${version}" | cut -d '.' -f1-2)
	local release=$(echo "${version}" | cut -d '.' -f3)
	local releasename="latest"
	case "${release}" in
	1)
		releasename="first"
		;;
	*)
		releasename="latest"
		;;
	esac

	{
		echo "samba-announce@lists.samba.org, samba@lists.samba.org, samba-technical@lists.samba.org"
	} > announce.${tagname}.to.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.to.txt"

	{
		echo "[Announce] Samba ${version} Available for Download"
	} > announce.${tagname}.subject.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.subject.txt"

	{
		cat ${TMPDIR}/WHATSNEW.top
		echo ""
		echo "================"
		echo "Download Details"
		echo "================"
		echo ""
		echo "The uncompressed tarballs and patch files have been signed"
		echo "using GnuPG (ID 6568B7EA).  The source code can be downloaded"
		echo "from:"
		echo ""
		echo "        ${download_url}"
		echo ""
		echo "The release notes are available online at:"
		echo ""
		echo "        ${history_url}${tagname}.html"
		echo ""
		echo "Our Code, Our Bugs, Our Responsibility."
		echo "(https://bugzilla.samba.org/)"
		echo ""
		echo "                        --Enjoy"
		echo "                        The Samba Team"
	} > announce.${tagname}.mail.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mail.txt"

	{
		echo -n "-i announce.${tagname}.mail.txt "
		echo -n "-s \"$(cat announce.${tagname}.subject.txt | xargs)\" "
		echo -n "$(cat announce.${tagname}.to.txt | xargs)"
	} > announce.${tagname}.mutt-arguments.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mutt-arguments.txt"

	{
		local tmp=$(cat ${TMPDIR}/WHATSNEW.top | grep -n '^Reporting bugs & Development Discussion' | head -1 | cut -d ':' -f1)
		local lines=$(expr ${tmp} - 2)

		echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"'
		echo ' "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
		echo '<html xmlns="http://www.w3.org/1999/xhtml">'

		echo "<head>"
		echo "<title>Samba ${version} - Release Notes</title>"
		echo "</head>"

		echo "<body>"
		echo "<H2>Samba ${version} Available for Download</H2>"

		echo "<p>"
		echo "<a href=\"${download_url}${tagname}.tar.gz\">Samba ${version} (gzipped)</a><br>"
		echo "<a href=\"${download_url}${tagname}.tar.asc\">Signature</a>"
		echo "</p>"

		echo "<p>"
		echo "<pre>"
		head -${lines} ${TMPDIR}/WHATSNEW.top | sed \
			-e 's!&!\&amp;!g' | sed \
			-e 's!<!\&lt;!g' \
			-e 's!>!\&gt;!g' \
			-e 's!ä!\&auml;!g' \
			-e 's!Ä!\&Auml;!g' \
			-e 's!ö!\&ouml;!g' \
			-e 's!Ö!\&Ouml;!g' \
			-e 's!ü!\&uuml;!g' \
			-e 's!Ü!\&Uuml;!g' \
			-e 's!ß!\&szlig;!g' \
			-e 's!"!\&quot;!g' \
			-e "s!'!\&apos;!g" \
			| cat
		echo "</pre>"
		echo "</p>"

		echo "</body>"
		echo "</html>"
	} > announce.${tagname}.html
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.html"

	local headlinefile="${utctime}.${version}.headline.html"
	{
		echo "<!-- BEGIN: posted_news/${headlinefile} -->"
		echo "<li> ${utcdate} <a href=\"${href}\">Samba ${version} Available for Download</a></li>"
		echo "<!-- END: posted_news/${headlinefile} -->"
	} > ${headlinefile}
	CLEANUP_FILES="${CLEANUP_FILES} ${headlinefile}"

	local bodyfile="${utctime}.${version}.body.html"
	{
		echo "<!-- BEGIN: posted_news/${bodyfile} -->"
		echo "<h5><a name=\"${version}\">${utcdate}</a></h5>"
		echo "<p class="headline">Samba ${version} Available for Download</p>"
		echo "<p>"
		echo "This is the ${releasename} stable release of the Samba ${series} release series."
		echo "</p>"
		echo "<p>"
		echo "The uncompressed tarball has been signed using GnuPG (ID ${GPG_KEYID})."
		echo "The source code can be <a href=\"${download_url}${tagname}.tar.gz\">downloaded now</a>."
		#test -n "${patchfile}" && {
		#	echo "A <a href=\"...\"> patch against Samba ${oldversion}</a> is also available."
		#}
		echo "See <a href=\"${history_url}${tagname}.html\">the release notes for more info</a>."
		echo "</p>"
		echo "<!-- END: posted_news/${bodyfile} -->"
		echo ""
	} > ${bodyfile}
	CLEANUP_FILES="${CLEANUP_FILES} ${bodyfile}"

	{
		ls -lart announce.${tagname}.* ${headlinefile} ${bodyfile}
		echo ""
		echo "NOTICE:"
		echo "You need to do the following manual steps in order"
		echo "to finish the announcement of ${tagname}!"
		echo ""
		echo "Copy the following files into the posted_news/"
		echo "subdirectory of the samba-web.git repository and commit them:"
		echo "  ${headlinefile}"
		echo "  ${bodyfile}"
		echo ""
		echo "  cp -a ${utctime}.${version}.*.html /path/to/samba-web/posted_news/"
		echo "  cp -a announce.${tagname}.html /path/to/samba-web/history/${tagname}.html"
		echo "  pushd /path/to/samba-web"
		echo "  git add posted_news/${utctime}.${version}.*.html"
		echo "  git add history/${tagname}.html"
		echo "  git commit --signoff --message \"NEWS[${version}]: Samba ${version} Available for Download\""
		echo "  git show -p --stat HEAD"
		echo "  git push ..."
		echo "  popd"
		echo ""
		echo "Once the resulting commit is pushed a cron job will update "
		echo "the content exported by the webserver every 5mins."
		echo ""
		echo "If the web content is updated, you need to send the announce mail (gpg signed)."
		echo "- announce.${tagname}.to.txt contains the mail's recipients for the To: header."
		echo "- announce.${tagname}.subject.txt contains the mail's subject line."
		echo "- announce.${tagname}.mail.txt contains the content of the mail body."
		echo "In case your're using mutt, you can use the following shortcut:"
		echo "  eval mutt \$(cat announce.${tagname}.mutt-arguments.txt)"
		echo ""
		echo "NOTICE: you're not done yet! Read the above instructions carefully!"
		echo "See: announce.${tagname}.todo.txt"
		echo ""
	} > announce.${tagname}.todo.txt
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.todo.txt"

	cat announce.${tagname}.todo.txt

	return 0
}

announce_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${announce_fn}" || {
		echo "announce_fn variable empty"
		return 1
	}

	echo "Running ${announce_fn}"
	${announce_fn}
}

case "${product}" in
talloc | tdb | tevent | ldb)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Library Distribution Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='13084025'
	}

	productbase="${product}"
	srcdir="lib/${product}"
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/${product}/"
	download_url="${CONF_DOWNLOAD_URL}/${product}/"

	check_fn="check_nopatch"
	fullcmds="create check push upload"
	;;
samba-rc)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='6568B7EA'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/samba/rc/"
	download_url="${CONF_DOWNLOAD_URL}/samba/rc/"

	verify_fn="verify_samba_rc"
	check_fn="check_nopatch"
	announce_fn="announce_samba_rc"
	fullcmds="verify create check whatsnew push upload announce"
	;;
samba-stable)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='6568B7EA'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/samba/stable/"
	download_url="${CONF_DOWNLOAD_URL}/samba/stable/"
	history_url="${CONF_HISTORY_URL}/samba/history/"

	verify_fn="verify_samba_stable"
	check_fn="check_withpatch"
	announce_fn="announce_samba_stable"
	fullcmds="verify create patch check push upload announce"
	;;
TODO-samba-security)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='6568B7EA'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/samba/stable/"
	download_url="${CONF_DOWNLOAD_URL}/samba/stable/"

	verify_fn="verify_samba_stable"
	check_fn="check_withpatch"
	announce_fn="announce_samba_security"
	fullcmds="verify create patch check"
	next_cmd="push"
	;;
*)
	usage
	echo "Unknown product ${product}"
	exit 1
esac

pushd ${srcdir} || {
	echo "srcdir[${srcdir}] does not exist"
	exit 1
}

trap_handler() {
	echo ""
	echo "ERROR: cleaning up"
	echo ""

	for t in ${CLEANUP_TAGS}; do
		echo "Removing tag[${t}]"
		git tag -v "${t}" && {
			git tag -d "${t}" || {
				echo "failed to remove tag ${t}"
			}
		}
	done

	for f in ${CLEANUP_FILES}; do
		echo "Removing file[${f}]"
		test -f "${f}" && {
			rm "${f}" || {
				echo "failed to remove ${f}"
			}
		}
	done

	for d in ${CLEANUP_DIRS}; do
		echo "Removing dir[${d}]"
		test -d "${d}" && {
			rm -rf "${d}" || {
				echo "failed to remove ${d}"
			}
		}
	done
}

CLEANUP_TAGS=""
CLEANUP_FILES=""
CLEANUP_DIRS=""
trap trap_handler INT QUIT TERM EXIT

cmd_allowed "${globalcmd}" fullrelease ${fullcmds} || {
	usage
	echo "command[${globalcmd}] not supported for product[${product}]"
	exit 1
}

case "${globalcmd}" in
fullrelease)
	check_args "${globalcmd}" "$#" "0" || exit 1
	cmds="${fullcmds}"
	;;
create)
	check_args "${globalcmd}" "$#" "0" || exit 1
	check_args "create" "$#" "0" || exit 1

	cmds=""
	cmd_allowed "verify" ${fullcmds} && {
		cmds="${cmds} verify"
	}
	cmds="${cmds} create"
	cmd_allowed "whatsnew" ${fullcmds} && {
		cmds="${cmds} whatsnew"
	}
	cmd_allowed "patch" ${fullcmds} && {
		cmds="${cmds} patch"
	}
	cmds="${cmds} check"
	next_cmd="push"
	;;
push)
	check_args "${globalcmd}" "$#" "1" || exit 1
	tagname="$1"
	cmds="check push"
	next_cmd="upload"
	;;
upload)
	check_args "${globalcmd}" "$#" "1" || exit 1
	tagname="$1"
	cmds="check upload"
	cmd_allowed "symlinks" ${fullcmds} && {
		cmds="${cmds} symlinks"
	}
	cmd_allowed "announce" ${fullcmds} && {
		next_cmd="announce"
	}
	;;
announce)
	check_args "${globalcmd}" "$#" "1" || exit 1
	tagname="$1"
	cmds="check announce"
	;;
*)
	usage
	echo "Unknown command ${globalcmd}"
	exit 1
	;;
esac

TMPDIR="release.$$"
CLEANUP_DIRS="${CLEANUP_DIRS} ${TMPDIR}"
umask 0077
mkdir "${TMPDIR}"
umask 0022

for cmd in ${cmds}; do
	echo "Starting subcommand[${cmd}]"
	${cmd}_release || {
		echo "Failed subcommand[${cmd}]"
		exit 1
	}
	echo "Finished subcommand[${cmd}]"
done

test -d "${TMPDIR}" && {
	rm -rf "${TMPDIR}" || {
		echo "failed to remove ${TMPDIR}"
	}
}

test -n "${next_cmd}" && {
	echo "Continue with '$0 ${product} ${next_cmd} ${tagname}'."
}

trap - INT QUIT TERM EXIT

exit 0
