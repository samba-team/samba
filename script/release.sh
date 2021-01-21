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

test -d ".git" -o -r ".git" || {
	echo "Run this script from the top-level directory in the"
	echo "repository"
	exit 1
}

usage() {
	echo "Usage: script/release.sh <PRODUCT> <COMMAND>"
	echo ""
	echo "PRODUCT: ldb, talloc, tevent, tdb, samba-rc, samba-stable"
	echo "COMMAND: fullrelease, create, push, upload, announce"
	echo ""
	return 0
}

test -x "script/release.sh" || {
	usage
	echo "Run this script from the top-level directory in the"
	echo "repository: as 'script/release.sh'"
	exit 1
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

load_samba_stable_versions() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${version-}" && {
		return 0
	}

	local SAMBA_VERSION_MAJOR=$(grep '^SAMBA_VERSION_MAJOR=' VERSION | cut -d '=' -f2 | xargs)
	local SAMBA_VERSION_MINOR=$(grep '^SAMBA_VERSION_MINOR=' VERSION | cut -d '=' -f2 | xargs)
	local SAMBA_VERSION_RELEASE=$(grep '^SAMBA_VERSION_RELEASE=' VERSION | cut -d '=' -f2 | xargs)

	version="${SAMBA_VERSION_MAJOR}.${SAMBA_VERSION_MINOR}.${SAMBA_VERSION_RELEASE}"
	tagname="${productbase}-${version}"

	test ${SAMBA_VERSION_RELEASE} -gt 0 || {
		return 0
	}

	oldversion="${SAMBA_VERSION_MAJOR}.${SAMBA_VERSION_MINOR}.$(expr ${SAMBA_VERSION_RELEASE} - 1)"
	oldtagname="${productbase}-${oldversion}"
	patchfile="${productbase}-${oldversion}-${version}.diffs"

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

	load_samba_stable_versions

	test -n "${oldtagname}" || {
		return 0
	}

	local verify_out="${TMPDIR}/verify-${oldtagname}.out"

	echo "Verifying oldtagname: ${oldtagname}"

	git tag -v "${oldtagname}" >${verify_out} 2>&1 || {
		echo "failed to verify old tag[${oldtagname}]"
		echo ""
		cat "${verify_out}"
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

	test -n "${tagname}" && {
		git tag -l "${tagname}" | grep -q "${tagname}" && {
			echo "tagname[${tagname}] already exist"
			return 1
		}

		local _tgzname="${tagname}.tar.gz"
		test -e "${_tgzname}" && {
			echo "_tgzname[${_tgzname}] already exist"
			return 1
		}
	}

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

	local _tagname=$(basename ${tgzname} .tar.gz)
	test -n "${tagname}" && {
		test x"${_tagname}" = x"${tagname}" || {
			echo "Invalid tgzname[${tgzname}]"
			return 1
		}
	}
	tagname="${_tagname}"

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
	echo "Tagging as ${tagname}"
	git tag -u ${GPG_KEYID} -s "${tagname}" -m "${productbase}: tag release ${tagname}" || {
		return 1
	}
	CLEANUP_TAGS="${CLEANUP_TAGS} ${tagname}"

	echo "Signing ${tarname} => ${tarname}.asc"
	rm -f "${tarname}.asc"
	gpg --default-key "${GPG_KEYID}" --detach-sign --armor ${tarname} || {
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

	test -n "${patchfile}" || {
		return 0
	}

	local oldpwd=$(pwd)
	echo "Generating ${patchfile}"
	(
		set -e
		set -u
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
	gpg --default-key "${GPG_KEYID}" --detach-sign --armor ${patchfile} || {
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

	local verify_out="${TMPDIR}/verify-${oldtagname}.out"

	echo "Verifying tagname: ${tagname}"

	git tag -v "${tagname}" >${verify_out} 2>&1 || {
		echo "failed to verify tag[${tagname}]"
		echo ""
		cat "${verify_out}"
		return 1
	}
	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "tagname[${tagname}] was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	echo "Verifying ${tagname}.tar.gz and ${tagname}.tar.asc"

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	test -f "${tagname}.tar.asc" || {
		echo "${tagname}.tar.asc does not exist"
		return 1
	}

	zcat "${tagname}.tar.gz" | gpg --verify "${tagname}.tar.asc" - 2>${verify_out} || {
		echo "Failed to verify ${tagname}.tar.asc"
		return 1
	}
	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "${tagname}.tar.asc was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	ls -la ${tagname}.*

	return 0
}

check_samba_stable() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	load_samba_stable_versions

	local verify_out="${TMPDIR}/verify-${oldtagname}.out"

	echo "Verifying tagname: ${tagname}"

	git tag -v "${tagname}" >${verify_out} 2>&1 || {
		echo "failed to verify tag[${tagname}]"
		echo ""
		cat "${verify_out}"
		return 1
	}
	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "tagname[${tagname}] was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	echo "Verifying ${tagname}.tar.gz and ${tagname}.tar.asc"

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	test -f "${tagname}.tar.asc" || {
		echo "${tagname}.tar.asc does not exist"
		return 1
	}

	zcat "${tagname}.tar.gz" | gpg --verify "${tagname}.tar.asc" - 2>${verify_out} || {
		echo "Failed to verify ${tagname}.tar.asc"
		return 1
	}
	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "${tagname}.tar.asc was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	test -n "${patchfile}" || {
		ls -lart ${tagname}.*
		return 0
	}

	echo "Verifying ${patchfile}.gz and ${patchfile}.asc"

	test -f "${patchfile}.gz" || {
		echo "${patchfile}.gz does not exist"
		return 1
	}

	test -f "${patchfile}.asc" || {
		echo "${patchfile}.asc does not exist"
		return 1
	}

	zcat "${patchfile}.gz" | gpg --verify "${patchfile}.asc" - 2>${verify_out} || {
		echo "Failed to verify ${patchfile}.asc"
		return 1
	}
	grep -q "${GPG_KEYID}" "${verify_out}" || {
		echo "${patchfile}.asc was not generated with GPG_KEYID[${GPG_KEYID}]!"
		echo ""
		cat "${verify_out}"
		return 1
	}

	ls -lart ${tagname}.* ${patchfile}.*
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

upload_nopatch() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	echo "Upload ${tagname}.* to '${upload_url}'"
	rsync -Pav --delay-updates ${tagname}.* "${upload_url}/" || {
		return 1
	}
	rsync ${upload_url}/${tagname}.*

	return 0
}

upload_samba_stable() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	load_samba_stable_versions

	local release_url="${upload_url}samba/stable/"
	local patch_url="${upload_url}samba/patches/"

	echo "Upload ${tagname}.tar.* to '${release_url}'"
	ls -lart ${tagname}.tar.*
	rsync -Pav --delay-updates ${tagname}.tar.* "${release_url}/" || {
		return 1
	}
	rsync ${release_url}/${tagname}.tar.*

	test -n "${patchfile}" || {
		return 0
	}

	echo "Upload ${patchfile}.* to '${patch_url}'"
	ls -lart ${patchfile}.*
	rsync -Pav --delay-updates ${patchfile}.* "${patch_url}/" || {
		return 1
	}
	rsync ${patch_url}/${patchfile}.*

	return 0
}

upload_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${upload_fn}" || {
		echo "upload_fn variable empty"
		return 1
	}

	echo "Running ${upload_fn}"
	${upload_fn}
}

announcement_samba_rc() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	test -f "${tagname}.WHATSNEW.txt" || {
		echo "${tagname}.WHATSNEW.txt does not exist"
		return 1
	}

	local t=""
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

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.to.txt"
	{
		echo "samba-announce@lists.samba.org, samba@lists.samba.org, samba-technical@lists.samba.org"
	} > announce.${tagname}.to.txt

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.subject.txt"
	{
		echo "[Announce] Samba ${version} Available for Download"
	} > announce.${tagname}.subject.txt

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mail.txt"
	{
		cat ${tagname}.WHATSNEW.txt
		echo ""
		echo "================"
		echo "Download Details"
		echo "================"
		echo ""
		echo "The uncompressed tarballs and patch files have been signed"
		echo "using GnuPG (ID ${GPG_KEYID}).  The source code can be downloaded"
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

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mutt-arguments.txt"
	{
		echo -n "-i announce.${tagname}.mail.txt "
		echo -n "-s \"$(cat announce.${tagname}.subject.txt | xargs)\" "
		echo -n "$(cat announce.${tagname}.to.txt | xargs)"
	} > announce.${tagname}.mutt-arguments.txt

	local headlinefile="posted_news/@UTCTIME@.${version}.headline.html"
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.headline.html"
	{
		echo "<!-- BEGIN: ${headlinefile} -->"
		echo "<li> @UTCDATE@ <a href=\"${href}\">Samba ${version} Available for Download</a></li>"
		echo "<!-- END: ${headlinefile} -->"
	} > announce.${tagname}.headline.html

	local bodyfile="posted_news/@UTCTIME@.${version}.body.html"
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.body.html"
	{
		echo "<!-- BEGIN: ${bodyfile} -->"
		echo "<h5><a name=\"${version}\">@UTCDATE@</a></h5>"
		echo "<p class="headline">Samba ${version} Available for Download</p>"
		echo "<p>"
		echo "This is the ${rcname} release candidate of the upcoming Samba ${series} release series."
		echo "</p>"
		echo "<p>"
		echo "The uncompressed tarball has been signed using GnuPG (ID ${GPG_KEYID})."
		echo "The source code can be <a href=\"${download_url}${tagname}.tar.gz\">downloaded now</a>."
		echo "See <a href=\"${download_url}${tagname}.WHATSNEW.txt\">the release notes for more info</a>."
		echo "</p>"
		echo "<!-- END: ${bodyfile} -->"
	} > announce.${tagname}.body.html

	local webrepo="${TMPDIR}/webrepo"

	mkdir "${webrepo}" || {
		return 1
	}
	git -C "${webrepo}" init || {
		return 1
	}

	mkdir -p "$(dirname ${webrepo}/${headlinefile})" || {
		return 1
	}
	cp -a "announce.${tagname}.headline.html" "${webrepo}/${headlinefile}" || {
		return 1
	}

	mkdir -p "$(dirname ${webrepo}/${bodyfile})" || {
		return 1
	}
	cp -a "announce.${tagname}.body.html" "${webrepo}/${bodyfile}" || {
		return 1
	}

	git -C "${webrepo}" add "${headlinefile}" "${bodyfile}" || {
		return 1
	}
	git -C "${webrepo}" commit --signoff --message "NEWS[${version}]: Samba ${version} Available for Download" || {
		return 1
	}
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.patch.txt"
	git -C "${webrepo}" format-patch --stdout -1 HEAD > announce.${tagname}.patch.txt || {
		return 1
	}

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.todo.txt"
	{
		ls -lart announce.${tagname}.*
		echo ""
		echo "NOTICE:"
		echo "You need to do the following manual steps in order"
		echo "to finish the announcement of ${tagname}!"
		echo ""
		echo "Change to a samba-web checkout and run"
		echo "  ./announce_samba_release.sh ${version} $(pwd)/announce.${tagname}.patch.txt"
		echo ""
		echo "Once the resulting commit is pushed a cron job will update "
		echo "the content exported by the webserver every 5-10 mins."
		echo "Check https://www.samba.org"
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

	ls -lart announce.${tagname}.*
	return 0
}

announcement_samba_stable() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	load_samba_stable_versions

	test -f "${tagname}.tar.gz" || {
		echo "${tagname}.tar.gz does not exist"
		return 1
	}

	local release_url="${download_url}samba/stable/"
	local patch_url="${download_url}samba/patches/"

	echo "extract WHATSNEW.txt"
	tar xf ${tagname}.tar.gz --to-stdout ${tagname}/WHATSNEW.txt > ${TMPDIR}/WHATSNEW.txt

	local t=""
	local oldversion=$(echo "${oldtagname}" | sed -e 's!^samba-!!')
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

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.to.txt"
	{
		echo "samba-announce@lists.samba.org, samba@lists.samba.org, samba-technical@lists.samba.org"
	} > announce.${tagname}.to.txt

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.subject.txt"
	{
		echo "[Announce] Samba ${version} Available for Download"
	} > announce.${tagname}.subject.txt

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mail.txt"
	{
		local top=$(cat ${TMPDIR}/WHATSNEW.txt | grep -n '^Release notes for older releases follow:' | head -1 | cut -d ':' -f1)
		test -n "${top}" || {
			top=$(cat ${TMPDIR}/WHATSNEW.txt | wc -l)
		}
		local skip=$(cat ${TMPDIR}/WHATSNEW.txt | grep -n '^[^ ]' | head -1 | cut -d ':' -f1)
		local headlimit=$(expr ${top} - 1 )
		local taillimit=$(expr ${headlimit} - \( ${skip} - 1 \))

		echo ""
		echo ""
		echo "Release Announcements"
		echo "---------------------"
		echo ""
		head -${headlimit} ${TMPDIR}/WHATSNEW.txt | tail -${taillimit}
		echo ""
		echo "================"
		echo "Download Details"
		echo "================"
		echo ""
		echo "The uncompressed tarballs and patch files have been signed"
		echo "using GnuPG (ID ${GPG_KEYID}).  The source code can be downloaded"
		echo "from:"
		echo ""
		echo "        ${release_url}"
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

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.mutt-arguments.txt"
	{
		echo -n "-i announce.${tagname}.mail.txt "
		echo -n "-s \"$(cat announce.${tagname}.subject.txt | xargs)\" "
		echo -n "$(cat announce.${tagname}.to.txt | xargs)"
	} > announce.${tagname}.mutt-arguments.txt

	local htmlfile="history/${tagname}.html"
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.html"
	{
		local tmp=$(cat ${TMPDIR}/WHATSNEW.txt | grep -n '^Reporting bugs & Development Discussion' | head -1 | cut -d ':' -f1)
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
		echo "<a href=\"${release_url}${tagname}.tar.gz\">Samba ${version} (gzipped)</a><br>"
		echo "<a href=\"${release_url}${tagname}.tar.asc\">Signature</a>"
		echo "</p>"

		test -n "${patchfile}" && {
			echo "<p>"
			echo "<a href=\"${patch_url}${patchfile}.gz\">Patch (gzipped) against Samba ${oldversion}</a><br>"
			echo "<a href=\"${patch_url}${patchfile}.asc\">Signature</a>"
			echo "</p>"
		}

		echo "<p>"
		echo "<pre>"
		head -${lines} ${TMPDIR}/WHATSNEW.txt | sed \
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

	local headlinefile="posted_news/@UTCTIME@.${version}.headline.html"
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.headline.html"
	{
		echo "<!-- BEGIN: ${headlinefile} -->"
		echo "<li> @UTCDATE@ <a href=\"${href}\">Samba ${version} Available for Download</a></li>"
		echo "<!-- END: ${headlinefile} -->"
	} > announce.${tagname}.headline.html

	local bodyfile="posted_news/@UTCTIME@.${version}.body.html"
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.body.html"
	{
		echo "<!-- BEGIN: ${bodyfile} -->"
		echo "<h5><a name=\"${version}\">@UTCDATE@</a></h5>"
		echo "<p class="headline">Samba ${version} Available for Download</p>"
		echo "<p>"
		echo "This is the ${releasename} stable release of the Samba ${series} release series."
		echo "</p>"
		echo "<p>"
		echo "The uncompressed tarball has been signed using GnuPG (ID ${GPG_KEYID})."
		echo "The source code can be <a href=\"${release_url}${tagname}.tar.gz\">downloaded now</a>."
		test -n "${patchfile}" && {
			echo "A <a href=\"${patch_url}${patchfile}.gz\">patch against Samba ${oldversion}</a> is also available."
		}
		echo "See <a href=\"${history_url}${tagname}.html\">the release notes for more info</a>."
		echo "</p>"
		echo "<!-- END: ${bodyfile} -->"
	} > announce.${tagname}.body.html

	local webrepo="${TMPDIR}/webrepo"

	mkdir "${webrepo}" || {
		return 1
	}
	git -C "${webrepo}" init || {
		return 1
	}

	mkdir -p "$(dirname ${webrepo}/${htmlfile})" || {
		return 1
	}
	cp -a "announce.${tagname}.html" "${webrepo}/${htmlfile}" || {
		return 1
	}

	mkdir -p "$(dirname ${webrepo}/${headlinefile})" || {
		return 1
	}
	cp -a "announce.${tagname}.headline.html" "${webrepo}/${headlinefile}" || {
		return 1
	}

	mkdir -p "$(dirname ${webrepo}/${bodyfile})" || {
		return 1
	}
	cp -a "announce.${tagname}.body.html" "${webrepo}/${bodyfile}" || {
		return 1
	}

	git -C "${webrepo}" add "${htmlfile}" "${headlinefile}" "${bodyfile}" || {
		return 1
	}
	git -C "${webrepo}" commit --signoff --message "NEWS[${version}]: Samba ${version} Available for Download" || {
		return 1
	}
	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.patch.txt"
	git -C "${webrepo}" format-patch --stdout -1 HEAD > announce.${tagname}.patch.txt || {
		return 1
	}

	CLEANUP_FILES="${CLEANUP_FILES} announce.${tagname}.todo.txt"
	{
		ls -lart announce.${tagname}.*
		echo ""
		echo "NOTICE:"
		echo "You need to do the following manual steps in order"
		echo "to finish the announcement of ${tagname}!"
		echo ""
		echo "Change to a samba-web checkout and run"
		echo "  ./announce_samba_release.sh ${version} $(pwd)/announce.${tagname}.patch.txt"
		echo ""
		echo "Once the resulting commit is pushed a cron job will update "
		echo "the content exported by the webserver every 5-10 mins."
		echo "Check https://www.samba.org"
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

	ls -lart announce.${tagname}.*
	return 0
}

announcement_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1

	test -n "${announcement_fn}" || {
		echo "announcement_fn variable empty"
		return 1
	}

	echo "Running ${announcement_fn}"
	${announcement_fn}
}

announce_release() {
	check_args "${FUNCNAME}" "$#" "0" || return 1
	require_tagname "${FUNCNAME}"

	test -f "announce.${tagname}.todo.txt" || {
		echo "announce.${tagname}.todo.txt does not exist"
		return 1
	}

	cat announce.${tagname}.todo.txt
	return 0
}

case "${product}" in
talloc | tdb | tevent | ldb)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Library Distribution Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='4793916113084025'
	}

	productbase="${product}"
	srcdir="lib/${product}"
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/${product}/"
	download_url="${CONF_DOWNLOAD_URL}/${product}/"

	check_fn="check_nopatch"
	upload_fn="upload_nopatch"
	fullcmds="create check push upload"
	;;
samba-rc)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='AA99442FB680B620'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/samba/rc/"
	download_url="${CONF_DOWNLOAD_URL}/samba/rc/"

	verify_fn="verify_samba_rc"
	check_fn="check_nopatch"
	upload_fn="upload_nopatch"
	announcement_fn="announcement_samba_rc"
	fullcmds="verify create check whatsnew announcement push upload announce"
	;;
samba-stable)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='AA99442FB680B620'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/"
	download_url="${CONF_DOWNLOAD_URL}/"
	history_url="${CONF_HISTORY_URL}/samba/history/"

	verify_fn="verify_samba_stable"
	check_fn="check_samba_stable"
	upload_fn="upload_samba_stable"
	announcement_fn="announcement_samba_stable"
	fullcmds="verify create patch check announcement push upload announce"
	;;
TODO-samba-security)
	test -z "${GPG_USER-}" && {
		GPG_USER='Samba Distribution Verification Key <samba-bugs@samba.org>'
	}

	test -z "${GPG_KEYID-}"  && {
		GPG_KEYID='AA99442FB680B620'
	}

	productbase="samba"
	srcdir="."
	repo_url="${CONF_REPO_URL}"
	upload_url="${CONF_UPLOAD_URL}/"
	download_url="${CONF_DOWNLOAD_URL}/"
	history_url="${CONF_HISTORY_URL}/samba/history/"

	verify_fn="verify_samba_stable"
	check_fn="check_samba_stable"
	upload_fn="upload_samba_stable"
	announcement_fn="announcement_samba_security"
	fullcmds="verify create patch check announcement"
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
	cmd_allowed "announcement" ${fullcmds} && {
		cmds="${cmds} announcement"
	}
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
