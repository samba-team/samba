#!/bin/sh

{
	vars=`set | \
		grep "^[a-zA-Z][^=]*='[^']*'$" | \
		grep -v '^IFS=' | \
		grep -v '^TERM' | \
		grep -v '^PPID' | \
		grep -v '^PS[1-9]=' | \
		cat `
	echo "${vars}"
	echo "${vars}" | sed -e 's!^\([a-zA-Z][^=]*\)=.*$!export \1!'
} > bin/restore.env.source

echo "RUN: '. bin/restore.env.source'"
