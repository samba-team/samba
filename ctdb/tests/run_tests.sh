#!/bin/sh

test_dir=$(dirname "$0")

case $(basename "$0") in
    *run_cluster_tests*)
	opts="-c"
	;;
    *)
	opts=""
esac

exec "${test_dir}/scripts/run_tests" $opts "$@"
