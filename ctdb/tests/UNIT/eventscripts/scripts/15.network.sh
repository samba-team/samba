# shellcheck disable=SC2120
# Function arguments passed in testcases
set_host_data()
{
	# Default is nothing, so all host lookups succeed with
	# 127.0.0.1
	export FAKE_HOST_DATA="$*"
}

set_ping_fail()
{
	# Default is nothing, so all pings succeed
	export FAKE_PING_FAIL="$*"
}

setup()
{
	set_host_data
	set_ping_fail
}
