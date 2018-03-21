set_mem_usage ()
{
	_mem_usage="${1:-10}" # Default is 10%
	_swap_usage="${2:-0}" # Default is  0%

	_swap_total=5857276
	_swap_free=$(( (100 - $_swap_usage) * $_swap_total / 100 ))

	_mem_total=3940712
	_mem_free=225268
	_mem_buffers=146120
	_mem_cached=$(( $_mem_total * (100 - $_mem_usage) / 100 -
			$_mem_free - $_mem_buffers ))

	export FAKE_PROC_MEMINFO="\
MemTotal:        ${_mem_total} kB
MemFree:          ${_mem_free} kB
Buffers:          ${_mem_buffers} kB
Cached:          ${_mem_cached} kB
SwapCached:        56016 kB
Active:          2422104 kB
Inactive:        1019928 kB
Active(anon):    1917580 kB
Inactive(anon):   523080 kB
Active(file):     504524 kB
Inactive(file):   496848 kB
Unevictable:        4844 kB
Mlocked:            4844 kB
SwapTotal:       ${_swap_total} kB
SwapFree:        ${_swap_free} kB
..."
}

set_fs_usage ()
{
	export FAKE_FS_USE="${1:-10}"  # Default is 10% usage
}

setup ()
{
	setup_dbdir

	# Tests use default unless explicitly set
	set_mem_usage
	set_fs_usage
}
