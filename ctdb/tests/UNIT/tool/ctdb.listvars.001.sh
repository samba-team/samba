#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "exact check of output"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok << EOF
SeqnumInterval             = 1000
ControlTimeout             = 60
TraverseTimeout            = 20
KeepaliveInterval          = 5
KeepaliveLimit             = 5
RecoverTimeout             = 30
RecoverInterval            = 1
ElectionTimeout            = 3
TakeoverTimeout            = 9
MonitorInterval            = 15
TickleUpdateInterval       = 20
EventScriptTimeout         = 30
MonitorTimeoutCount        = 20
RecoveryGracePeriod        = 120
RecoveryBanPeriod          = 300
DatabaseHashSize           = 100001
DatabaseMaxDead            = 5
RerecoveryTimeout          = 10
EnableBans                 = 1
NoIPFailback               = 0
VerboseMemoryNames         = 0
RecdPingTimeout            = 60
RecdFailCount              = 10
LogLatencyMs               = 0
RecLockLatencyMs           = 1000
RecoveryDropAllIPs         = 120
VacuumInterval             = 10
VacuumMaxRunTime           = 120
RepackLimit                = 10000
VacuumFastPathCount        = 60
MaxQueueDropMsg            = 1000000
AllowUnhealthyDBRead       = 0
StatHistoryInterval        = 1
DeferredAttachTO           = 120
AllowClientDBAttach        = 1
FetchCollapse              = 1
HopcountMakeSticky         = 50
StickyDuration             = 600
StickyPindown              = 200
NoIPTakeover               = 0
DBRecordCountWarn          = 100000
DBRecordSizeWarn           = 10000000
DBSizeWarn                 = 100000000
PullDBPreallocation        = 10485760
LockProcessesPerDB         = 200
RecBufferSizeLimit         = 1000000
QueueBufferSize            = 1024
IPAllocAlgorithm           = 2
AllowMixedVersions         = 0
EOF

simple_test
