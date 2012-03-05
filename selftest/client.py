#!/usr/bin/python -u
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import shutil

def write_clientconf(conffile, clientdir, vars):
    if not os.path.isdir(clientdir):
        os.mkdir(clientdir, 0777)

    for n in ["private", "lockdir", "statedir", "cachedir"]:
        p = os.path.join(clientdir, n)
        if os.path.isdir(p):
            shutil.rmtree(p)
        os.mkdir(p, 0777)

    # this is ugly, but the ncalrpcdir needs exactly 0755
    # otherwise tests fail.
    mask = os.umask(0022)

    for n in ["ncalrpcdir", "ncalrpcdir/np"]:
        p = os.path.join(clientdir, n)
        if os.path.isdir(p):
            shutil.rmtree(p)
        os.mkdir(p, 0777)
    os.umask(mask)

    settings = {
        "netbios name": "client",
        "private dir": os.path.join(clientdir, "private"),
        "lock dir": os.path.join(clientdir, "lockdir"),
        "state directory": os.path.join(clientdir, "statedir"),
        "cache directory": os.path.join(clientdir, "cachedir"),
        "ncalrpc dir": os.path.join(clientdir, "ncalrpcdir"),
        "name resolve order": "file bcast",
        "panic action": os.path.join(os.path.dirname(__file__), "gdb_backtrace \%d"),
        "max xmit": "32K",
        "notify:inotify": "false",
        "ldb:nosync": "true",
        "system:anonymous": "true",
        "client lanman auth": "Yes",
        "log level": "1",
        "torture:basedir": clientdir,
        # We don't want to pass our self-tests if the PAC code is wrong
        "gensec:require_pac": "true",
        "resolv:host file": os.path.join(prefix_abs, "dns_host_file"),
        # We don't want to run 'speed' tests for very long
        "torture:timelimit": "1",
        }

    if "DOMAIN" in vars:
        settings["workgroup"] = vars["DOMAIN"]
    if "REALM" in vars:
        settings["realm"] = vars["REALM"]
    if opts.socket_wrapper:
        settings["interfaces"] = interfaces

    f = open(conffile, 'w')
    try:
        f.write("[global]\n")
        for item in settings.iteritems():
            f.write("\t%s = %s\n" % item)
    finally:
        f.close()


