#!/usr/bin/env python3

# Copyright (C) Catalyst.Net Ltd 2019
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Manage dependencies and bootstrap environments for Samba.

Config file for packages and templates.

Update the lists in this file to require new packages in the
container images used in GitLab CI

Author: Joe Guo <joeg@catalyst.net.nz>
"""
import os
from os.path import abspath, dirname, join
HERE = abspath(dirname(__file__))
# output dir for rendered files
OUT = join(HERE, 'generated-dists')


# pkgs with same name in all packaging systems
COMMON = [
    'acl',
    'attr',
    'autoconf',
    'binutils',
    'bison',
    'ccache',
    'curl',
    'chrpath',
    'codespell',
    'flex',
    'gcc',
    'gdb',
    'git',
    'gzip',
    'hostname',
    'htop',
    'jq',
    'lcov',
    'make',
    'mold',
    'patch',
    'perl',
    'psmisc',  # for pstree in test
    'rng-tools',
    'rsync',
    'sed',
    'shfmt',
    'sudo',  # docker images has no sudo by default
    'tar',
    'tree',
    'wget',
    'cargo',
]


# define pkgs for all packaging systems in parallel
# make it easier to find missing ones
# use latest ubuntu and fedora as defaults
# deb, rpm, ...
PKGS = [
    # NAME1-dev, NAME2-devel
    ('lmdb-utils', 'lmdb'),
    ('mingw-w64', 'mingw64-gcc'),
    ('zlib1g-dev', 'zlib-devel'),
    ('landscape-common', ''), # for landscape/lib/os_release.py
    ('libbsd-dev', 'libbsd-devel'),
    ('liburing-dev', 'liburing-devel'),
    ('libarchive-dev', 'libarchive-devel'),
    ('libblkid-dev', 'libblkid-devel'),
    ('libcap-dev', 'libcap-devel'),
    ('libacl1-dev', 'libacl-devel'),
    ('libattr1-dev', 'libattr-devel'),
    ('libutf8proc-dev', 'utf8proc-devel'),
    ('libssl-dev', 'openssl-devel'),
    ('libclang-dev', 'clang-devel'),

    # libNAME1-dev, NAME2-devel
    ('libpopt-dev', 'popt-devel'),
    ('libreadline-dev', 'readline-devel'),
    ('libjansson-dev', 'jansson-devel'),
    ('liblmdb-dev', 'lmdb-devel'),
    ('libncurses5-dev', 'ncurses-devel'),
    # NOTE: Debian 7+ or Ubuntu 16.04+
    ('libsystemd-dev', 'systemd-devel'),
    ('libkrb5-dev', 'krb5-devel'),
    ('libldap2-dev', 'openldap-devel'),
    ('libcups2-dev', 'cups-devel'),
    ('libpam0g-dev', 'pam-devel'),
    ('libgpgme11-dev', 'gpgme-devel'),
    # NOTE: Debian 8+ and Ubuntu 14.04+
    ('libgnutls28-dev', 'gnutls-devel'),
    ('gnutls-bin', 'gnutls-utils'),
    ('libtasn1-bin', 'libtasn1-tools'),
    ('libtasn1-dev', 'libtasn1-devel'),
    ('', 'quota-devel'),
    ('uuid-dev', 'libuuid-devel'),
    ('libjs-jquery', ''),
    ('libavahi-common-dev', 'avahi-devel'),
    ('libdbus-1-dev', 'dbus-devel'),
    ('libpcap-dev', 'libpcap-devel'),
    ('libunwind-dev', 'libunwind-devel'),  # for back trace
    ('libglib2.0-dev', 'glib2-devel'),
    ('libicu-dev', 'libicu-devel'),
    ('heimdal-multidev', ''),
    ('libevent-dev', 'libevent-devel'),

    # NAME1, NAME2
    # for debian, locales provide locale support with language packs
    # ubuntu split language packs to language-pack-xx
    # for centos, glibc-common provide locale support with language packs
    # fedora split language packs  to glibc-langpack-xx
    ('locales', 'glibc-common'),  # required for locale
    ('language-pack-en', 'glibc-langpack-en'),  # we need en_US.UTF-8
    ('bind9utils', 'bind-utils'),
    ('dnsutils', ''),
    ('xsltproc', 'libxslt'),
    ('krb5-user', 'krb5-workstation'),
    ('krb5-config', ''),
    ('krb5-kdc', 'krb5-server'),
    ('apt-utils', 'yum-utils'),
    ('pkg-config', 'pkgconfig'),
    ('procps', 'procps-ng'),  # required for the free cmd in tests
    ('lsb-release', 'lsb-release'),  # we need lsb_release to show info
    ('', 'rpcgen'),  # required for test
    # refer: https://fedoraproject.org/wiki/Changes/SunRPCRemoval
    ('', 'libtirpc-devel'),  # for <rpc/rpc.h> header on fedora
    ('', 'rpcsvc-proto-devel'), # for <rpcsvc/rquota.h> header
    ('mawk', 'gawk'),
    ('shellcheck', 'ShellCheck'),
    ('', 'crypto-policies-scripts'),

    ('python3', 'python3'),
    ('python3-cryptography', 'python3-cryptography'),
    ('python3-dev', 'python3-devel'),
    ('python3-dbg', ''),
    ('python3-iso8601', 'python3-iso8601'),
    ('python3-gpg', 'python3-gpg'),  # defaults to ubuntu/fedora latest
    ('python3-markdown', 'python3-markdown'),
    ('python3-dnspython', 'python3-dns'),
    ('python3-pyasn1', 'python3-pyasn1'), # for krb5 tests
    ('python3-setproctitle', 'python3-setproctitle'),
    ('python3-requests', 'python3-requests'), # for cert auto enroll

    ('', 'python3-libsemanage'),
    ('', 'python3-policycoreutils'),

    # perl
    ('libparse-yapp-perl', 'perl-Parse-Yapp'),
    ('perl-modules', ''),
    ('', 'perl-FindBin'),
    ('', 'perl-Archive-Tar'),
    ('', 'perl-ExtUtils-MakeMaker'),
    ('', 'perl-Test-Base'),
    ('', 'perl-generators'),
    ('', 'perl-interpreter'),

    # fs
    ('xfslibs-dev', 'xfsprogs-devel'), # for xfs quota support
    ('', 'glusterfs-api-devel'),
    ('glusterfs-common', 'glusterfs-devel'),
    ('libcephfs-dev', 'libcephfs-devel'),

    # systemd userdb
    ('', 'libvarlink-devel'),
    ('', 'python3-varlink'),

    # misc
    # @ means group for rpm, use fedora as rpm default
    ('build-essential', '@development-tools'),
    ('debhelper', ''),
    # rpm has no pkg for docbook-xml
    ('docbook-xml', 'docbook-dtds'),
    ('docbook-xsl', 'docbook-style-xsl'),
    ('libkeyutils-dev', 'keyutils-libs-devel'),
    ('', 'which'),
    ('xz-utils', 'xz')
]


DEB_PKGS = COMMON + [pkg for pkg, _ in PKGS if pkg]
RPM_PKGS = COMMON + [pkg for _, pkg in PKGS if pkg]

GENERATED_MARKER = r"""
#
# This file is generated by 'bootstrap/template.py --render'
# See also bootstrap/config.py
#
"""


APT_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get -y update

apt-get -y install \
    {pkgs}

apt-get -y autoremove
apt-get -y autoclean
apt-get -y clean
"""


YUM_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

yum update -y
yum install -y epel-release
yum install -y yum-plugin-copr
yum copr enable -y sergiomb/SambaAD
yum update -y

yum install -y \
    {pkgs}

yum clean all

if [ ! -f /usr/bin/python3 ]; then
    ln -sf /usr/bin/python3.6 /usr/bin/python3
fi
"""

ROCKY8_DNF_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

yum update -y
yum install -y dnf-plugins-core
yum install -y epel-release
yum install -y centos-release-ceph-pacific

sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Ceph-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Ceph-*
sed -i 's/$contentdir/centos/g' /etc/yum.repos.d/CentOS-Ceph-*

yum -v repolist all
yum config-manager --set-enabled powertools -y

yum update -y

yum install -y \
    --setopt=install_weak_deps=False \
    --setopt=centos-ceph-pacific.module_hotfixes=true \
    {pkgs}

yum clean all
"""

CENTOS9S_DNF_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

dnf update -y
dnf install -y dnf-plugins-core
dnf install -y epel-release
dnf install -y centos-release-gluster9

dnf -v repolist all
dnf config-manager --set-enabled crb -y

dnf update -y

dnf install -y \
    --setopt=install_weak_deps=False \
    {pkgs}

dnf clean all
"""

DNF_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

dnf update -y

dnf install -y \
    --setopt=install_weak_deps=False \
    {pkgs}

dnf clean all

update-crypto-policies --set DEFAULT:AD-SUPPORT
"""

DNF_BOOTSTRAP_MIT = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

dnf update -y
dnf install -y dnf-plugins-core
dnf copr -y enable abbra/krb5-test
dnf update -y

dnf install -y \
    --setopt=install_weak_deps=False \
    {pkgs}

dnf clean all
"""

ZYPPER_BOOTSTRAP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

zypper --non-interactive refresh
zypper --non-interactive update
zypper --non-interactive install \
    --no-recommends \
    system-user-nobody \
    {pkgs}

zypper --non-interactive clean

if [ -f /usr/lib/mit/bin/krb5-config ]; then
    ln -sf /usr/lib/mit/bin/krb5-config /usr/bin/krb5-config
fi
"""

# A generic shell script to setup locale
LOCALE_SETUP = r"""
#!/bin/bash
{GENERATED_MARKER}
set -xueo pipefail

# refer to /usr/share/i18n/locales
INPUTFILE=en_US
# refer to /usr/share/i18n/charmaps
CHARMAP=UTF-8
# locale to generate in /usr/lib/locale
# glibc/localedef will normalize UTF-8 to utf8, follow the naming style
LOCALE=$INPUTFILE.utf8

# if locale is already correct, exit
( locale | grep LC_ALL | grep -i $LOCALE ) && exit 0

# if locale not available, generate locale into /usr/lib/locale
if ! ( locale --all-locales | grep -i $LOCALE )
then
    # no-archive means create its own dir
    localedef --inputfile $INPUTFILE --charmap $CHARMAP --no-archive $LOCALE
fi

# update locale conf and global env file
# set both LC_ALL and LANG for safe

# update conf for Debian family
FILE=/etc/default/locale
if [ -f $FILE ]
then
    echo LC_ALL="$LOCALE" > $FILE
    echo LANG="$LOCALE" >> $FILE
fi

# update conf for RedHat family
FILE=/etc/locale.conf
if [ -f $FILE ]
then
    # LC_ALL is not valid in this file, set LANG only
    echo LANG="$LOCALE" > $FILE
fi

# update global env file
FILE=/etc/environment
if [ -f $FILE ]
then
    # append LC_ALL if not exist
    grep LC_ALL $FILE || echo LC_ALL="$LOCALE" >> $FILE
    # append LANG if not exist
    grep LANG $FILE || echo LANG="$LOCALE" >> $FILE
fi
"""


DOCKERFILE = r"""
{GENERATED_MARKER}
FROM {docker_image}

# pass in with --build-arg while build
ARG SHA1SUM
RUN [ -n $SHA1SUM ] && echo $SHA1SUM > /sha1sum.txt

ADD *.sh /tmp/
# need root permission, do it before USER samba
RUN /tmp/bootstrap.sh && /tmp/locale.sh

# if ld.gold exists, force link it to ld
RUN set -x; ! LD_GOLD=$(which ld.gold) || {{ LD=$(which ld) && ln -sf $LD_GOLD $LD && test -x $LD && echo "$LD is now $LD_GOLD"; }}
# if ld.mold exists, force link it to ld (prefer mold over gold! ;-)
RUN set -x; ! LD_MOLD=$(which ld.mold) || {{ LD=$(which ld) && ln -sf $LD_MOLD $LD && test -x $LD && echo "$LD is now $LD_MOLD"; }}

# make test can not work with root, so we have to create a new user
RUN useradd -m -U -s /bin/bash samba && \
    mkdir -p /etc/sudoers.d && \
    echo "samba ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/samba

USER samba
WORKDIR /home/samba
# samba tests rely on this
ENV USER=samba LC_ALL=en_US.utf8 LANG=en_US.utf8 LANGUAGE=en_US
"""

# Vagrantfile snippet for each dist
VAGRANTFILE_SNIPPET = r"""
    config.vm.define "{name}" do |v|
        v.vm.box = "{vagrant_box}"
        v.vm.hostname = "{name}"
        v.vm.provision :shell, path: "{name}/bootstrap.sh"
        v.vm.provision :shell, path: "{name}/locale.sh"
    end
"""

# global Vagrantfile with snippets for all dists
VAGRANTFILE_GLOBAL = r"""
{GENERATED_MARKER}

Vagrant.configure("2") do |config|
    config.ssh.insert_key = false

{vagrantfile_snippets}

end
"""

DEB_DISTS = {
    'debian11': {
        'docker_image': 'debian:11-slim',
        'vagrant_box': 'debian/bullseye64',
        'replace': {
            'language-pack-en': '',   # included in locales
            'shfmt': '',
            'cargo': '', # included cargo is broken
            'landscape-common': '',
            'mold': '',
        }
    },
    'debian11-32bit': {
        'docker_image': 'debian:11-slim',  # specify the platform in .gitlab-ci.yaml
        'vagrant_box': 'debian/bullseye32',
        'replace': {
            'language-pack-en': '',   # included in locales
            'shfmt': '',
            'cargo': '', # included cargo is broken
            'landscape-common': '',
            'mold': '',
        }
    },
    'debian12': {
        'docker_image': 'debian:12-slim',
        'vagrant_box': 'debian/bookworm64',
        'replace': {
            'language-pack-en': '',   # included in locales
            'cargo': '', # included cargo is broken
            'landscape-common': '',
        }
    },
    'debian12-32bit': {
        'docker_image': 'registry-1.docker.io/i386/debian:12-slim',
        'vagrant_box': 'debian/bookworm32',
        'replace': {
            'language-pack-en': '',   # included in locales
            'cargo': '', # included cargo is broken
            'landscape-common': '',
        }
    },
    'ubuntu2004': {
        'docker_image': 'ubuntu:20.04',
        'vagrant_box': 'ubuntu/focal64',
        'replace': {
            'liburing-dev': '',   # not available
            'shfmt': '',
            'mold': '',
        }
    },
    'ubuntu2204': {
        'docker_image': 'ubuntu:22.04',
        'vagrant_box': 'ubuntu/jammy64',
        'replace': {
        },
    },
    'ubuntu2404': {
        'docker_image': 'ubuntu:24.04',
        'vagrant_box': 'ubuntu/noble64',
        'replace': {
        },
    },
}


RPM_DISTS = {
    'rocky8': {
        'docker_image': 'docker.io/library/rockylinux:8',
        'vagrant_box': 'rocky/8',
        'bootstrap': ROCKY8_DNF_BOOTSTRAP,
        'replace': {
            'lsb-release': 'redhat-lsb',
            '@development-tools': '"@Development Tools"',  # add quotes
            'lcov': '', # does not exist
            'perl-JSON-Parse': '', # does not exist?
            'perl-Test-Base': 'perl-Test-Simple',
            'perl-FindBin': '',
            'liburing-devel': '', # not available yet, Add me back, once available!
            'mold': '',
            'ShellCheck': '',
            'shfmt': '',
            'codespell': '',
            'libvarlink-devel': '', # not available
        }
    },
    'centos9s': {
        'docker_image': 'quay.io/centos/centos:stream9',
        'vagrant_box': 'centos/stream9',
        'bootstrap': CENTOS9S_DNF_BOOTSTRAP,
        'replace': {
            'lsb-release': 'lsb_release',
            '@development-tools': '"@Development Tools"',  # add quotes
            'lcov': '', # does not exist
            'perl-JSON-Parse': '', # does not exist?
            'perl-Test-Base': 'perl-Test-Simple',
            'perl-FindBin': '',
            'mold': '',
            'ShellCheck': '',
            'shfmt': '',
            'codespell': '',
            'libcephfs-devel': '',  # not available anymore
            'curl': '',  # Use installed curl-minimal
            'libvarlink-devel': '', # not available
            'python3-varlink': '', # not available
        }
    },
    'fedora42': {
        'docker_image': 'quay.io/fedora/fedora-minimal:42',
        'vagrant_box': 'fedora/42-cloud-base',
        'bootstrap': DNF_BOOTSTRAP,
        'replace': {
            'lsb-release': 'redhat-lsb',
            'perl-FindBin': '',
            'python3-iso8601': 'python3-dateutil',
        }
    },
    'opensuse155': {
        'docker_image': 'opensuse/leap:15.5',
        'vagrant_box': 'opensuse/openSUSE-15.5-x86_64',
        'bootstrap': ZYPPER_BOOTSTRAP,
        'replace': {
            '@development-tools': '',
            'dbus-devel': 'dbus-1-devel',
            'docbook-style-xsl': 'docbook-xsl-stylesheets',
            'glibc-common': 'glibc-locale',
            'glibc-locale-source': 'glibc-i18ndata',
            'glibc-langpack-en': '',
            'jansson-devel': 'libjansson-devel',
            'keyutils-libs-devel': 'keyutils-devel',
            'krb5-workstation': 'krb5-client',
            'python3-libsemanage': 'python3-semanage',
            'openldap-devel': 'openldap2-devel',
            'perl-Archive-Tar': 'perl-Archive-Tar-Wrapper',
            'perl-JSON-Parse': 'perl-JSON-XS',
            'perl-generators': '',
            'perl-interpreter': '',
            'perl-FindBin': '',
            'procps-ng': 'procps',
            'python3-iso8601': 'python3-python-dateutil',
            'python3-dns': 'python3-dnspython',
            'python3-markdown': 'python3-Markdown',
            'quota-devel': '',
            'glusterfs-api-devel': '',
            'gnutls-utils': 'gnutls',
            'libtasn1-tools': '', # asn1Parser is part of libtasn1
            'mold': '',
            'shfmt': '',
            'yum-utils': '',
            'libvarlink-devel': '', # not available
        }
    }
}


DEB_FAMILY = {
    'name': 'deb',
    'pkgs': DEB_PKGS,
    'bootstrap': APT_BOOTSTRAP,  # family default
    'dists': DEB_DISTS,
}


RPM_FAMILY = {
    'name': 'rpm',
    'pkgs': RPM_PKGS,
    'bootstrap': YUM_BOOTSTRAP,  # family default
    'dists': RPM_DISTS,
}


YML_HEADER = r"""
---
packages:
"""


def expand_family_dists(family):
    dists = {}
    for name, config in family['dists'].items():
        config = config.copy()
        config['name'] = name
        config['home'] = join(OUT, name)
        config['family'] = family['name']
        config['GENERATED_MARKER'] = GENERATED_MARKER

        # replace dist specific pkgs
        replace = config.get('replace', {})
        pkgs = []
        for pkg in family['pkgs']:
            pkg = replace.get(pkg, pkg)  # replace if exists or get self
            if pkg:
                pkgs.append(pkg)
        pkgs.sort()

        lines = ['  - {}'.format(pkg) for pkg in pkgs]
        config['packages.yml'] = YML_HEADER.lstrip() + os.linesep.join(lines)

        sep = ' \\' + os.linesep + '    '
        config['pkgs'] = sep.join(pkgs)

        # get dist bootstrap template or fall back to family default
        bootstrap_template = config.get('bootstrap', family['bootstrap'])
        config['bootstrap.sh'] = bootstrap_template.format(**config).strip()
        config['locale.sh'] = LOCALE_SETUP.format(**config).strip()

        config['Dockerfile'] = DOCKERFILE.format(**config).strip()
        # keep the indent, no strip
        config['vagrantfile_snippet'] = VAGRANTFILE_SNIPPET.format(**config)

        dists[name] = config
    return dists


# expanded config for dists
DEB_DISTS_EXP = expand_family_dists(DEB_FAMILY)
RPM_DISTS_EXP = expand_family_dists(RPM_FAMILY)

# assemble all together
DISTS = {}
DISTS.update(DEB_DISTS_EXP)
DISTS.update(RPM_DISTS_EXP)


def render_vagrantfile(dists):
    """
    Render all snippets for each dist into global Vagrantfile.

    Vagrant supports multiple vms in one Vagrantfile.
    This make it easier to manage the fleet, e.g:

    start all: vagrant up
    start one: vagrant up ubuntu2404

    All other commands apply to above syntax, e.g.: status, destroy, provision
    """
    # sort dists by name and put all vagrantfile snippets together
    snippets = [
        dists[dist]['vagrantfile_snippet']
        for dist in sorted(dists.keys())]

    return VAGRANTFILE_GLOBAL.format(
            vagrantfile_snippets=''.join(snippets),
            GENERATED_MARKER=GENERATED_MARKER
            )


VAGRANTFILE = render_vagrantfile(DISTS)


# data we need to expose
__all__ = ['DISTS', 'VAGRANTFILE', 'OUT']
