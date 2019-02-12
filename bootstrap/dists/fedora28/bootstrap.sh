#!/bin/bash
set -xueo pipefail

dnf -y -q update

dnf -y -q --verbose install \
    @development-tools \
    attr \
    autoconf \
    bind \
    bind-utils \
    binutils \
    bison \
    ccache \
    cups-devel \
    curl \
    dbus-devel \
    docbook-dtds \
    docbook-style-xsl \
    gcc \
    gdb \
    git \
    glibc-common \
    glibc-langpack-en \
    glibc-locale-source \
    gnutls-devel \
    gpgme-devel \
    jansson-devel \
    keyutils-libs-devel \
    krb5-devel \
    krb5-workstation \
    libacl-devel \
    libaio-devel \
    libarchive-devel \
    libattr-devel \
    libblkid-devel \
    libbsd-devel \
    libnsl2-devel \
    libpcap-devel \
    libsemanage-python \
    libtirpc-devel \
    libxml2-devel \
    libxslt \
    lmdb-devel \
    lmdb-devel \
    make \
    mlocate \
    ncurses-devel \
    nettle-devel \
    openldap-devel \
    pam-devel \
    perl \
    perl-ExtUtils-MakeMaker \
    perl-Parse-Yapp \
    perl-Test-Base \
    pkgconfig \
    policycoreutils-python \
    popt-devel \
    procps-ng \
    psmisc \
    python-crypto \
    python-devel \
    python-dns \
    python-markdown \
    python2-gpg \
    python3-crypto \
    python3-devel \
    python3-dns \
    python3-gpg \
    python3-markdown \
    readline-devel \
    redhat-lsb \
    rpcgen \
    sudo \
    systemd-devel \
    vim \
    wget \
    yum-utils \
    zlib-devel

dnf clean all

# gen locale
localedef -c -i en_US -f UTF-8 en_US.UTF-8

# no update-locale, diy
# LC_ALL is not valid in this file
echo LANG="en_US.UTF-8" > /etc/locale.conf

# set both for safe
echo LC_ALL="en_US.UTF-8" >> /etc/environment
echo LANG="en_US.UTF-8" >> /etc/environment