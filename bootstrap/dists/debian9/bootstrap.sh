#!/bin/bash
set -xueo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get -y update

apt-get -y install \
    apt-utils \
    attr \
    autoconf \
    bind9 \
    bind9utils \
    binutils \
    bison \
    build-essential \
    ccache \
    curl \
    debhelper \
    dnsutils \
    docbook-xml \
    docbook-xsl \
    flex \
    gcc \
    gdb \
    git \
    krb5-kdc \
    libacl1-dev \
    libaio-dev \
    libarchive-dev \
    libattr1-dev \
    libblkid-dev \
    libbsd-dev \
    libcap-dev \
    libcups2-dev \
    libdbus-1-dev \
    libgnutls28-dev \
    libgpgme11-dev \
    libjansson-dev \
    libjson-perl \
    libkrb5-dev \
    libldap2-dev \
    liblmdb-dev \
    libncurses5-dev \
    libpam0g-dev \
    libparse-yapp-perl \
    libpopt-dev \
    libreadline-dev \
    libsystemd-dev \
    libxml2-dev \
    lmdb-utils \
    locales \
    locate \
    lsb-core \
    make \
    nettle-dev \
    perl \
    perl-modules \
    pkg-config \
    procps \
    psmisc \
    python-crypto \
    python-dev \
    python-dnspython \
    python-gpg \
    python-markdown \
    python3-crypto \
    python3-dev \
    python3-dnspython \
    python3-gpg \
    python3-markdown \
    sudo \
    vim \
    wget \
    xsltproc \
    zlib1g-dev

apt-get -y autoremove
apt-get -y autoclean
apt-get -y clean

# uncomment locale
# this file doesn't exist on ubuntu1404 even locales installed
if [ -f /etc/locale.gen ]; then
    sed -i '/^#\s*en_US.UTF-8 UTF-8/s/^#\s*//' /etc/locale.gen
fi

locale-gen

# update /etc/default/locale
update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8

# set both for safe
echo LC_ALL="en_US.UTF-8" >> /etc/environment
echo LANG="en_US.UTF-8" >> /etc/environment