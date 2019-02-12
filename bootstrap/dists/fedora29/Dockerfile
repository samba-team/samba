FROM fedora:29

# we will use this image to run ci, these ENV vars are important
ENV CC="ccache gcc"

ADD bootstrap.sh /tmp/bootstrap.sh
# need root permission, do it before USER samba
RUN bash /tmp/bootstrap.sh

# make test can not work with root, so we have to create a new user
RUN useradd -m -s /bin/bash samba && \
    mkdir -p /etc/sudoers.d && \
    echo "samba ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/samba

USER samba
WORKDIR /home/samba
# samba tests rely on this
ENV USER=samba LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8