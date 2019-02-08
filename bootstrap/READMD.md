# Samba Bootstrap

A pure python3 module with CLI to bootstrap Samba envs for multiple distributions.

## Features

- manage Samba dependencies list for multiple distributions
- render dependencies package list to boostrap shell scripts(apt, yum and dnf)
- render Vagrantfile to provision vitual machines with bootstrap scripts
- render Dockerfile to build docker images with bootstrap scripts
- build/tag/push docker images

## Supported Distributions

deb: Debian 7|8|9, Ubuntu 1404|1604|1804
rpm: CentOS 6|7, Fedora 28|29

Easy to add more.

## Usage

Render files:

    ./template.py --render

By default, files are rendered into `files` directory in current dir.

Build docker images:

    ./docker.py --build

Tag docker images:

    ./docker.py --tag --prefix registry.gitlab.com/samba-team/samba

Push docker images(you need to have permission):

    docker login
    ./docker.py --push --prefix registry.gitlab.com/samba-team/samba

the prefix defaults to `registry.gitlab.com/samba-team/samba`, and you can
override it with env var `SAMBA_DOCKER_IMAGE_NAME_PREFIX`.

## User Stories

As a gitlab-ci maintainer, I can use this tool to build the CI docker images.
I can also automate it.

As a Samba developer/tester, I can setup a Samba env very quickly.

With Docker:

    cd ~/samba
    git clean -xdf
    docker run -it -v $(pwd):/home/samba/samba samba-ubuntu1604:latest bash

With Vagrant:

    cd ./files/
    vagrant up   # start all
    vagrant up debian9  # start one
    vagrant ssh debian9
    vagrant destroy debian9  # destroy one
    vagrant destroy  # destroy all

Or a remote/cloud machine:

    scp ./files/fedora29/bootstrap.sh USER@IP:
    ssh USER@IP
    sudo bash ./bootstrap.sh

