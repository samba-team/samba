# Samba Bootstrap

A pure python3 module with CLI to bootstrap Samba envs for multiple distributions.

## Features

- manage Samba dependencies list for multiple distributions
- render dependencies package list to boostrap shell scripts(apt, yum and dnf)
- render Vagrantfile to provision vitual machines with bootstrap scripts
- render Dockerfile to build docker images with bootstrap scripts
- build/tag/push docker images

## Supported Distributions

deb: Debian 7|8|9|10, Ubuntu 1404|1604|1804
rpm: CentOS 6|7, Fedora 28|29, openSUSE Leap 15.0|15.1

Easy to add more.

## Usage

Render files:

 bootstrap/template.py --render

Files are rendered into `bootstrap/generated-dists` directory in current dir.
It also generates bootstrap/sha1sum.txt and prints out the sha1sum of the
current code/configuration.

Just calculate the sha1sum for consistency checks:

 bootstrap/template.py --sha1sum

The checksum needs to be added as `SAMBA_CI_CONTAINER_TAG` in
the toplevel .gitlab-ci.yml file.

## User Stories

As a gitlab-ci user, I can use this tool to build new CI docker images:

 After committing the result of calling `bootstrap/template.py --render`
 and updating `SAMBA_CI_CONTAINER_TAG` in .gitlab-ci.yml, you can push
 The branch to git@gitlab.com:samba-team/devel/samba.git using:

  git push -o ci.skip git@gitlab.com:samba-team/devel/samba.git ...

 The `-o ci.skip` option means gitlab won't start a pipeline
 for the just pushed branch.

 Instead you would start a custom pipeline at:

  https://gitlab.com/samba-team/devel/samba/pipelines/new

 But you need to pass `SAMBA_CI_REBUILD_IMAGES=yes` as environment
 variable. It means the pipeline runs the 'images' stage and builds
 the new container images for all supported distributions and
 uploads the images into the registry.gitlab.com/samba-team/devel/samba
 container registry.

 If you want to try to build images for the (currently) broken
 distributions, you would pass `SAMBA_CI_REBUILD_BROKEN_IMAGES=yes`
 in addition to the custom pipeline. Note the images for
 the broken distributions are just build, but not uploaded
 to the container registry. And any failures in the image
 creation is ignored. Once you managed to get success, you should
 move from `.build_image_template_force_broken` to `.build_image_template`.
 And also add a `.samba-o3-template` job for the new image
 in the main .gitlab-ci.yml file.

 Over time we'll get a lot of images pushed to the container registry.
 The approach we're using allows gitlab project maintainers to
 remove old images! But it is possible to regenerate the images
 if you have the need to run a gitlab ci pipeline based on an
 older branch.

As a Samba developer/tester, I can setup a Samba env very quickly.

With Docker:

 cd ~/samba
 git clean -xdf
 docker login
 docker pull registry.gitlab.com/samba-team/devel/samba/samba-ci-ubuntu1804:${sha1sum}
 docker run -it -v $(pwd):/home/samba/samba samba-ci-ubuntu1804:${sha1sum} bash

With podman:

  podman run -ti --cap-add=SYS_PTRACE --security-opt seccomp=unconfined registry.gitlab.com/samba-team/devel/samba/samba-ci-ubuntu1804:${sha1sum} bash

With Vagrant:

 cd bootstrap/generated-dists/
 vagrant up   # start all
 vagrant up debian9  # start one
 vagrant ssh debian9
 vagrant destroy debian9  # destroy one
 vagrant destroy  # destroy all

Or a remote/cloud machine:

 scp bootstrap/generated-dists/fedora30/bootstrap.sh USER@IP:
 ssh USER@IP
 sudo bash ./bootstrap.sh

