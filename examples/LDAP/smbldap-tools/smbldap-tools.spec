# $Source: /data/src/mirror/cvs/samba/examples/LDAP/smbldap-tools/smbldap-tools.spec,v $
%define version	0.8
%define release	1
%define name 	smbldap-tools
%define realname  smbldap-tools

Summary:	User & Group administration tools for Samba-OpenLDAP
Name: 		%{name}
version: 	%{version}
Release: 	%{release}
Group: 		System Environment/Base
License: 	GPL

Vendor:		IDEALX S.A.S.
URL:		http://samba.IDEALX.org/
Packager:	Jerome Tournier <jerome.tournier@IDEALX.com>
Source0: 	smbldap-groupadd.pl
Source1:	smbldap-groupdel.pl
Source2:	smbldap-groupmod.pl
Source3:	smbldap-groupshow.pl
Source4:	smbldap-passwd.pl
Source5:	smbldap-useradd.pl
Source6:	smbldap-userdel.pl
Source7:	smbldap-usermod.pl
Source8:	smbldap-usershow.pl
Source9:	smbldap_conf.pm
Source10:	smbldap_tools.pm
Source11:	CONTRIBUTORS
Source12:	COPYING
Source13:	ChangeLog
Source14:	FILES
Source15:	README
Source16:	TODO
Source17:       mkntpwd.tar.gz
Source18:	smbldap-populate.pl
Source19:	smbldap-migrate-accounts.pl
Source20:	smbldap-migrate-groups.pl
Source21:	INFRA
BuildRoot: 	/%{_tmppath}/%{name}
Prefix: /usr/local
BuildRequires: perl >= 5.6
Requires: perl >= 5.6, openldap, openldap-clients, samba

%description
In settings with OpenLDAP and Samba-LDAP servers, this collection is
useful to add, modify and delete users and groups, and to change
Unix and Samba passwords. In those context they replace the system
tools to manage users, groups and passwords.

%prep

%setup -c -T

%build
tar zxvf %{SOURCE17}
cd mkntpwd
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{prefix}/sbin
mkdir -p $RPM_BUILD_ROOT/%{prefix}/share
mkdir -p $RPM_BUILD_ROOT/usr/share/doc
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools

cd mkntpwd ; make PREFIX=$RPM_BUILD_ROOT/%{prefix} install

install -m 550 %{SOURCE0} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-groupadd.pl
install -m 550 %{SOURCE1} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-groupdel.pl
install -m 550 %{SOURCE2} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-groupmod.pl
install -m 555 %{SOURCE3} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-groupshow.pl
install -m 555 %{SOURCE4} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-passwd.pl
install -m 550 %{SOURCE5} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-useradd.pl
install -m 550 %{SOURCE6} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-userdel.pl
install -m 550 %{SOURCE7} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-usermod.pl
install -m 555 %{SOURCE8} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-usershow.pl
install -m 550 %{SOURCE18} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-populate.pl
install -m 751 %{SOURCE9} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap_conf.pm
install -m 555 %{SOURCE10} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap_tools.pm
install -m 550 %{SOURCE19} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-migrate-accounts.pl
install -m 550 %{SOURCE20} $RPM_BUILD_ROOT/%{prefix}/sbin/smbldap-migrate-groups.pl

install -m 644 %{SOURCE11} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/CONTRIBUTORS
install -m 644 %{SOURCE12} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/COPYING
install -m 644 %{SOURCE13} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/ChangeLog
install -m 644 %{SOURCE14} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/FILES
install -m 644 %{SOURCE15} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/README
install -m 644 %{SOURCE16} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/TODO
install -m 644 %{SOURCE21} $RPM_BUILD_ROOT/usr/share/doc/smbldap-tools/INFRA

%clean
rm -rf $RPM_BUILD_ROOT

%post
ln -sf %{prefix}/sbin/smbldap_tools.pm /usr/lib/perl5/site_perl/smbldap_tools.pm
ln -sf %{prefix}/sbin/smbldap_conf.pm /usr/lib/perl5/site_perl/smbldap_conf.pm
chgrp 512 %{prefix}/sbin/smbldap-useradd.pl %{prefix}/sbin/smbldap_conf.pm || echo "An error occured while changing groups of smbldap-useradd.pl and smbldap_conf.pm in /usr/local/sbin. For proper operations, please ensure that they have the same posix group as the Samba domain administrator if there's a local Samba PDC."
perl -i -pe 's/_SLAVELDAP_/localhost/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_MASTERLDAP_/localhost/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_SUFFIX_/dc=IDEALX,dc=org/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_USERS_/Users/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_COMPUTERS_/Computers/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_GROUPS_/Groups/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_LOGINSHELL_/\/bin\/bash/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_HOMEPREFIX_/\/home\//' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_BINDDN_/cn=Manager,\$suffix/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_BINDPW_/secret/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_PDCNAME_/PDC-SRV/' %{prefix}/sbin/smbldap_conf.pm
perl -i -pe 's/_HOMEDRIVE_/H/' %{prefix}/sbin/smbldap_conf.pm

# FIXME: links should not be removed on upgrade
#%postun
#if [ $1 = 0 ] ; then
#  rm -f /usr/lib/perl5/site_perl/smbldap_tools.pm
#  rm -f /usr/lib/perl5/site_perl/smbldap_conf.pm
#fi

%files
%defattr(-,root,root)
%{prefix}/sbin/*.pl
%{prefix}/sbin/smbldap_tools.pm
%config %{prefix}/sbin/smbldap_conf.pm
%{prefix}/sbin/mkntpwd
%doc /usr/share/doc/%{name}/


%changelog
* Fri Aug 22 2003 Jerome Tournier <jerome.tournier@idealx.com> 0.8-1
- support for Samba3.0

* Thu Sep 26 2002 Gérald Macinenti <gmacinenti@IDEALX.com> 0.7-2
- top and account objectclasses replaced by InetOrgPerson

* Sat Jun  1 2002 Olivier Lemaire <olem@IDEALX.com> 0.7-1
- some bugfixes about smbldap-populate
- bugfixed the smbpasswd call in smbldap-useradd
- cleaned up the smbldap_conf
- more documentation

* Tue Apr 30 2002 Brad Langhorst <brad@langhorst.com> 0.6-2
- changed requires samba-common to samba
- replaced /usr/local with %{prefix} to allow relocation

* Tue Feb 5 2002 David Le Corfec <dlc@IDEALX.com> 0.6-1
- v0.6

* Mon Feb 4 2002 David Le Corfec <dlc@IDEALX.com> 0.5-1
- v0.5

* Mon Jan 14 2002 David Le Corfec <dlc@IDEALX.com> 0.3-4
- internal changes
- should upgrade smoothly from now on

* Mon Jan 14 2002 David Le Corfec <dlc@IDEALX.com> 0.2-1
- added migration scripts

* Fri Dec 28 2001 David Le Corfec <dlc@IDEALX.com> 0.1-5
- numeric group for chmod

* Thu Dec 27 2001 David Le Corfec <dlc@IDEALX.com> 0.1-4
- misc bugfixes

* Mon Dec 18 2001 David Le Corfec <dlc@IDEALX.com> 0.1-3
- changed files attrs for domain admins to add users
- added smbldap-populate.pl

* Fri Dec 14 2001 David Le Corfec <dlc@IDEALX.com>
- added mkntpwd

* Wed Dec 12 2001 Olivier Lemaire <olivier.lemaire@IDEALX.com>
- Spec file was generated, and tested atomically.
