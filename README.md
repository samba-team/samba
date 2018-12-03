About Samba
===========

Samba is the standard Windows interoperability suite of
programs for Linux and Unix.
Samba is Free Software licensed under the GNU General Public License and
the Samba project is a member of the Software Freedom Conservancy.
Since 1992, Samba has provided secure, stable and fast file and print services
for all clients using the SMB/CIFS protocol, such as all versions of DOS
and Windows, OS/2, Linux and many others.
Samba is an important component to seamlessly integrate Linux/Unix Servers and
Desktops into Active Directory environments. It can function both as a
domain controller or as a regular domain member.


NOTE: Installation instructions may be found
      for the file/print server and domain member in:
      docs/htmldocs/Samba3-HOWTO/install.html

For the AD DC implementation a full HOWTO is provided at:
      https://wiki.samba.org/index.php/Samba4/HOWTO

Community guidelines can be read at:
      https://wiki.samba.org/index.php/How_to_do_Samba:_Nicely

This software is freely distributable under the GNU public license, a
copy of which you should have received with this software (in a file
called COPYING).



CONTRIBUTIONS
=============

1. To contribute via GitLab
  - fork the official Samba team repository on GitLab
      * see https://gitlab.com/samba-team/samba
  - become familiar with the coding standards as described in README.Coding
  - make sure you read the Samba copyright policy
      * see https://www.samba.org/samba/devel/copyright-policy.html
  - create a feature branch
  - make changes
  - when committing, be sure to add signed-off-by tags
      * see https://wiki.samba.org/index.php/CodeReview#commit_message_tags
  - send a merge request for your branch through GitLab
  - this will send an email to everyone registered on GitLab
  - discussion happens on the samba-technical mailing list as described below
  - more info on using Git for Samba development can be found on the Samba Wiki
      * see https://wiki.samba.org/index.php/Using_Git_for_Samba_Development

2. If you want to contribute to the development of the software then
please join the mailing list. The Samba team accepts patches
(preferably in "diff -u" format, see https://www.samba.org/samba/devel/
for more details) and are always glad to receive feedback or
suggestions to the address samba@lists.samba.org.  More information
on the various Samba mailing lists can be found at https://lists.samba.org/.

You can also get the Samba sourcecode straight from the git repository - see
https://wiki.samba.org/index.php/Using_Git_for_Samba_Development.

If you like a particular feature then look through the git change-log
(on the web at https://gitweb.samba.org/?p=samba.git;a=summary) and see
who added it, then send them an email.

Remember that free software of this kind lives or dies by the response
we get. If no one tells us they like it then we'll probably move onto
something else.


MORE INFO
=========

DOCUMENTATION
-------------

There is quite a bit of documentation included with the package,
including man pages, and lots of .html files with hints and useful
info. This is also available from the webpage. There is a growing
collection of information under docs/.

A list of Samba documentation in languages other than English is
available on the webpage.

If you would like to help with the documentation, please coordinate
on the samba@samba.org mailing list.  See the next section for details
on subscribing to samba mailing lists.


MAILING LIST
------------

Please do NOT send subscription/unsubscription requests to the lists!

There is a mailing list for discussion of Samba.  For details go to
<https://lists.samba.org/> or send mail to <samba-subscribe@lists.samba.org>

There is also an announcement mailing list where new versions are
announced.  To subscribe go to <https://lists.samba.org/> or send mail
to <samba-announce-subscribe@lists.samba.org>.  All announcements also
go to the samba list, so you only need to be on one.

For details of other Samba mailing lists and for access to archives, see
<https://lists.samba.org/>


MAILING LIST ETIQUETTE
----------------------

A few tips when submitting to this or any mailing list.

1. Make your subject short and descriptive. Avoid the words "help" or
   "Samba" in the subject. The readers of this list already know that
   a) you need help, and b) you are writing about samba (of course,
   you may need to distinguish between Samba PDC and other file
   sharing software). Avoid phrases such as "what is" and "how do
   i". Some good subject lines might look like "Slow response with
   Excel files" or "Migrating from Samba PDC to NT PDC".

2. If you include the original message in your reply, trim it so that
   only the relevant lines, enough to establish context, are
   included. Chances are (since this is a mailing list) we've already
   read the original message.

3. Trim irrelevant headers from the original message in your
   reply. All we need to see is a) From, b) Date, and c) Subject. We
   don't even really need the Subject, if you haven't changed
   it. Better yet is to just preface the original message with "On
   [date] [someone] wrote:".

4. Please don't reply to or argue about spam, spam filters or viruses
   on any Samba lists. We do have a spam filtering system that is
   working quite well thank you very much but occasionally unwanted
   messages slip through. Deal with it.

5. Never say "Me too." It doesn't help anyone solve the
   problem. Instead, if you ARE having the same problem, give more
   information. Have you seen something that the other writer hasn't
   mentioned, which may be helpful?

6. If you ask about a problem, then come up with the solution on your
   own or through another source, by all means post it. Someone else
   may have the same problem and is waiting for an answer, but never
   hears of it.

7. Give as much *relevant* information as possible such as Samba
   release number, OS, kernel version, etc...

8. RTFM. Google.


WEBSITE
-------

A Samba website has been setup with lots of useful info. Connect to:

https://www.samba.org/

As well as general information and documentation, this also has searchable
archives of the mailing list and links to other useful resources such as
the wiki.
