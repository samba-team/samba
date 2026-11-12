# How to contribute a patch to Samba

Please see https://wiki.samba.org/index.php/Contribute
for detailed set-by-step instructions on how to submit a patch
for Samba via GitLab.

Samba's GitLab mirror is at https://gitlab.com/samba-team/samba

## Ownership of the contributed code

Samba is a project with distributed copyright ownership, which means
we prefer the copyright on parts of Samba to be held by individuals
rather than corporations if possible. There are historical legal
reasons for this, but one of the best ways to explain it is that it's
much easier to work with individuals who have ownership than corporate
legal departments if we ever need to make reasonable compromises with
people using and working with Samba.

We track the ownership of every part of Samba via git, our source code
control system, so we know the provenance of every piece of code that
is committed to Samba.

So if possible, if you're doing Samba changes on behalf of a company
who normally owns all the work you do please get them to assign
personal copyright ownership of your changes to you as an individual,
that makes things very easy for us to work with and avoids bringing
corporate legal departments into the picture.

If you can't do this we can still accept patches from you owned by
your employer under a standard employment contract with corporate
copyright ownership. It just requires a simple set-up process first.

We use a process very similar to the way things are done in the Linux
kernel community, so it should be very easy to get a sign off from
your corporate legal department. The only changes we've made are to
accommodate the licenses we use, which are GPLv3 and LGPLv3 (or later)
whereas the Linux kernel uses GPLv2.

The process is called signing.

## How to sign your work

Once you have permission to contribute to Samba from
your employer, simply email a copy of the following text
from your corporate email address to contributing@samba.org

------------------------------------------------------------
Samba Developer's Declaration, Version 1.0

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the appropriate
    version of the GNU General Public License; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the GNU General Public License, in the
    appropriate version; or

(c) The contribution was provided directly to me by some other
    person who certified (a) or (b) and I have not modified
    it.

(d) I understand and agree that this project and the
    contribution are public and that a record of the
    contribution (including all metadata and personal
    information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed
    consistent with the Samba Team's policies and the
    requirements of the GNU GPL where they are relevant.

(e) I am granting this work to this project under the terms of both
    the GNU General Public License and the GNU Lesser General Public
    License as published by the Free Software Foundation; either version
    3 of these Licenses, or (at the option of the project) any later
    version.

    http://www.gnu.org/licenses/gpl-3.0.html
    http://www.gnu.org/licenses/lgpl-3.0.html
------------------------------------------------------------

We will maintain a copy of that email as a record that you have the
rights to contribute code to Samba under the required licenses whilst
working for the company where the email came from.

Then when sending in a patch via the normal mechanisms described
above, add a line that states:

Signed-off-by: Random J Developer <random@developer.example.org>

using your real name and the email address you sent the original email
you used to send the Samba Developer's Declaration to us
(sorry, no pseudonyms or anonymous contributions.)

That's it ! Such code can then quite happily contain changes that have
copyright messages such as :

        (C) Example Corporation.

and can be merged into the Samba codebase in the same way as patches
from any other individual. You don't need to send in a copy of the
Samba Developer's Declaration for each patch, or inside each
patch. Just the sign-off message is all that is required once we've
received the initial email.

Have fun and happy Samba hacking !

The Samba Team.


The "Samba Developer's Declaration, Version 1.0" is:
  (C) 2011 Software Freedom Conservancy, Inc.
  (C) 2005 Open Source Development Labs, Inc.

licensed under Creative Commons Attribution-ShareAlike 4.0 License as found
at https://creativecommons.org/licenses/by-sa/4.0/legalcode and based on
"Developer's Certificate of Origin 1.1" as found at
http://web.archive.org/web/20070306195036/http://osdlab.org/newsroom/press_releases/2004/2004_05_24_dco.html

## Policy on the Use of AI Development Tools

### Preface

The Samba project recognises the broader social and environmental
concerns surrounding AI. These are important issues that we, as a
society, need to address. Allowing the use of AI tools in Samba
development is not an endorsement of every aspect of the technology or
the way it is being developed and deployed. We can make pragmatic use of
these tools while continuing to question and work towards improving
their broader impact.

### Scope

This policy describes the requirements for using AI tools when
developing and contributing to Samba. It applies to contributors who use
such tools to assist with code, tests, documentation, or other project
contributions.

### Contribution Requirements

Human interaction and communication are central to the Samba
community. They are also part of the engineering process by which we
convey design intent, establish correctness, and maintain
accountability.

AI tools can help produce code and other contributions, but they do not
replace the contributor's responsibility to understand, verify, explain,
and maintain the submitted work. Contributors are expected to engage
personally in technical discussions and take responsibility for their
contributions.

All contributions must follow the project's established policies and
processes, including:

- [How to do Samba:
  Nicely](https://wiki.samba.org/index.php/How_to_do_Samba:_Nicely)
- [Samba Contribution
  Howto](https://wiki.samba.org/index.php/Contribute)
- [Samba Developer
  Documentation](https://wiki.samba.org/index.php/Developer_Documentation)

### Copyright and Licensing

All contributions must comply with Samba's licensing requirements and
applicable project policies.

- Submissions must be suitable for inclusion under the applicable Samba
  project licences, including GPL-3.0-or-later and LGPL-3.0-or-later, as
  appropriate.
- Contributors must ensure that submitted material does not introduce
  incompatible licensing terms or improperly reproduce third-party
  material.

See [Samba's copyright
policy](https://www.samba.org/samba/devel/copyright-policy.html) for
further details.

### Developer Certification

Every contribution must satisfy Samba's requirements for the [Samba
Developer's
Declaration](https://www.samba.org/samba/devel/copyright-policy.html).

Before submitting AI-assisted work, the contributor must:
- Review and understand the submitted changes.
- Check the contribution for correctness and compliance with Samba's
  development and licensing requirements.
- Add their own `Signed-off-by` tag to certify compliance with the Samba
  Developer's Declaration.
- Accept responsibility for the contribution, including any material
  produced with AI assistance.

### Disclosure of AI Assistance

Disclose AI assistance in the merge request description when a
significant portion of the contribution was generated or substantially
rewritten by an AI tool. A brief note is sufficient; the goal is
transparency, not restriction.

