The following files in the WindowsServerDocs folder have been sourced from a
Microsoft Github repository.

project: https://github.com/MicrosoftDocs/windowsserverdocs/

License files (LICENSE and LICENSE-CODE) have also been included in the
./WindowsServerDocs directory for reference.


===============================================================================

The Schema updates file is taken from this repository:

file: WindowsServerDocs/identity/ad-ds/deploy/Schema-Updates.md

./WindowsServerDocs/Schema-Updates.md is our current version of the file
(last updated Jun 1, 2017, commit SHA f79755b75d2810b8a4).

The ms_schema_markdown.py script was then used to produce the .ldf files.

However, this schema didn't work. The ./WindowsServerDocs/*.diff files are the
changes we made on top of this to get the schema working on Samba. If you are
re-generating the .ldf files, to apply the patches, use:

for p in `ls WindowsServerDocs/*.diff` ; do patch -p 1 < $p ; done

All this is handled at runtime in the provision code, so that we do
not store patched generated files in git (an alternative would have
been to patch the original markdown).


===============================================================================

The Forest Wide updates file is taken from this repository:

file: WindowsServerDocs/identity/ad-ds/deploy/RODC/Forest-Wide-Updates.md

./WindowsServerDocs/Forest-Wide-Updates.md is our current version of the file
(last updated Dec 15, 2017, commit SHA f209fb9101ee87107).

The ms_forest_updates_markdown.py script is used to extract the add portions of
the updates. The rest are handled manually in forest_updates.py by interpreting
this documentation (as they are not as well-structured).
