The Schema updates in this directory were based on information retrieved
from Microsoft's Github:

file: WindowsServerDocs/identity/ad-ds/deploy/Schema-Updates.md
project: https://github.com/MicrosoftDocs/windowsserverdocs/

./WindowsServerDocs/Schema-Updates.md is the version of the file we used (last updated
Jun 1, 2017, commit SHA f79755b75d2810b8a4).

License files (LICENSE and LICENSE-CODE) have also been included in the
./WindowsServerDocs directory for reference.

The ms_schema_markdown.py script was then used to produce the .ldf files.

However, this schema didn't work. The ./WindowsServerDocs/*.diff files are the
changes we made on top of this to get the schema working on Samba. If you are
re-generating the .ldf files, to apply the patches, use:

for p in `ls WindowsServerDocs/*.diff` ; do patch -p 1 < $p ; done

All this is handled at runtime in the provision code, so that we do
not store patched generated files in git (an alternative would have
been to patch the original markdown).
