This repository contains a curated, reconstructed history of the TrueCrypt project from when it began as a
fork of Encryption for the Masses v2.0.2 in 1999 through to the TrueCrypt v7.2 release in May 2014.

The curated history of the sub-projects (code libraries) included in TrueCrypt, and TrueCrypt releases themselves,
is contained in the directory ./.METADATA/HISTORY/ in each branch. Please read

 ./.METADATA/HISTORY/README.md

for an explanation of the history meta-data.


All source-code contained in this repository is copyright its respective authors. Please see the licence details
in each branch.

This curated reconstructed history is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/.

# OVERVIEW

TrueCrypt, in source-code form, was distributed initially as .ZIP archives. V1.0 only supported
Microsoft Windows but v4.0 introduced support for Linux. At that time source-code distribution in .TAR.GZ
archives was added.

Support for Unix flavours was added later, such as Mac OSX and Solaris.

The Windows and Linux/Unix source distribtions diverged at v5.1. From then on the Windows source distribution
continued in .ZIP archives and Linux/Unix in .TAR.GZ archives.

This history was created from the source-code archives at

   https://github.com/DrWhax/truecrypt-archive

In this repository there is one branch for each version-archive file. To the extent that it was possible, I've
reconstructed the release history by basing each verion-branch on its closest ancestor - the one with
the smallest difference.

Some branches may be identical, such as some -zip and -gz branches for the same version.

Because of the diverging of the Windows and Linux/Unix branches it is difficult to construct an accurate
trunk/master history because of conflicts in the removal/addition of files for each diverging leg. Therefore
I have refrained from building the master branch until I've studied the history in more detail.

To review all the branches do:

   git branch

I have tagged the versions up to the point where the branches diverge. Further tags will depend on reconstruction
of the master history.

TJ <crypto@iam.tj>
England. U.K.

