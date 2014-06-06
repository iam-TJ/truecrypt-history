How to build Encryption for the Masses A Developers Guide
=========================================================

Paul Le Roux

Copyright (C) 1998-2000 Paul Le Roux. All Rights Reserved.

1. Introduction
===============

Welcome to the source distribution of E4M. This document briefly
describes how to build E4M.

Firstly E4M does not use the build tool supplied by Microsoft in the
NT DDK.

E4M uses normal makefiles to build everything.

Extract the files from the zip archive, with "use directories" set on.
The source zip contains long names so don't use an older pkunzip.

For the rest of this document I will assume you installed it into
\e4m, but this can be any directory. All paths in the code, and the
makefiles are relative.

The commandline makefiles are the only supported method of building
E4M.

IDE project files for the Visual C++ 5.0 environment are provided as
part of the source package, but they are unsupported. These are in the
e4m\ide directory.

The reference compiler for Windows builds is Visual C++ 5.0 (no
service packs).

This is the compiler that the shipping product is built under.

2. What you will need
=====================

1.   Visual C++ 4.x, 5.0, 6.0 or later

2.   MASM 6.11c

3.   NT DDK

4.   Windows 95 DDK

3. Setup the DDK paths
======================

In the device driver makefiles, change the variable DDK to the full
path of your ddk directories for both the Windows 9x driver, and the
NT driver.

4. If you plan to debug the product
===================================

1.   Two computers and a serial cable (laplink cable)

2.   The Win32 SDK, or WinDbg alone, which can be downloaded from
     Microsoft

3.   The checked build of Widows NT installed on the second computer

4.   For Windows 9x SoftIce 3.24 or later (but don't use the /zi
     flag).

5. If you want to modify the help files
=======================================

1.   SDF http://www.mincom.com/mtr/sdf/resources/index.html

2.   any Microsoft help compiler

3.   any text editor

Note: The Debug format changed between VC4.x and VC5.0. To debug using
VC5.0 or later you must download a new WinDbg from Microsoft. With an
older VC4.x, try the WinDbg from an old Win32 SDK CD.

6. Verifying that you have genuine source code
==============================================

Follow the instructions given in the E4M help file or in the online
documentation for verifying the main program. The source is verified
the same way.

7. Building the drivers
=======================

1.   open up a DOS prompt

2.   change to the C drive

3.   cd to \e4m\ntdriver  or \e4m\windriver

4.   run "\progra~1\devstudio\vc\bin\vcvars32.bat" or "vcvars32 x86"
     for VC4.x this sets up the search path's for your compiler

5.   run "nmake" or "nmake RELEASE=1"

You should end up with e4mnt4.sys in the ntdriver directory.

or e4m9x.vxd in the windriver directory.

8. Building volmount, voltest etc
=================================

1.   open up a DOS prompt

2.   change to the C drive

3.   cd to \e4m\volmount, volformat etc

4.   run "\progra~1\devstudio\vc\bin\vcvars32.bat" or "vcvars32 x86"

5.   run "nmake" or "nmake RELEASE=1"

9. Setting up the registry entries for the driver
=================================================

Don't try this by hand, just install the driver from the binary
distribution, then overwrite it with the rebuilt driver.

10. Mkproto - automatically generating function prototypes
==========================================================

All the function prototypes in E4M (except those in crypto\) are
generated using the mkproto tool which you can download from
http://www.e4m.net/download.html

This tool is used with the following command line option:

mkproto -s -p -h somefile.c

the above command produces somefile.h with a prototype line for each
function found in somefile.c

11. GNU Indent - generating beautified code
===========================================

GNU Indent v1.2 is used to format the code that is distributed.

This tool is used with the following command line option:

indent -cli0.4 -bli0 -i8 -ci0 somefile.c

The IDE tab settings used are the defaults (eg: tab size=4, indent
size=4, keep tabs).

12. RAR - packaging the final product
=====================================

The shareware tool "rar" v2.50 is used to package the final product,
this tool creates both the sfx installation binary, and the zip
archive for the source code.

This tool is available from http://www.rarsoft.com

Enjoy!

Paul Le Roux

