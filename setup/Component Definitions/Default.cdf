[Components]
component0=Driver Files
component1=Windows Files
component2=Program Files
[Driver Files]
SELECTED=Yes
FILENEED=CRITICAL
HTTPLOCATION=
STATUS=
UNINSTALLABLE=Yes
TARGET=<WINSYSDIR>\Drivers
FTPLOCATION=
VISIBLE=Yes
DESCRIPTION=
DISPLAYTEXT=
IMAGE=
DEFSELECTION=Yes
filegroup0=Driver Files
requiredby0=Program Files
COMMENT=
INCLUDEINBUILD=Yes
INSTALLATION=ALWAYSOVERWRITE
COMPRESSIFSEPARATE=No
MISC=
ENCRYPT=No
DISK=ANYDISK
TARGETDIRCDROM=
PASSWORD=
TARGETHIDDEN=Windows Operating System\Windows System Folder\Drivers
[TopComponents]
component0=Program Files
component1=Driver Files
component2=Windows Files
[SetupType]
setuptype0=Typical
[Windows Files]
SELECTED=Yes
FILENEED=CRITICAL
HTTPLOCATION=
STATUS=
UNINSTALLABLE=Yes
TARGET=<WINDIR>
FTPLOCATION=
VISIBLE=Yes
DESCRIPTION=
DISPLAYTEXT=
IMAGE=
DEFSELECTION=Yes
filegroup0=Windows Files
COMMENT=
INCLUDEINBUILD=Yes
INSTALLATION=ALWAYSOVERWRITE
COMPRESSIFSEPARATE=No
MISC=
ENCRYPT=No
DISK=ANYDISK
TARGETDIRCDROM=
PASSWORD=
TARGETHIDDEN=Windows Operating System
[Program Files]
required0=Driver Files
SELECTED=Yes
FILENEED=CRITICAL
HTTPLOCATION=
STATUS=
UNINSTALLABLE=Yes
TARGET=<TARGETDIR>
FTPLOCATION=
VISIBLE=Yes
DESCRIPTION=
DISPLAYTEXT=
IMAGE=
DEFSELECTION=Yes
filegroup0=Program Executable Files
COMMENT=
INCLUDEINBUILD=Yes
INSTALLATION=ALWAYSOVERWRITE
COMPRESSIFSEPARATE=No
MISC=
ENCRYPT=No
DISK=ANYDISK
TARGETDIRCDROM=
PASSWORD=
TARGETHIDDEN=General Application Destination
[Info]
Type=CompDef
Version=1.00.000
Name=
[SetupTypeItem-Typical]
Comment=
item0=Driver Files
item1=Windows Files
item2=Program Files
Descrip=
DisplayText=