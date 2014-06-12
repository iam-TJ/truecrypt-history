/****************************************************************************
*																			*
*						  cryptlib Randomness Routines						*
*	Copyright Peter Gutmann, Matt Thomlinson, Blake Coverett, Paul Kendall,	*
*					Chris Wedgwood, and Brian Warner 1995-1996				*
*																			*
****************************************************************************/

/* This code probably needs more work - I'm not sure how thread-safe or
   reentrant the whole thing is, especially under Unix, and the way the
   weighting of the gathered randomness is handled under Unix probably needs
   work as well - it's a bit pessimistic on some systems */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "sha.h"
#else
  #include "hash/sha.h"
#endif /* Compiler-specific includes */

/* The size of the random byte pool and the allocated size, which allows
   for the overflow created by the fact that the SHA blocksize isn't any
   useful multiple of a power of 2 */

#define RANDOMPOOL_SIZE			256
#define RANDOMPOOL_ALLOCSIZE	( ( RANDOMPOOL_SIZE + SHA_DIGESTSIZE - 1 ) / SHA_DIGESTSIZE ) * SHA_DIGESTSIZE

/* The buffer containing the random byte pool.  This isn't allocated until
   needed because the allocation strategy may be changed through
   cryptIoctl().

   Since the slow poll executes in the background, it can cause
   synchronisation problems when a cryptAddRandom() or fast poll are
   executed when a slow poll is in progress.   Under Win32 a critical section
   is used to serialise access when adding data to the random pool.  The
   synchronisation calls protect threadSafeAddRandomBuffer() and the
   appropriate fastPoll() function.  For this reason fastPoll() must call
   addRandmomBuffer (the low-level variant).

   Any functions added to lib_rand.c which call addRandomLong and
   addRandomWord should enter the critical section as appropriate (as
   fastPoll() does) */

#ifdef __WIN32__
  #define THREADVAR volatile
#else
  #define THREADVAR
#endif /* __WIN32__ */

static BYTE *randomPool;			/* Random byte pool */
static THREADVAR int randomWritePos;/* Current write position in the pool */
static THREADVAR int randomReadPos;	/* Current read position in the pool */
static THREADVAR int randomStatus;	/* Wether there's any randomness in the pool */

#ifdef __WIN32__

static CRITICAL_SECTION randProt;
volatile HANDLE threadID = NULL;	/* Thread ID, set by the thread */
HANDLE threadEvent = NULL;			/* Thread event handle, used to signal
									   thread termination */
#endif /* __WIN32__ */

/****************************************************************************
*																			*
*						Random Pool Management Routines						*
*																			*
****************************************************************************/

/* The SHA transformation, taken from the MDC/SHS code.   */

void SHATransform( LONG *digest, LONG *data );

/* Stir up the data in the random buffer.  Given a circular buffer of length
   n bytes, we use SHA to hash the 20 bytes at n with the 64 bytes at
   n...n + 64 as the input data block.  Then move on to the next 20 bytes
   until the entire buffer has been mixed.  This carries 512 bits of
   randomness along with it, and wraps around the entire buffer.  We don't
   bother with SHA data endianess-adjustment since we're not really
   interested in the final output values, as long as they're well-mixed */

static void mixRandomPool( void )
	{
	int i;

	/* Stir up the entire pool */
#ifdef _BIG_WORDS
	for( i = 0; i < RANDOMPOOL_SIZE; i += SHA_DIGESTSIZE )
		{
		LONG digestLong[ SHA_DIGESTSIZE / 4 ];
		LONG inputBuffer[ SHA_DATASIZE / 4 ];
		BYTE *digestPtr;
		int digestCount, j;

		/* Copy SHA_DATASIZE bytes from the circular buffer into the hash
		   data buffer, hash the data, and copy the result back into the
		   random pool */
		for( j = 0; j < SHA_DATASIZE; j += 4 )
			inputBuffer[ j / 4 ] = \
				( ( LONG ) randomPool[ ( i + j ) % RANDOMPOOL_SIZE ] << 24 ) | \
				( ( LONG ) randomPool[ ( i + j + 1 ) % RANDOMPOOL_SIZE ] << 16 ) | \
				( ( LONG ) randomPool[ ( i + j + 2 ) % RANDOMPOOL_SIZE ] << 8 ) | \
				( ( LONG ) randomPool[ ( i + j + 3 ) % RANDOMPOOL_SIZE ] );
		digestPtr = randomPool + i;
		for( j = 0; j < SHA_DIGESTSIZE / 4; j++ )
			{
			digestLong[ j ] = mgetBLong( digestPtr );
			}
		SHATransform( digestLong, inputBuffer );
		digestPtr = randomPool + i;
		for( j = 0; j < SHA_DIGESTSIZE / 4; j++ )
			{
			mputBLong( digestPtr, digestLong[ j ] );
			}
		zeroise( inputBuffer, SHA_DATASIZE );
		}
#else
	for( i = 0; i < RANDOMPOOL_SIZE; i += SHA_DIGESTSIZE )
		{
		BYTE inputBuffer[ SHA_DATASIZE ];
		int j;

		/* Copy SHA_DATASIZE bytes from the circular buffer into the hash
		   data buffer, hash the data, and copy the result back into the
		   random pool */
		for( j = 0; j < SHA_DATASIZE; j++ )
			inputBuffer[ j ] = randomPool[ ( i + j ) % RANDOMPOOL_SIZE ];
		SHATransform( ( LONG * ) ( randomPool + i ), ( LONG * ) inputBuffer );
		zeroise( inputBuffer, SHA_DATASIZE );
		}
#endif /* _BIG_WORDS */

	/* We're back to reading and writing from the start of the pool */
	randomReadPos = randomWritePos = 0;
	}

/* Add a random offset to the location where the next amount of data is to
   be inserted */

#define randomizeAddPos()	randomWritePos += randomPool[ 0 ] & 0x0F

/* Add a byte to the random buffer.  This is implemented as a macro to avoid
   leaving random data passed to a function on the stack.  These are low-
   level routines which are not thread-safe */

#define addRandomByte( data ) \
	{ \
	if( randomWritePos > RANDOMPOOL_SIZE - 1 ) \
		mixRandomPool(); \
	randomPool[ randomWritePos++ ] += data; \
	}

#define addRandomWord( word ) \
	addRandomByte( ( BYTE ) ( ( WORD ) word >> 8 ) ); \
	addRandomByte( ( BYTE ) ( WORD ) word )

#define addRandomLong( word ) \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 24 ) ); \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 16 ) ); \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 8 ) ); \
	addRandomByte( ( BYTE ) ( LONG ) word )

/* Add a block of data to the random buffer */

static void addRandomBuffer( BYTE *buffer, int count )
	{
	while( count-- )
		addRandomByte( *buffer++ );
	}

#ifdef __WIN32__

/* Higher-level thread-safe version of addRandomBuffer */

static void threadSafeAddRandomBuffer( BYTE *buffer, int count )
	{
	EnterCriticalSection( &randProt );
	addRandomBuffer( buffer, count );
	LeaveCriticalSection( &randProt );
	}
#else
  #define threadSafeAddRandomBuffer	addRandomBuffer
#endif /* __WIN32__ */

/****************************************************************************
*																			*
*					OS-Specific Randomness-Gathering Functions				*
*																			*
****************************************************************************/

#if defined( __MSDOS__ )									/* DOS */

#include <fcntl.h>
#include <io.h>

static void fastPoll( void )
	{
	/* There's not much we can do under DOS, we rely entirely on the
	   /dev/random read for information */
	addRandomLong( time( NULL ) );
	}

static void slowPoll( void )
	{
	BYTE buffer[ 128 ];
	int fd, count;

	/* Read 128 bytes from /dev/random and add it to the buffer.  Since DOS
	   doesn't swap we don't need to be as careful about copying data to
	   temporary buffers as we usually are.  We also have to use unbuffered
	   I/O, since the high-level functions will read BUFSIZ bytes at once
	   from the input, comletely draining the driver of any randomness */
	if( ( fd = open( "/dev/random", O_RDONLY ) ) == -1 )
		return;
	count = read( fd, buffer, 128 );
	randomizeAddPos();
	addRandomBuffer( buffer, count );
	zeroise( buffer, 128 );
	close( fd );

	/* Remember that we've got some randomness we can use */
	randomStatus = CRYPT_OK;
	}

#elif defined( __WIN16__ )									/* Win16 */

#include <stress.h>
#include <toolhelp.h>

static void fastPoll( void )
	{
	static int noFastPolls = 0;
	SYSHEAPINFO sysHeapInfo;
	MEMMANINFO memManInfo;
	TIMERINFO timerInfo;
	POINT point;

	/* Get various basic pieces of system information */
	addRandomWord( GetCapture() );	/* Handle of window with mouse capture */
	addRandomWord( GetFocus() );	/* Handle of window with input focus */
	addRandomLong( GetFreeSpace( 0 ) );	/* Amount of space in global heap */
	addRandomWord( GetInputState() );	/* Whether system queue has any events */
	addRandomLong( GetMessagePos() );	/* Cursor pos.for last message */
	addRandomLong( GetMessageTime() );	/* 55 ms time for last message */
	addRandomWord( GetNumTasks() );	/* Number of active tasks */
	addRandomLong( GetTickCount() );/* 55 ms time since Windows started */
	GetCursorPos( &point );			/* Current mouse cursor position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );
	GetCaretPos( &point );			/* Current caret position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );

	/* Get the largest free memory block, number of lockable pages, number of
	   unlocked pages, number of free and used pages, and number of swapped
	   pages */
	memManInfo.dwSize = sizeof( MEMMANINFO );
	MemManInfo( &memManInfo );
	addRandomBuffer( ( BYTE * ) &memManInfo, sizeof( MEMMANINFO ) );

	/* Get the execution times of the current task and VM to approximately
	   1ms resolution */
	timerInfo.dwSize = sizeof( TIMERINFO );
	TimerCount( &timerInfo );
	addRandomBuffer( ( BYTE * ) &timerInfo, sizeof( TIMERINFO ) );

	/* Get the percentage free and segment of the user and GDI heap */
	sysHeapInfo.dwSize = sizeof( SYSHEAPINFO );
	SystemHeapInfo( &sysHeapInfo );
	addRandomBuffer( ( BYTE * ) &sysHeapInfo, sizeof( SYSHEAPINFO ) );

	/* Since the Win16 fast poll gathers a reasonable amount of information,
	   we treat five of them as being equivalent to one slow poll */
	if( ++noFastPolls >= 5 )
		/* Remember that we've got some randomness we can use */
		randomStatus = CRYPT_OK;
	}

/* The slow poll can get *very* slow because of the overhead involved in
   obtaining the necessary information.  On a moderately loaded system there
   are often 500+ objects on the global heap and 50+ modules, so we limit
   the number checked to a reasonable level to make sure we don't spend
   forever polling.  We give the global heap walk the most leeway since this
   provides the best source of randomness */

static void slowPoll( void )
	{
	MODULEENTRY moduleEntry;
	GLOBALENTRY globalEntry;
	TASKENTRY taskEntry;
    int count;

	randomizeAddPos();

	/* Walk the global heap getting information on each entry in it.  This
	   retrieves the objects linear address, size, handle, lock count, owner,
	   object type, and segment type */
	count = 0;
	globalEntry.dwSize = sizeof( GLOBALENTRY );
	if( GlobalFirst( &globalEntry, GLOBAL_ALL ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &globalEntry, sizeof( GLOBALENTRY ) );
			count++;
			}
		while( count < 70 && GlobalNext( &globalEntry, GLOBAL_ALL ) );

	/* Walk the module list getting information on each entry in it.  This
	   retrieves the module name, handle, reference count, executable path,
	   and next module */
	count = 0;
	moduleEntry.dwSize = sizeof( MODULEENTRY );
	if( ModuleFirst( &moduleEntry ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &moduleEntry, sizeof( MODULEENTRY ) );
			count++;
			}
		while( count < 20 && ModuleNext( &moduleEntry ) );

	/* Walk the task list getting information on each entry in it.  This
	   retrieves the task handle, parent task handle, instance handle, stack
	   segment and offset, stack size, number of pending events, task queue,
	   and the name of module executing the task.  We also call TaskGetCSIP()
	   for the code segment and offset of each task if it's safe to do so */
	count = 0;
	taskEntry.dwSize = sizeof( TASKENTRY );
	if( TaskFirst( &taskEntry ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &taskEntry, sizeof( TASKENTRY ) );
			if( taskEntry.hTask != GetCurrentTask() )
				addRandomLong( TaskGetCSIP( taskEntry.hTask ) );
			count++;
			}
		while( count < 100 && TaskNext( &taskEntry ) );

	/* Remember that we've got some randomness we can use */
	randomStatus = CRYPT_OK;
	}

#elif defined( __WIN32__ )									/* Win32 */

#include <tlhelp32.h>
#include <winperf.h>
#include <winioctl.h>
#include <process.h>

#pragma comment( lib, "advapi32" )

#define	THREADSTACKSIZE		8192

static HANDLE hNetAPI32 = NULL;

static void fastPoll( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	static int noFastPolls = 0;
	FILETIME  creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;
	LARGE_INTEGER performanceCount;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;

	EnterCriticalSection( &randProt );

	/* Get various basic pieces of system information */
	addRandomLong( GetActiveWindow() );	/* Handle of active window */
	addRandomLong( GetCapture() );		/* Handle of window with mouse capture */
	addRandomLong( GetClipboardOwner() );/* Handle of clipboard owner */
	addRandomLong( GetClipboardViewer() );/* Handle of start of clpbd.viewer list */
	addRandomLong( GetCurrentProcess() );/* Pseudohandle of current process */
	addRandomLong( GetCurrentProcessId() );/* Current process ID */
	addRandomLong( GetCurrentThread() );/* Pseudohandle of current thread */
	addRandomLong( GetCurrentThreadId() );/* Current thread ID */
	addRandomLong( GetCurrentTime() );	/* Milliseconds since Windows started */
	addRandomLong( GetDesktopWindow() );/* Handle of desktop window */
	addRandomLong( GetFocus() );		/* Handle of window with kb.focus */
	addRandomWord( GetInputState() );	/* Whether sys.queue has any events */
	addRandomLong( GetMessagePos() );	/* Cursor pos.for last message */
	addRandomLong( GetMessageTime() );	/* 1 ms time for last message */
	addRandomLong( GetOpenClipboardWindow() );	/* Handle of window with clpbd.open */
	addRandomLong( GetProcessHeap() );	/* Handle of process heap */
	addRandomLong( GetProcessWindowStation() );	/* Handle of procs window station */
	addRandomLong( GetQueueStatus( QS_ALLEVENTS ) );/* Types of events in input queue */

	/* Get multiword system information */
	GetCaretPos( &point );				/* Current caret position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );
	GetCursorPos( &point );				/* Current mouse cursor position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );

	/* Get percent of memory in use, bytes of physical memory, bytes of free
	   physical memory, bytes in paging file, free bytes in paging file, user
	   bytes of address space, and free user bytes */
	memoryStatus.dwLength = sizeof( MEMORYSTATUS );
	GlobalMemoryStatus( &memoryStatus );
	addRandomBuffer( ( BYTE * ) &memoryStatus, sizeof( MEMORYSTATUS ) );

	/* Get thread and process creation time, exit time, time in kernel mode,
	   and time in user mode in 100ns intervals */
	handle = GetCurrentThread();
	GetThreadTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomBuffer( ( BYTE * ) &creationTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &exitTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &kernelTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &userTime, sizeof( FILETIME ) );
	handle = GetCurrentProcess();
	GetProcessTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomBuffer( ( BYTE * ) &creationTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &exitTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &kernelTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &userTime, sizeof( FILETIME ) );

	/* Get the minimum and maximum working set size for the current process */
	GetProcessWorkingSetSize( handle, &minimumWorkingSetSize,
							  &maximumWorkingSetSize );
	addRandomLong( minimumWorkingSetSize );
	addRandomLong( maximumWorkingSetSize );

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		STARTUPINFO startupInfo;

		/* Get name of desktop, console window title, new window position and
		   size, window flags, and handles for stdin, stdout, and stderr */
		startupInfo.cb = sizeof( STARTUPINFO );
		GetStartupInfo( &startupInfo );
		addRandomBuffer( ( BYTE * ) &startupInfo, sizeof( STARTUPINFO ) );
		addedFixedItems = TRUE;
		}

	/* The docs say QPC can fail if appropriate hardware is not available.
	   It works on 486 & Pentium boxes, but hasn't been tested for 386 or
	   RISC boxes */
	if( QueryPerformanceCounter( &performanceCount ) )
		addRandomBuffer( ( BYTE * ) &performanceCount, sizeof( LARGE_INTEGER ) );
	else
		{
		/* Millisecond accuracy at best... */
		DWORD dwTicks = GetTickCount();
		addRandomBuffer( ( BYTE * ) &dwTicks, sizeof( dwTicks ) );
		}

	/* Since the Win32 fast poll gathers quite a bit of information, we treat
	   three of them as being equivalent to one slow poll */
	if( ++noFastPolls >= 3 )
		/* Remember that we've got some randomness we can use */
		randomStatus = CRYPT_OK;

	LeaveCriticalSection( &randProt );
	}

/* Type definitions for function pointers to call Toolhelp32 functions */

typedef BOOL ( WINAPI *MODULEWALK )( HANDLE hSnapshot, LPMODULEENTRY32 lpme );
typedef BOOL ( WINAPI *THREADWALK )( HANDLE hSnapshot, LPTHREADENTRY32 lpte );
typedef BOOL ( WINAPI *PROCESSWALK )( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL ( WINAPI *HEAPLISTWALK )( HANDLE hSnapshot, LPHEAPLIST32 lphl );
typedef BOOL ( WINAPI *HEAPFIRST )( LPHEAPENTRY32 lphe, DWORD th32ProcessID, DWORD th32HeapID );
typedef BOOL ( WINAPI *HEAPNEXT )( LPHEAPENTRY32 lphe );
typedef HANDLE ( WINAPI *CREATESNAPSHOT )( DWORD dwFlags, DWORD th32ProcessID );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the Win95 kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   NT */

static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
static MODULEWALK pModule32First = NULL;
static MODULEWALK pModule32Next = NULL;
static PROCESSWALK pProcess32First = NULL;
static PROCESSWALK pProcess32Next = NULL;
static THREADWALK pThread32First = NULL;
static THREADWALK pThread32Next = NULL;
static HEAPLISTWALK pHeap32ListFirst = NULL;
static HEAPLISTWALK pHeap32ListNext = NULL;
static HEAPFIRST pHeap32First = NULL;
static HEAPNEXT pHeap32Next = NULL;

static void slowPollWin95( void )
	{
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	HANDLE hSnapshot;

	/* Initialize the Toolhelp32 function pointers if necessary */
	if( pCreateToolhelp32Snapshot == NULL )
		{
		HANDLE hKernel = NULL;

		/* Obtain the module handle of the kernel to retrieve the addresses
		   of the Toolhelp32 functions */
    	if( ( hKernel = GetModuleHandle( "KERNEL32.DLL" ) ) == NULL )
    		return;

		/* Now get pointers to the functions */
		pCreateToolhelp32Snapshot = ( CREATESNAPSHOT ) GetProcAddress( hKernel,
													"CreateToolhelp32Snapshot" );
		pModule32First = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32First" );
		pModule32Next = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32Next" );
		pProcess32First = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32First" );
		pProcess32Next = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32Next" );
		pThread32First = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32First" );
		pThread32Next = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32Next" );
		pHeap32ListFirst = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListFirst" );
		pHeap32ListNext = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListNext" );
		pHeap32First = ( HEAPFIRST ) GetProcAddress( hKernel,
													"Heap32First" );
		pHeap32Next = ( HEAPNEXT ) GetProcAddress( hKernel,
													"Heap32Next" );

		/* Make sure we got valid pointers for every Toolhelp32 function */
		if( pModule32First == NULL || pModule32Next == NULL || \
			pProcess32First == NULL || pProcess32Next == NULL || \
			pThread32First == NULL || pThread32Next == NULL || \
			pHeap32ListFirst == NULL || pHeap32ListNext == NULL || \
			pHeap32First == NULL || pHeap32Next == NULL || \
			pCreateToolhelp32Snapshot == NULL )
			{
			/* Mark the main function as unavailable in case for future
			   reference */
			pCreateToolhelp32Snapshot = NULL;
			return;
			}
		}

	/* Take a snapshot of everything we can get to which is currently
	   in the system */
	hSnapshot = pCreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
	if( !hSnapshot )
		return;

	/* Walk through the local heap */
	hl32.dwSize = sizeof( HEAPLIST32 );
	if( pHeap32ListFirst( hSnapshot, &hl32 ) )
		do
			{
			HEAPENTRY32 he32;

			/* First add the information from the basic Heaplist32
			   structure */
			threadSafeAddRandomBuffer( ( BYTE * ) &hl32, sizeof( HEAPLIST32 ) );

			/* Now walk through the heap blocks getting information
			   on each of them */
			he32.dwSize = sizeof( HEAPENTRY32 );
			if( pHeap32First( &he32, hl32.th32ProcessID, hl32.th32HeapID ) )
				do
					threadSafeAddRandomBuffer( ( BYTE * ) &he32, sizeof( HEAPENTRY32 ) );
				while( pHeap32Next( &he32 ) );
			}
		while( pHeap32ListNext( hSnapshot, &hl32 ) );

	/* Walk through all processes */
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if( pProcess32First( hSnapshot, &pe32 ) )
		do
			threadSafeAddRandomBuffer( ( BYTE * ) &pe32, sizeof( PROCESSENTRY32 ) );
		while( pProcess32Next( hSnapshot, &pe32 ) );

	/* Walk through all threads */
	te32.dwSize = sizeof( THREADENTRY32 );
	if( pThread32First( hSnapshot, &te32 ) )
		do
			threadSafeAddRandomBuffer( ( BYTE * ) &te32, sizeof( THREADENTRY32 ) );
	while( pThread32Next( hSnapshot, &te32 ) );

	/* Walk through all modules associated with the process */
	me32.dwSize = sizeof( MODULEENTRY32 );
	if( pModule32First( hSnapshot, &me32 ) )
		do
			threadSafeAddRandomBuffer( ( BYTE * ) &me32, sizeof( MODULEENTRY32 ) );
	while( pModule32Next( hSnapshot, &me32 ) );

	/* Clean up the snapshot */
	CloseHandle( hSnapshot );

	/* Remember that we've got some randomness we can use */
	randomStatus = CRYPT_OK;
	}

/* Perform a thread-safe slow poll.  The following function *must* be started
   as a thread */

static void threadSafeSlowPollWin95( void *dummy )
	{
	ResetEvent( threadEvent );
	slowPollWin95();
	SetEvent( threadEvent );
	threadID = NULL;
	_endthread();
	}

/* Type definitions for function pointers to call NetAPI32 functions */

typedef DWORD ( WINAPI *NETSTATISTICSGET )( LPWSTR szServer, LPWSTR szService,
											DWORD dwLevel, DWORD dwOptions,
											LPBYTE *lpBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERSIZE )( LPVOID lpBuffer, LPDWORD cbBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERFREE )( LPVOID lpBuffer );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the WinNT kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   Win95 */

static NETSTATISTICSGET pNetStatisticsGet = NULL;
static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
static NETAPIBUFFERFREE pNetApiBufferFree = NULL;

static void slowPollWinNT( void )
	{
	static int isWorkstation = CRYPT_ERROR;
	PPERF_DATA_BLOCK pPerfData;
	static int cbPerfData = 0x10000;
	HANDLE hDevice;
	LPBYTE lpBuffer;
	DWORD dwSize, status;
	int nDrive;

	/* Find out whether this is an NT server or workstation if necessary */
	if( isWorkstation == CRYPT_ERROR )
		{
		HKEY hKey;

		if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						  "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
						  0, KEY_READ, &hKey ) == ERROR_SUCCESS )
			{
			BYTE szValue[ 32 ];
			dwSize = sizeof( szValue );

			isWorkstation = TRUE;
			status = RegQueryValueEx( hKey, "ProductType", 0, NULL,
									  szValue, &dwSize );
			if( status == ERROR_SUCCESS && stricmp( szValue, "WinNT" ) )
				/* Note: There are (at least) three cases for ProductType:
				   WinNT = NT Workstation, ServerNT = NT Server, LanmanNT =
				   NT Server acting as a Domain Controller */
				isWorkstation = FALSE;

			RegCloseKey( hKey );
			}
		}

	/* Initialize the NetAPI32 function pointers if necessary */
	if( hNetAPI32 == NULL )
		{
		/* Obtain a handle to the module containing the Lan Manager functions */
    	if( hNetAPI32 = LoadLibrary( "NETAPI32.DLL" ) )
			{
			/* Now get pointers to the functions */
			pNetStatisticsGet = ( NETSTATISTICSGET ) GetProcAddress( hNetAPI32,
														"NetStatisticsGet" );
			pNetApiBufferSize = ( NETAPIBUFFERSIZE ) GetProcAddress( hNetAPI32,
														"NetApiBufferSize" );
			pNetApiBufferFree = ( NETAPIBUFFERFREE ) GetProcAddress( hNetAPI32,
														"NetApiBufferFree" );

			/* Make sure we got valid pointers for every NetAPI32 function */
			if( pNetStatisticsGet == NULL ||
				pNetApiBufferSize == NULL ||
				pNetApiBufferFree == NULL )
				{
				/* Free the library reference and reset the static handle */
				FreeLibrary( hNetAPI32 );
				hNetAPI32 = NULL;
				}
			}
		}

	/* Get network statistics.  Note: Both NT Workstation and NT Server by
	   default will be running both the workstation and server services.  The
	   heuristic below is probably useful though on the assumption that the
	   majority of the network traffic will be via the appropriate service */
	if( hNetAPI32 &&
		pNetStatisticsGet( NULL,
						   isWorkstation ? L"LanmanWorkstation" : L"LanmanServer",
						   0, 0, &lpBuffer ) == 0 )
		{
		pNetApiBufferSize( lpBuffer, &dwSize );
		threadSafeAddRandomBuffer( ( BYTE * ) lpBuffer, dwSize );
		pNetApiBufferFree( lpBuffer );
		}

	/* Get disk I/O statistics for all the hard drives */
	for( nDrive = 0;; nDrive++ )
		{
		DISK_PERFORMANCE diskPerformance;
		char szDevice[ 24 ];

		/* Check whether we can access this device */
		sprintf( szDevice, "\\\\.\\PhysicalDrive%d", nDrive );
		hDevice = CreateFile( szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
							  NULL, OPEN_EXISTING, 0, NULL );
		if( hDevice == INVALID_HANDLE_VALUE )
			break;

		/* Note: This only works if you have turned on the disk performance
		   counters with 'diskperf -y'.  These counters are off by default */
		if( DeviceIoControl( hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
							 &diskPerformance, sizeof( DISK_PERFORMANCE ),
							 &dwSize, NULL ) )
			{
			threadSafeAddRandomBuffer( ( BYTE * ) &diskPerformance, dwSize );
			}
		CloseHandle( hDevice );
		}

	/* Get the performance counters */
	pPerfData = ( PPERF_DATA_BLOCK ) malloc( cbPerfData );
	while( pPerfData )
		{
		dwSize = cbPerfData;
		status = RegQueryValueEx( HKEY_PERFORMANCE_DATA, "Global", NULL,
								  NULL, ( LPBYTE ) pPerfData, &dwSize );

		if( status == ERROR_SUCCESS )
			{
			if( !memcmp( pPerfData->Signature, L"PERF", 8 ) )
				threadSafeAddRandomBuffer( ( BYTE * ) pPerfData, dwSize );
			free( pPerfData );
			pPerfData = NULL;
			}
		else
			if( status == ERROR_MORE_DATA )
				{
				cbPerfData += 4096;
				pPerfData == ( PPERF_DATA_BLOCK ) realloc( pPerfData, cbPerfData );
				}
		}

	/* Remember that we've got some randomness we can use */
	randomStatus = CRYPT_OK;
	}

/* Perform a thread-safe slow poll.  The following function *must* be started
   as a thread */

static void threadSafeSlowPollWinNT( void *dummy )
	{
	ResetEvent( threadEvent );
	slowPollWinNT();
    SetEvent(threadEvent);
	threadID = NULL;
	_endthread();
	}

static void slowPoll( void )
	{
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	if( dwPlatform == CRYPT_ERROR )
		{
		OSVERSIONINFO osvi = { sizeof( osvi ) };
		if( GetVersionEx( &osvi ) )
			dwPlatform = osvi.dwPlatformId;
		}

	/* Start a threaded slow poll.  If a slow poll is already running, we
	   just return since there isn't much point in running two of them at the
	   same time */
	switch( dwPlatform )
		{
		case VER_PLATFORM_WIN32_NT:
			if( !threadID )
				threadID = ( HANDLE ) _beginthread( threadSafeSlowPollWinNT,
													THREADSTACKSIZE, NULL );
   			break;

		case VER_PLATFORM_WIN32_WINDOWS:
			if( !threadID )
				threadID = ( HANDLE ) _beginthread( threadSafeSlowPollWin95,
													THREADSTACKSIZE, NULL );
			break;

		case VER_PLATFORM_WIN32s:
			break;
		}
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   randomFlush, which will block until the background process completes.  At
   the moment this call is in the getRandomByte routine */

void randomFlush( void )
	{
	if( threadID != NULL )
		WaitForSingleObject( threadEvent, INFINITE );
	}

#elif defined( __UNIX__ )									/* Unix */

#ifdef __osf__
  /* Somewhere in the morass of system-specific cruft which OSF/1 pulls in
	 via the following includes are various endianness defines, so we
	 undefine the cryptlib ones, which aren't really needed for this module
	 anyway */
  #undef BIG_ENDIAN
  #undef LITTLE_ENDIAN
#endif /* __osf__ */

#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/time.h>	/* SCO and SunOS need this before resource.h */
#include <sys/resource.h>
#ifdef _AIX
  #include <sys/select.h>
#endif /* _AIX */
#include <sys/shm.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>	/* Verschiedene komische Typen */
#include <sys/wait.h>
/* #include <kitchensink.h> */

/* The structure containing information on random-data sources.  Each
   record contains the source and a relative estimate of its usefulness
   (weighting) which is used to scale the number of kB of output from the
   source.  Usually the weighting is in the range 1-3 (or 0 for especially
   useless sources).  If the source is constantly changing (certain types of
   network statistics have this characteristic) but the amount of output is
   small, the constant value 100 is added to the weighting to indicate that
   the output should be treated as if a minimum of 1K of output had been
   obtained.  If the source produces a lot of output then the scale factor is
   fractional.  In order to provide enough randomness to satisfy the
   requirements for a slow poll, we need to accumulate at least 25 points of
   usefulness (a typical system should get about 30-35 points).

   Some potential options are missed out because of special considerations.
   pstat -i and pstat -f can produce amazing amounts of output (the record
   is 600K on an Oracle server) which floods the buffer and doesn't yield
   anything useful (apart from perhaps increasing the entropy of the vmstat
   output a bit), so we don't bother with this.  pstat in general produces
   quite a bit of output, but it doesn't change much over time, so it gets
   very low weightings.  netstat -s produces constantly-changing output but
   also produces quite a bit of it, so it only gets a weighting of 2 rather
   than 3.  The same holds for netstat -in, which gets 1 rather than 2.

   Some binaries are stored in different locations on different systems so
   alternative paths are given for them.  The code sorts out which one to
   run by itself, once it finds an exectable somewhere it moves on to the
   next source.  The sources are arranged roughly in their order of
   usefulness, occasionally sources which provide a tiny amount of
   relatively useless data are placed ahead of ones which provide a large
   amount of possibly useful data because another 100 bytes can't hurt, and
   it means the buffer won't be swamped by one or two high-output sources.
   All the high-output sources are clustered towards the end of the list
   for this reason.  Some binaries checked for in a certain order, for
   example under Slowaris /usr/ucb/ps understands aux as an arg, but the
   others don't.  Some systems have conditional defines enabling alternatives
   to commands which don't understand the usual options but will provide
   enough output (in the form of error messages) to look like they're the
   real thing, causing alternative options to be skipped (we can't check the
   return either because some commands return peculiar, non-zero status even
   when they're working correctly).

   In order to maximise use of the buffer, the code performs a form of run-
   length compression on its input where a repeated sequence of bytes is
   replaced by the occurrence count mod 256.  Some commands output an awful
   lot of whitespace, this measure greatly increases the amount of data we
   can fit in the buffer.

   Some broken preprocessors may give a division by zero warning on the
   following macro */

#define SC( weight )	( weight ? 1024 / weight : 0 )	/* Scale factor */

static struct RI {
	const char *path;		/* Path to check for existence of source */
	const char *arg;		/* Args for source */
	const int usefulness;	/* Usefulness of source */
	FILE *pipe;				/* Pipe to source as FILE * */
	int pipeFD;				/* Pipe to source as FD */
	pid_t pid;				/* pid of child for waitpid() */
	int length;				/* Quantity of output produced */
	const BOOLEAN hasAlternative;	/* Whether source has alt.location */
	} dataSources[] = {
	{ "/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/pfstat", NULL, SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/nfsstat", NULL, SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/mpstat", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/w", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/iostat", NULL, SC( 0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/uptime", NULL, SC( 0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-f", SC( 0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-f", SC( 0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", NULL, SC( 0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", NULL, SC( 0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, FALSE },
#ifdef __sgi
	{ "/bin/ps", "-el", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
#endif /* __sgi */
	{ "/usr/ucb/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
							/* Unreliable source, depends on system usage */
	{ "/etc/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
							/* pstat is your friend (usually) */
	{ "/usr/sbin/advfsstat", "-b usr_domain", SC( 0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-l 2 usr_domain", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-p usr_domain", SC( 0 ), NULL, 0, 0, 0, FALSE },
							/* This is a complex and screwball program.  Some
							   systems have things like rX_dmn, x = integer,
							   for RAID systems, but the statistics are
							   pretty dodgy */
	{ NULL, NULL, 0, NULL, 0, 0, 0, FALSE } };

/* Variables to manage the child process which fills the buffer */

static pid_t gathererProcess = 0;/* The child process which fills the buffer */
static BYTE *gathererBuffer;	/* Shared buffer for gathering random noise */
static int gathererMemID;		/* ID for shared memory */
static int gathererBufSize;		/* Size of the shared memory buffer */
static uid_t gathererID = -1;	/* Gatherers user ID */

/* The struct at the start of the shared memory buffer used to communicate
   information from the child to the parent */

typedef struct {
	int usefulness;				/* Usefulness of data in buffer */
	int noBytes;				/* No.of bytes in buffer */
	} GATHERER_INFO;

/* Under SunOS popen() doesn't record the pid of the child process.  When
   pclose() is called, instead of calling waitpid() for the correct child, it
   calls wait() repeatedly until the right child is reaped.  The problem is
   that this reaps any other children that happen to have died at that
   moment, and when their pclose() comes along, the process hangs forever.
   The fix is to use a wrapper for popen()/pclose() which saves the pid in
   the dataSources structure (code adapted from GNU-libc's popen() call) */

#include <sys/errno.h>

extern int errno;

static FILE *my_popen( struct RI *entry )
	{
	int pipedes[ 2 ];
	FILE *stream;

	/* Create the pipe */
	if( pipe( pipedes ) < 0 )
		return( NULL );

	/* Fork off the child ("vfork() is like an OS orgasm.  All OS's want to
	   do it, but most just end up faking it" - Chris Wedgwood).  If your OS
	   supports it, you should try to use vfork() here because it's somewhat
	   more efficient */
#if defined( sun ) || defined( __ultrix__ ) || defined( __osf__ )
	entry->pid = vfork();
#else
	entry->pid = fork();
#endif /* Unixen which have vfork() */
	if( entry->pid == ( pid_t ) -1 )
		{
		/* The fork failed */
		close( pipedes[ 0 ] );
		close( pipedes[ 1 ] );
		return( NULL );
		}
	else
		if( entry->pid == ( pid_t ) 0 )
			{
			/* We are the child.  Make the read side of the pipe be stdout */
			if( dup2( pipedes[ STDOUT_FILENO ], STDOUT_FILENO ) < 0 )
				exit( 127 );

			/* Close the pipe descriptors */
			close( pipedes[ STDIN_FILENO ] );
			close( pipedes[ STDOUT_FILENO ] );

			/* Try and exec the program */
			execl( entry->path, entry->path, entry->arg, NULL );

			/* Die if the exec failed */
			exit( 127 );
			}

	/* We are the parent.  Close the irrelevant side of the pipe and open the
	   relevant side as a new stream.  Mark our side of the pipe to close on
	   exec, so new children won't see it */
	close( pipedes[ STDOUT_FILENO ] );
	fcntl( pipedes[ STDIN_FILENO ], F_SETFD, FD_CLOEXEC );
	stream = fdopen( pipedes[ STDIN_FILENO ], "r" );
	if( stream == NULL )
		{
		int savedErrno = errno;

		/* The stream couldn't be opened or the child structure couldn't be
		   allocated.  Kill the child and close the other side of the pipe */
		kill( entry->pid, SIGKILL );
		if( stream == NULL )
			close( pipedes[ STDOUT_FILENO ] );
        else
			fclose( stream );
		waitpid( entry->pid, NULL, 0 );
		entry->pid = 0;
		errno = savedErrno;
		return( NULL );
		}

	return( stream );
	}

static int my_pclose( struct RI *entry )
	{
	int status = 0;

	if( fclose( entry->pipe ) )
		return( -1 );

	/* We ignore the return value from the process because some programs
	   return funny values which would result in the input being discarded
	   even if they executed successfully.  This isn't a problem because
	   the 1K size threshold will filter out any programs which exit with
	   a usage message without producing useful output */
	if( waitpid( entry->pid, NULL, 0 ) != entry->pid )
		status = -1;

	entry->pipe = NULL;
	entry->pid = 0;
	return( status );
	}

/* Unix fast poll - not terribly useful */

static void fastPoll( void )
	{
#ifndef _M_XENIX	/* SCO has a gettimeofday() prototype, but no sys.call */
	struct timeval tv;
#ifndef __hpux		/* PHUX has the fn.prototypes, but not the system call */
	struct rusage rusage;
#endif /* __hpux */

	gettimeofday( &tv, NULL );
	addRandomLong( tv.tv_sec );
	addRandomLong( tv.tv_usec );

#ifndef __hpux
	getrusage( RUSAGE_SELF, &rusage );
	addRandomBuffer( ( BYTE * ) &rusage, sizeof( struct rusage ) );
#endif /* __hpux */
#endif /* _M_XENIX */
	}

/* Unix slow poll with special support for Linux.  Really for Linux >=1.3.43
   (>=2.0.12 recommended), "mknod /dev/urandom c 1 9" if you don't have this
   device, and also "mknod /dev/random c 1 8" (this assumes you're root -
   "Use Linux, be your own luser").

   If a few of the randomness sources create a large amount of output then
   the slowPoll() stops once the buffer has been filled (but before all the
   randomness sources have been sucked dry) so that the 'usefulness' factor
   remains below the threshold.  For this reason the gatherer buffer has to
   be fairly sizeable on moderately loaded systems.  This is something of a
   bug since the usefulness should be influenced by the amount of output as
   well as the source type */

#define DEVRANDOM_BITS		1024
#define SHARED_BUFSIZE 		49152	/* Usually about 25K are filled */

static void slowPoll( void )
	{
	int	fd;

	if( ( fd = open( "/dev/urandom", O_RDONLY ) ) >= 0 )
		{
		BYTE buffer[ DEVRANDOM_BITS / 8 ];

		/* Read data from /dev/urandom, which won't block (although the
		   quality of the noise is lesser).  This is Linux-specific, but we
		   may as well leave it in for other systems in case it's present
		   there */
		read( fd, buffer, DEVRANDOM_BITS / 8 );
		randomizeAddPos();
		addRandomBuffer( buffer, DEVRANDOM_BITS / 8 );
		zeroise( buffer, DEVRANDOM_BITS / 8 );
		close( fd );
		gathererProcess = 0; /* We never forked off a child */

		/* Remember that we've got some randomness we can use */
		randomStatus = CRYPT_OK;
		}
	else
		{
		GATHERER_INFO *gathererInfo;
		BOOLEAN moreSources;
		struct timeval tv;
		struct passwd *passwd;
		fd_set fds;
#if defined( __hpux )
		size_t maxFD = 0;
		int pageSize = 4096;			/* PHUX doesn't have getpagesize() */
#elif defined( _M_XENIX )
		int maxFD = 0, pageSize = 4096;	/* Nor does SCO, but it gets fd right */
#else
		int maxFD = 0, pageSize = getpagesize();
#endif /* OS-specific brokenness */
		int bufPos, i, usefulness = 0;

		/* Set up the shared memory */
		gathererBufSize = ( SHARED_BUFSIZE / pageSize ) * ( pageSize + 1 );
		if( ( gathererMemID = shmget( IPC_PRIVATE, gathererBufSize,
									  IPC_CREAT | 0600 ) ) == -1 )
			return;	/* Something broke */
		if( ( gathererBuffer = ( BYTE * ) shmat( gathererMemID, NULL, 0 ) ) == ( BYTE * ) -1 )
			return; /* Something broke */

		/* Fork off the gatherer, the parent process returns to the caller */
		if( ( gathererProcess = fork() ) || ( gathererProcess == -1 ) )
			return;	/* Error/parent process returns */

		fclose( stderr );	/* Arrghh!!  It's Stuart code!! */

		/* Make sure we don't call popen() as root */
		if( gathererID == -1 && \
			( passwd = getpwnam( "nobody" ) ) != NULL )
			gathererID = passwd->pw_uid;
		setuid( gathererID );

		/* Fire up each randomness source */
		FD_ZERO( &fds );
		for( i = 0; dataSources[ i ].path != NULL; i++ )
			{
			/* Since popen() is a fairly heavy function, we check to see
			   whether the executable exists before we try to run it */
			if( access( dataSources[ i ].path, X_OK ) )
				{
#ifdef DEBUG_RANDOM
				printf( "%s not present%s\n", dataSources[ i ].path,
						dataSources[ i ].hasAlternative ? ", has alternatives" : "" );
#endif /* DEBUG_RANDOM */
				dataSources[ i ].pipe = NULL;
				}
			else
				dataSources[ i ].pipe = my_popen( &dataSources[ i ] );
			if( dataSources[ i ].pipe != NULL )
				{
				dataSources[ i ].pipeFD = fileno( dataSources[ i ].pipe );
				if( dataSources[ i ].pipeFD > maxFD )
					maxFD = dataSources[ i ].pipeFD;
				fcntl( dataSources[ i ].pipeFD, F_SETFL, O_NONBLOCK );
				FD_SET( dataSources[ i ].pipeFD, &fds );
				dataSources[ i ].length = 0;

				/* If there are alternatives for this command, don't try and
				   execute them */
				while( dataSources[ i ].hasAlternative )
					{
#ifdef DEBUG_RANDOM
					printf( "Skipping %s\n", dataSources[ i + 1 ].path );
#endif /* DEBUG_RANDOM */
					i++;
					}
				}
			}
		gathererInfo = ( GATHERER_INFO * ) gathererBuffer;
		bufPos = sizeof( GATHERER_INFO );	/* Start of buf.has status info */

		/* Suck all the data we can get from each of the sources */
		moreSources = TRUE;
		while( moreSources && bufPos <= gathererBufSize )
			{
			/* Wait for data to become available from any of the sources,
			   with a timeout of 10 seconds.  This adds even more randomness
			   since data becomes available in a nondeterministic fashion.
			   Kudos to HP's QA department for managing to ship a select()
			   which breaks its own prototype */
			tv.tv_sec = 10;
			tv.tv_usec = 0;
#ifdef __hpux
			if( select( maxFD + 1, ( int * ) &fds, NULL, NULL, &tv ) == -1 )
#else
			if( select( maxFD + 1, &fds, NULL, NULL, &tv ) == -1 )
#endif /* __hpux */
				break;

			/* One of the sources has data available, read it into the
			   buffer */
			for( i = 0; dataSources[ i ].path != NULL; i++ )
				if( dataSources[ i ].pipe != NULL && \
					FD_ISSET( dataSources[ i ].pipeFD, &fds ) )
					{
					size_t noBytes;

					if( ( noBytes = fread( gathererBuffer + bufPos, 1,
										   gathererBufSize - bufPos,
										   dataSources[ i ].pipe ) ) == 0 )
						{
						if( my_pclose( &dataSources[ i ] ) == 0 )
							{
							int total = 0;

							/* Try and estimate how much entropy we're
							   getting from a data source */
							if( dataSources[ i ].usefulness )
								if( dataSources[ i ].usefulness < 0 )
									total = ( dataSources[ i ].length + 999 ) / \
											-dataSources[ i ].usefulness;
								else
									total = dataSources[ i ].length / \
											dataSources[ i ].usefulness;
#ifdef DEBUG_RANDOM
							printf( "%s %s contributed %d bytes "
									"(compressed), usefulness = %d\n",
									dataSources[ i ].path,
									( dataSources[ i ].arg != NULL ) ? \
									dataSources[ i ].arg : "",
									dataSources[ i ].length, total );
#endif /* DEBUG_RANDOM */
							usefulness += total;
							}
						dataSources[ i ].pipe = NULL;
						}
					else
						{
						int currPos = bufPos;
						int endPos = bufPos + noBytes;

						/* Run-length compress the input byte sequence */
						while( currPos < endPos )
							{
							int ch = gathererBuffer[ currPos ];

							/* If it's a single byte, just copy it over */
							if( ch != gathererBuffer[ currPos + 1 ] )
								{
								gathererBuffer[ bufPos++ ] = ch;
								currPos++;
								}
							else
								{
								int count = 0;

								/* It's a run of repeated bytes, replace
								   them with the byte count mod 256 */
								while( ( ch == gathererBuffer[ currPos ] ) && \
									   currPos < endPos )
									{
									count++;
									currPos++;
									}
								gathererBuffer[ bufPos++ ] = count;
								noBytes -= count - 1;
								}
							}

						/* Remember the number of (compressed) bytes of input
						   we obtained */
						dataSources[ i ].length += noBytes;
						}
					}

			/* Check if there is more input available on any of the sources */
			moreSources = FALSE;
			FD_ZERO( &fds );
			for( i = 0; dataSources[ i ].path != NULL; i++ )
				if( dataSources[ i ].pipe != NULL )
					{
					FD_SET( dataSources[ i ].pipeFD, &fds );
					moreSources = TRUE;
					}
			}
		gathererInfo->usefulness = usefulness;
		gathererInfo->noBytes = bufPos;
#ifdef DEBUG_RANDOM
		printf( "Got %d bytes, usefulness = %d\n", bufPos, usefulness );
#endif /* DEBUG_RANDOM */

		/* Child MUST exit here */
		exit( 0 );
		}
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   randomFlush(), which will block until the background process completes.
   At the moment this call is in the getRandomByte() routine */

static void randomFlush()
	{
	if( gathererProcess	)
		{
		GATHERER_INFO *gathererInfo = ( GATHERER_INFO * ) gathererBuffer;
		int	status;

		/* Wait for the gathering process to finish, add the randomness it's
		   gathered, and detach the shared memory */
		waitpid( gathererProcess, &status, 0 ); /* Should prob.check status */
		addRandomBuffer( gathererBuffer, gathererInfo->noBytes );
		if( gathererInfo->usefulness >= 25 )
			randomStatus = CRYPT_OK;
		zeroise( gathererBuffer, gathererBufSize );
		shmdt( gathererBuffer );
		shmctl( gathererMemID, IPC_RMID, NULL );
		gathererProcess = 0;
		}
	}
#else
  #error You need to create the OS-specific randomness-gathering functions for lib_rand.c
#endif /* Various OS-specific defines */

/****************************************************************************
*																			*
*							Random Pool External Interface					*
*																			*
****************************************************************************/

/* Add random data to the random pool.  We don't try to estimate the amount
   of entroy which we're adding due to the difficulty in doing this - if this
   sort of thing is required it's up to the user to look after it */

CRET cryptAddRandom( void CPTR randomData, int randomDataLength )
	{
	BYTE *randomDataPtr = ( BYTE * ) randomData;

	/* Perform basic error checking */
	if( randomData == NULL )
		{
		if( randomDataLength != CRYPT_RANDOM_FASTPOLL && \
			randomDataLength != CRYPT_RANDOM_SLOWPOLL )
			return( CRYPT_BADPARM1 );
		}
	else
		if( randomDataLength <= 0 )
			return( CRYPT_BADPARM2 );

	/* If the random data pool doesn't exist yet, create it now */
	if( randomPool == NULL )
		{
		int status;

#ifdef __WIN32__
		InitializeCriticalSection( &randProt );
		if( ( threadEvent = CreateEvent( NULL, FALSE, FALSE, NULL ) ) == NULL )
			return( CRYPT_NOMEM );	/* Anon.event, auto reset, not signalled */
#endif /* __WIN32__ */

		if( ( status = secureMalloc( ( void ** ) &randomPool,
									 RANDOMPOOL_ALLOCSIZE ) ) != CRYPT_OK )
			return( status );
		randomWritePos = randomReadPos = 0;
		randomStatus = CRYPT_NORANDOM;
		}

	/* If we're adding data to the pool, add it now and exit */
	if( randomData != NULL )
		{
		threadSafeAddRandomBuffer( randomDataPtr, randomDataLength );

		/* We assume that the externally-added randomness is strong enough to
		   satisfy the requirements for good random data.  Presumably anyone
		   who bothers to use this call will ensure that they're using
		   appropriate data such as the output of a hardware source and not
		   just a call to time() */
		randomStatus = CRYPT_OK;

		return( CRYPT_OK );
		}

	/* Perform either a fast or slow poll for random system data */
	if( randomDataLength == CRYPT_RANDOM_FASTPOLL )
		fastPoll();
	else
		slowPoll();

	return( CRYPT_OK );
	}

/* Generate a session key in an encryption context from data in the random
   pool */

CRET cryptGenerateContextEx( CRYPT_CONTEXT cryptContext, const int userKeyLength )
	{
	CRYPT_INFO *cryptInfoPtr = CONTEXT_TO_INFO( cryptContext );
	CAPABILITY_INFO *capabilityInfoPtr;
	int keyLength;

	/* Perform basic error checking */
	if( isBadCookie( cryptContext ) )
		return( CRYPT_BADPARM1 );
	if( cryptInfoPtr->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;

	/* If it's a hash function or PKC, the session key generate operation is
	   meaningless */
	if( cryptInfoPtr->capabilityInfo->cryptMode == CRYPT_MODE_NONE || \
		cryptInfoPtr->isPKCcontext )
		return( CRYPT_NOTAVAIL );

	/* Determine the number of random bytes we'll need.  In order to avoid
	   problems with space inside shorter RSA-encrypted blocks, we limit the
	   total keysize to 448 bits, which is adequate for all purposes - the
	   limiting factor is three-key triple DESX, which requires ( 3 * 64 ) +
	   ( 4 * 64 ) bits of key, and absolutely must have that many bits or it
	   just reduces to triple-DES with a bit of DESX.  Unfortunately we can't
	   tell what the user is going to do with the generated key so we have to
	   take the approach of using the shortest possible length.  This means
	   that the default keys generated for Blowfish, MDC/SHS, and triple DESX
	   can't be exported when very short RSA keys are used */
	if( ( keyLength = userKeyLength ) == CRYPT_USE_DEFAULT )
		if( capabilityInfoPtr->getKeysizeFunction != NULL )
			keyLength = capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr );
		else
			keyLength = capabilityInfoPtr->maxKeySize;
	if( keyLength > bitsToBytes( 448 ) )
		keyLength = bitsToBytes( 448 );
	if( keyLength > RANDOMPOOL_SIZE )
		return( CRYPT_BADPARM3 );

	/* Perform a failsafe check - this should only ever be called once per
		app, because after the first blocking poll the programmer of the
		calling app will make sure there's a slow poll done earlier on */
	if( randomPool == NULL )
		cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );
#if defined( __UNIX__ ) || defined( __WIN32__ )
	randomFlush();	/* Make sure any gatherer thread/process has completed */
#endif /* __UNIX__ || __WIN32__ */

	/* If we still can't get any random information, let the user know */
	if( cryptStatusError( randomStatus ) )
		return( randomStatus );

	/* Load a session key into the encryption context.  Before we use the
	   information from the random pool, we perform a final quick poll of
	   the system to get any last bit of entropy.  We then pass the
	   (probably pagelocked) random pool directly to cryptLoadContext() to
	   avoid copying it to a pageable temporary buffer.
	   Note that we don't want to set the clearBuffer flag in the encryption
	   context here because (a) the entropy pool is probably pagelocked
	   anyway and (b) we don't want to lose the contents of the pool */
	fastPoll();
#ifdef __WIN32__
	EnterCriticalSection( &randProt );
#endif /* __WIN32__ */
	mixRandomPool();
#ifdef __WIN32__
	LeaveCriticalSection( &randProt );
#endif /* __WIN32__ */
	return( cryptLoadContext( cryptContext, randomPool, keyLength ) );
	}

/* Retrieve data from the random pool */

int getRandomByte( void )
	{
#if defined( __UNIX__ ) || defined( __WIN32__ )
	randomFlush();	/* Make sure any gatherer thread/process has completed */
#endif /* __UNIX__ || __WIN32__ */

	/* Perform a failsafe check - this should only ever be called once per
	   app, because after the first blocking poll the programmer of the
	   calling app will make sure there's a slow poll done earlier on */
	if( randomPool == NULL )
		cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );

	/* If we still can't get any random information, let the user know */
	if( cryptStatusError( randomStatus ) )
		return( randomStatus );

	/* If there's newly-written (and currently unmixed) data in the pool or
	   we've reached the end of the pool, mix it up, then return the next
	   byte in the pool */
	if( randomWritePos || randomReadPos > RANDOMPOOL_SIZE )
		mixRandomPool();
	return( randomPool[ randomReadPos++ ] );
	}

/* Shut down the random data pool */

void endRandom( void )
	{
#if defined( __WIN32__ )
	if( threadID != NULL )
		CloseHandle( threadID );
	if( threadEvent != NULL )
		CloseHandle( threadEvent );
	DeleteCriticalSection( &randProt );
	if( hNetAPI32 )
		{
		FreeLibrary( hNetAPI32 );
		hNetAPI32 = NULL;
		}
#endif /* __WIN32__ */
	if( randomPool != NULL )
		{
		secureFree( ( void ** ) &randomPool );
		randomWritePos = randomReadPos = 0;
		}
	}
