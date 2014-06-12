/****************************************************************************
*																			*
*						  SHA Message Digest Algorithm 						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "sha.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "sha.h"
#else
  #include "crypt.h"
  #include "hash/sha.h"
#endif /* Compiler-specific includes */

/* Bring in the SHA core code */

#if defined( _MSC_VER ) || defined( __MWERKS__ )
  #include "shacore.c"
#else
  #include "hash/shacore.c"
#endif /* Compiler-specific includes */
