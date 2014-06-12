/*
 * bn00.c - auto-size-detecting bn??.c file.
 *
 * Written in 1995 by Colin Plumb.
 */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "bnsize00.h"
#else
  #include "bnlib/bnsize00.h"
#endif /* Compiler-specific includes */

#if BNSIZE64

/* Include all of the C source file by reference */
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "bn64.c"
  #include "bninit64.c"
#else
  #include "bnlib/bn64.c"
  #include "bnlib/bninit64.c"
#endif /* Compiler-specific includes */

#elif BNSIZE32

/* Include all of the C source file by reference */
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "bn32.c"
  #include "bninit32.c"
#else
  #include "bnlib/bn32.c"
  #include "bnlib/bninit32.c"
#endif /* Compiler-specific includes */

#else /* BNSIZE16 */

/* Include all of the C source file by reference */
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "bn16.c"
  #include "bninit16.c"
#else
  #include "bnlib/bn16.c"
  #include "bnlib/bninit16.c"
#endif /* Compiler-specific includes */

#endif
