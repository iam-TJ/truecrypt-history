/*
 * bn8086.c - bnInit() for Intel x86 family in 16-bit mode.
 *
 * Written in 1995 by Colin Plumb.
 */

#if defined( INC_CHILD )
  #include "lbn.h"
  #include "bn16.h"
  #include "bn32.h"
#else
  #include "bnlib/lbn.h"
  #include "bnlib/bn16.h"
  #include "bnlib/bn32.h"
#endif /* INC_CHILD */

#ifndef BNINCLUDE
#error You must define BNINCLUDE to lbn8086.h to use assembly primitives.
#endif

void
bnInit(void)
{
	if (not386())
		bnInit_16();
	else
		bnInit_32();
}
