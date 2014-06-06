/* Copyright (C) 1998-99 Paul Le Roux. All rights reserved. Please see the
   file license.txt for full license details. paulca@rocketmail.com */

#include "e4mdefs.h"
#include "endian.h"

void
LongReverse (unsigned long *buffer, unsigned byteCount)
{
	unsigned long value;

	byteCount /= sizeof (unsigned long);
	while (byteCount--)
	{
		value = *buffer;
		value = ((value & 0xFF00FF00L) >> 8) | \
		    ((value & 0x00FF00FFL) << 8);
		*buffer++ = (value << 16) | (value >> 16);
	}
}
