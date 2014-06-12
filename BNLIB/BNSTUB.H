/* Replace the bignum code with dummy functions for now to save space */

#define bnInit()
#define bnBegin( bn )
#define bnSwap( a, b )
#define bnEnd( bn )
#define bnCopy( dest, src )
#define bnExtractBigBytes( bn, dest, lsbyte, len )
#define bnInsertBigBytes( bn, src, lsbyte, len )
#define bnExtractLittleBytes( bn, dest, lsbyte, len )
#define bnInsertLittleBytes( bn, src, lsbyte, len )
#define bnAdd( dest, src )
#define bnSub( dest, src )
#define bnSetQ( dest, src )
#define bnAddQ( dest, src )
#define bnSubQ( dest, src )
#define bnCmp( a, b )	0
#define bnSquare( dest, src )
#define bnMul( dest, a, b )
#define bnMod( dest, src, d )
#define bnExpMod( result, n, exp, mod )	-1
