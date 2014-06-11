/************************************************
The Tiny Encryption Algorithm (TEA) by
David Wheeler and Roger Needham of the
Cambridge Computer Laboratory

***  Inline assembler for encipher/decipher code ***

Notes:
TEA is a Feistel cipher with XOR and
and addition as the non-linear mixing
functions.

Takes 64 bits of data in v[0] and v[1].
Takes 128 bits of key in k[0] - k[3].

TEA can be operated in any of the modes
of DES. Cipher Block Chaining is, for example,
simple to implement.

n is the number of iterations. 32 is ample,
16 is sufficient, as few as eight may be OK.
The algorithm achieves good dispersion after
six iterations. The iteration count can be
made variable if required.

Note this is optimised for 32-bit CPUs with
fast shift capabilities. It can very easily
be ported to assembly language on most CPUs.

delta is chosen to be the real part of (the
golden ratio Sqrt(5/4) - 1/2 ~ 0.618034
multiplied by 2^32).

************************************************/

#include "tea_asm.h"

void teaencipher(unsigned long *const v,teakey *tk)
{
	unsigned  long * k=(unsigned long *) tk;
	int		rounds=tk->rounds;

	/* Implements:
	 y += (z<<4)+a ^ z+sum ^ (z>>5)+b;
	 z += (y<<4)+c ^ y+sum ^ (y>>5)+d;
	 for each round  */

	_asm
        {
;Encrypt:
		mov edi,[v]           ;buffer v
		mov esi,[k]           ;key    k
		mov     ebx,[edi]     ;ebx=v[0] y
        mov     ecx,[edi+4]   ;ecx=v[1] z 
        xor     eax,eax
        mov     edx,9e3779b9h ; sqr(5)-1 * 2^31
        push ebp              ;save local pointer
		push edi              ;save buffer pntr
		mov edi,[rounds]      ;load in round count
ELoopR: add     eax,9e3779b9h ;eax=eax+delta
		mov     ebp,ecx     ;z
        shl     ebp,4       ;z<<4
        add     ebp,[esi]    ;(z<<4)+a		
		mov edx,ecx         ;z
		shr edx,5           ;z>>5
		add edx,[esi+4]     ;(z>>5)+b
		xor ebp,edx         ; ( (z<<4)+a ) ^ ( (z>>5)+b)
		lea edx,[ecx+eax]   ;edx+z+sum
		xor ebp,edx          
		add ebx,ebp	  ;
		mov ebp,ebx			;y
		shr ebp,5			;y>>5
		add ebp,[esi+12]	;d
		mov edx,ebx
		shl edx,4
		add edx,[esi+8]		;c
		xor ebp,edx
	    lea edx,[eax+ebx]   ;edx=sum+y
		xor ebp,edx         ;^
		add ecx,ebp         ;z+= 
        dec     edi
		jnz     ELoopR
		pop edi
		pop ebp
        mov     [edi],ebx
        mov     [edi+4],ecx
		}

}

void teadecipher(unsigned long *const v,teakey *tk)
{
	unsigned  long *k=(unsigned long *) tk;	
	int		rounds=tk->rounds;
	int		sum=0x9e3779b9*rounds;

	/* implements:
	z -= (y<<4)+c ^ y+sum ^ (y>>5)+d;
	y -= (z<<4)+a ^ z+sum ^ (z>>5)+b;
	 for each round */

	_asm
	   {
;Decrypt
	    pushad
		mov edi,[v]
		mov esi,[k]
        mov     ebx,[edi]      ;Y
        mov     ecx,[edi+4]    ;Z
		mov eax,[sum]
		push ebp
		push edi
		mov edi,[rounds]
DLoopR: mov     ebp,ebx     ;y
        shl     ebp,4       ;y<<4
        add     ebp,[esi+8]    ;(y<<4)+d		
		mov edx,ebx         ;y
		shr edx,5           ;y>>5
		add edx,[esi+12]    ;(y>>5)+d
		xor ebp,edx         ; ( (y<<4)+a ) ^ ( (y>>5)+c)
		lea edx,[ebx+eax]   ;edx+z+sum
		xor ebp,edx 
		sub ecx,ebp	  ;
		mov ebp,ecx		;z
		shr ebp,5		;z>>5
		add ebp,[esi+4] ;d
		mov edx,ecx
		shl edx,4
		add edx,[esi] ;c
		xor ebp,edx
		lea edx,[eax+ecx] ;edx=sum+y
		xor ebp,edx       ;^
		sub ebx,ebp       ;y=
		sub eax,9e3779b9h ;sum-=delta
        dec     edi       ;count
        jnz     DLoopR
		pop edi           ;restore buffer
		pop ebp           ;restore locals
        mov     [edi],ebx
        mov     [edi+4],ecx
   		popad

		}

}

void inittea(unsigned long *keypntr,void *ks, int rounds)
{
	teakey* t=ks;

	t->ka=keypntr[0];
	t->kb=keypntr[1];
	t->kc=keypntr[2];
	t->kd=keypntr[3];
	t->rounds=rounds;
}

