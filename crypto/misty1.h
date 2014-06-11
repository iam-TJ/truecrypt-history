#define MISTY1_KEYSIZE 32

unsigned long fi ( unsigned long fi_in , unsigned long fi_key );
unsigned long fo ( unsigned long *ek , unsigned long fo_in , unsigned char k );
unsigned long fl ( unsigned long *ek , unsigned long fl_in , unsigned char k );
unsigned long flinv ( unsigned long *ek , unsigned long fl_in , unsigned char k );
void misty1_encrypt_block ( unsigned long *ek , unsigned long p [2 ], unsigned long c [2 ]);
void misty1_decrypt_block ( unsigned long *ek , unsigned long c [2 ], unsigned long p [2 ]);
void misty1_keyinit ( unsigned long *ek , unsigned long *k );
