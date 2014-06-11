typedef struct teakey
{
unsigned long ka;
unsigned long kb;
unsigned long kc;
unsigned long kd;
unsigned long rounds;
}teakey;

void teaencipher ( unsigned long *const v , teakey *tk );
void teadecipher ( unsigned long *const v , teakey *tk );
void inittea ( unsigned long *keypntr , void *ks , int rounds );
