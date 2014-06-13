#include <sys/time.h>
typedef unsigned long u4;
typedef unsigned char byte;


/* 1Mbyte == 131072 blocks*/
#define LOOP  131072
main()
{
  u4  ek[32];
  u4  t[]= {0x01234567, 0x89abcdef};
  u4  Key[]= {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff};
  u4  c[2];
  int i;
  int ds,dms;
  double df;
  struct timeval  t1, t2;
  struct timezone tz;

  gettimeofday(&t1,&tz);
  misty1_keyinit(ek,Key);
  for(i=0;i<LOOP;i++) {
    misty1_encrypt_block(ek,t,c);
  }
  gettimeofday(&t2,&tz);

  ds = t2.tv_sec - t1.tv_sec;
  dms = t2.tv_usec - t1.tv_usec;
  ds -= (dms < 0)? (1):(0);
  dms += (dms < 0)? (1000000):(0);
  printf("Time: %d.%3.3dsec\t",ds,dms/1000);
  df = ds*1000 + (dms/1000);
  printf("Rate: %0.0fKbps\n",((LOOP * 8)/df)*8 );

}

