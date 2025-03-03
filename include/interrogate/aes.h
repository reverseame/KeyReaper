#ifndef AES_INTERROGATE_H
#define AES_INTERROGATE_H

#include <windows.h>
#include <vector>
#include <algorithm>

namespace interrogate {

typedef struct {
  unsigned int     keytype, /* Keytype to be searched for */
  keysize,                  /* The key size that are to be searched for */
  wsize,                    /* The search window size */
  nofs,                     /* The number of symbols in our alphabet */
  bitmode,                  /* Bitmode boolean */
  verbose,                  /* Verbose mode */
  naivemode,                /* Calculate true entropy */
  quickmode,                /* Non-overlapping entropy windows */
  interval,                 /* Only search in interval (boolean) */
  from,                     /* Starting point */
  to,                       /* End point */
  cr3,                      /* CR3 offset in case recunstruction of mem */
  filelen,                  /* Input file length in bytes */
  bytethreshold;            /* Threshold for bytecount */
  FILE    *output_fp;       /* Pointer to output file for statistics */
  float   threshold;        /* Entropy threshold */
  long    count;            /* Number of keys found */
}
interrogate_context;

void rotate(unsigned char *in);
unsigned char rcon(unsigned char in);
unsigned char gmul(unsigned char a, unsigned char b);
unsigned char gmul_inverse(unsigned char in);
unsigned char sbox(unsigned char in);
void schedule_core(unsigned char *in, unsigned char i);
void expand_key(unsigned char *in);
void expand_key_192(unsigned char *in);
void expand_key_256(unsigned char *in);

std::vector<std::vector<BYTE>> aes_search(interrogate_context* ctx, unsigned char* buffer);

} // namespace interrogate

#endif // AES_INTERROGATE_H