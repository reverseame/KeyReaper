#ifndef AES_INTERROGATE_H
#define AES_INTERROGATE_H

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


void print_hex_array(unsigned char *buffer, int length, int columns) {
  int i;
  for (i = 0; i < length; i++) {
    if ((i % columns) == 0)
      printf("\n");
    printf("%02x ", buffer[i]);
  }
  printf("\n\n");
}

std::vector<std::vector<BYTE>> aes_search(interrogate_context* ctx, unsigned char* buffer) {
  auto found_keys = vector<BYTE>();
	unsigned int i;

	/* Set key schedule sizes */
	unsigned int kssize = 176;
	if (ctx->keysize == 192) {
		kssize = 208;
	} else if (ctx->keysize == 256) {
		kssize = 240;
	}

	unsigned char* ks = (unsigned char*) malloc(kssize * sizeof(unsigned char));

	for (i = ctx->from; i < ctx->filelen - kssize; i++) {
		/* Copy a chunk of data from buffer, expand it using AES key
		 * schedule routines */
		ks = (unsigned char*) memcpy(ks, &buffer[i], kssize);
		if ((ctx->keysize == 128))
			expand_key(ks);
		else if ((ctx->keysize == 192))
			expand_key_192(ks);
		else
			expand_key_256(ks);
		/* Compare expanded key schedule to the data proceeding the chunk */
		if (memcmp(ks, &buffer[i], kssize) == 0) {
			ctx->count++;
			printf("Found (probable) AES key at offset %.8x:\n", i);
			print_hex_array(ks, ctx->keysize / 8, 16);
			printf("Expanded key:\n");
			print_hex_array(ks, kssize, 16);
      auto key = vector<BYTE>(ctx->keysize, 0);
      memcpy(key.data(), ks, min(key.size(), kssize));
      found_keys.push_back(move(key));
		}
	}
  if (ctx->count == 0) printf("Did not found any keys\n");

  return found_keys;
}

} // namespace interrogate

#endif // AES_INTERROGATE_H