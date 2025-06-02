#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "aesenc.c"
int md5(){
#define MD5_A 0x67452301
#define MD5_B 0xefcdab89
#define MD5_C 0x98badcfe
#define MD5_D 0x10325476

static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
static uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,                                                                                                                                                                    
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,                                                                                                                                                                    
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,                                                                                                                                                                    
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,                                                                                                                                              
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                                                                                                                                           
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                                                                                                                                              
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                                                                                                                                              
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                                                                                                                                               
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                                                                                                                                             
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

uint32_t rotateLeft(uint32_t x, uint32_t n){
    return (x << n) | (x >> (32 - n));
}

typedef struct{
    uint64_t input_size;
    uint32_t state[4];
    uint8_t block[64];
    uint8_t hash[16];
} MD5Context;

void md5Init(MD5Context *ctx){
    ctx->input_size = (uint64_t)0;
    ctx->state[0] = (uint32_t)MD5_A;
    ctx->state[1] = (uint32_t)MD5_B;
    ctx->state[2] = (uint32_t)MD5_C;
    ctx->state[3] = (uint32_t)MD5_D;
}
void md5Step(uint32_t *state, uint32_t *block){
    uint32_t A = state[0];
    uint32_t B = state[1];
    uint32_t C = state[2];
    uint32_t D = state[3];
    uint32_t E;
    unsigned int j;
    for(unsigned int i = 0; i < 64; ++i){
        switch(i / 16){
            case 0: E = F(B, C, D); j = i; break;
            case 1: E = G(B, C, D); j = ((i * 5) + 1) % 16; break;
            case 2: E = H(B, C, D); j = ((i * 3) + 5) % 16; break;
            default: E = I(B, C, D); j = (i * 7) % 16; break;
        }
        uint32_t temp = D;
        D = C;
        C = B;
        B = B + rotateLeft(A + E + K[i] + block[j], S[i]);
        A = temp;
    }
    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
}

void md5Update(MD5Context *ctx, uint8_t *input, size_t input_len){
    uint32_t block[16];
    unsigned int offset = ctx->input_size % 64;
    ctx->input_size += (uint64_t)input_len;
    for(unsigned int i = 0; i < input_len; ++i){
        ctx->block[offset++] = (uint8_t)*(input + i);
        if(offset % 64 == 0){
            for(unsigned int j = 0; j < 16; ++j){
                block[j] = (uint32_t)(ctx->block[(j * 4) + 3]) << 24 |
                           (uint32_t)(ctx->block[(j * 4) + 2]) << 16 |
                           (uint32_t)(ctx->block[(j * 4) + 1]) <<  8 |
                           (uint32_t)(ctx->block[(j * 4)]);
            }
            md5Step(ctx->state, block);
            offset = 0;
        }
    }
}

void md5Finalize(MD5Context *ctx){
    uint32_t block[16];
    unsigned int offset = ctx->input_size % 64;
    unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;
    md5Update(ctx, PADDING, padding_length);
    ctx->input_size -= (uint64_t)padding_length;
    for(unsigned int j = 0; j < 14; ++j){
        block[j] = (uint32_t)(ctx->block[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->block[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->block[(j * 4) + 1]) <<  8 |
                   (uint32_t)(ctx->block[(j * 4)]);
    }
    block[14] = (uint32_t)(ctx->input_size * 8);
    block[15] = (uint32_t)((ctx->input_size * 8) >> 32);
    md5Step(ctx->state, block);
    for(unsigned int i = 0; i < 4; ++i){
        ctx->hash[(i * 4) + 0] = (uint8_t)((ctx->state[i] & 0x000000FF));
        ctx->hash[(i * 4) + 1] = (uint8_t)((ctx->state[i] & 0x0000FF00) >>  8);
        ctx->hash[(i * 4) + 2] = (uint8_t)((ctx->state[i] & 0x00FF0000) >> 16);
        ctx->hash[(i * 4) + 3] = (uint8_t)((ctx->state[i] & 0xFF000000) >> 24);
    }
}


void md5String(char *input, uint8_t *result){
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, (uint8_t *)input, strlen(input));
    md5Finalize(&ctx);
    memcpy(result, ctx.hash, 16);
}

void print_hash(uint8_t *p){
    for(unsigned int i = 0; i < 16; ++i){
        printf("%02x", p[i]);
    }
    printf("\n");
}

int md5hash() {
    FILE *file = fopen("input.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file: input.txt\n");
        return 1;
    }

    FILE *outputFile = fopen("output.txt", "w"); 
    if (outputFile == NULL) {
        fprintf(stderr, "Error creating file: output.txt\n");
        fclose(file);
        return 1;
    }

    char line[256];
    uint8_t result[16];

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        md5String(line, result);
        fprintf(outputFile, "%s: ", line);
        for (int i = 0; i < 16; i++) {
            fprintf(outputFile, "%02x", result[i]);
        }
        fprintf(outputFile, "\n");
    }
    printf("Output written to output.txt");
    fclose(file);
    fclose(outputFile);
    return 0;
}
md5hash();
}
int sha256(){
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define SHR(x, n) (x >> n)

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t new_len = len + 1 + 8;
    while (new_len % 64 != 0) new_len++;
    uint8_t *padded = calloc(new_len, 1);
    memcpy(padded, data, len);
    padded[len] = 0x80;
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++)
        padded[new_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
    
    for (size_t i = 0; i < new_len; i += 64) {
        uint32_t W[64];
        for (int j = 0; j < 16; j++)
            W[j] = (padded[i + j * 4] << 24) | (padded[i + j * 4 + 1] << 16) |
                   (padded[i + j * 4 + 2] << 8) | (padded[i + j * 4 + 3]);
        for (int j = 16; j < 64; j++)
            W[j] = sig1(W[j - 2]) + W[j - 7] + sig0(W[j - 15]) + W[j - 16];
        
        uint32_t a, b, c, d, e, f, g, h;
        a = H[0]; b = H[1]; c = H[2]; d = H[3];
        e = H[4]; f = H[5]; g = H[6]; h = H[7];
        
        for (int j = 0; j < 64; j++) {
            uint32_t T1 = h + SIG1(e) + CH(e, f, g) + K[j] + W[j];
            uint32_t T2 = SIG0(a) + MAJ(a, b, c);
            h = g; g = f; f = e;
            e = d + T1;
            d = c; c = b; b = a;
            a = T1 + T2;
        }
        
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }
    free(padded);
}

void generateRainbowTable(const char *inputFilename) {
    FILE *inputFile = fopen(inputFilename, "r");
    if (!inputFile) {
        printf("Failed to open input file\n");
        return;
    }

    FILE *outputFile = fopen("output.txt", "w");  
    if (!outputFile) {
        printf("Failed to create output file\n");
        fclose(inputFile);
        return;
    }

    char line[256];
    uint8_t hash[32];  
    while (fgets(line, sizeof(line), inputFile)) {
        line[strcspn(line, "\n")] = 0; 
        sha256((uint8_t *)line, strlen(line), hash);

        fprintf(outputFile, "%s: ", line);
        for (int i = 0; i < 32; i++) {
            fprintf(outputFile, "%02x", hash[i]);
        }
        fprintf(outputFile, "\n");
    }

    fclose(inputFile);
    fclose(outputFile);
}

int sha256hash() {
    generateRainbowTable("input.txt");
    printf("Output written to output.txt");
    return 0;
}
sha256hash();
}
int encryption(){
int choice;
    printf("Select an option:\n");
    printf("1. Encrypt a file\n");
    printf("2. Decrypt a file\n");
    printf("Enter your choice (1 or 2): ");
    scanf("%d", &choice);
    uint8_t key[16];
    if (choice == 1) {
        srand((unsigned int)time(NULL));
        for (int i = 0; i < 16; i++) {
            key[i] = (uint8_t)(rand() % 256);  
        }
        printf("Generated Key: ");
        for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
        }
        printf("\n");
        const char* input_file = "output.txt";
        const char* output_file = "encrypted.bin";
        encrypt_file(input_file, output_file, key);
        printf("File encrypted successfully. Encrypted file: %s\n", output_file);
    } else if (choice == 2) {
        char key_input[33];
        int i;
        const char* input_file = "encrypted.bin";
        const char* output_file = "decrypted.txt";
        printf("Enter key:");
        scanf("%32s",&key_input[i]);
         for (int i = 0; i < 16; i++) {
            sscanf(&key_input[i * 2], "%2hhx", &key[i]);
        }
        decrypt_file(input_file, output_file, key);
        printf("File decrypted successfully. Decrypted file: %s\n", output_file);
    } else {
        printf("Invalid choice. Please select 1 or 2.\n");
    }
    return 0;
}

int main(){
int a;
printf("Enter a number\n----------------------------------\n1 for MD5\n2 for SHA-256\n3 for encryption and decryption\n----------------------------------\n");
scanf("%d",&a);
switch (a) {
  case 1:
    md5();
    break;
  case 2:
    sha256();
    break;
  case 3:
    encryption();
  default:
    printf("Program exited!!");
}
}
