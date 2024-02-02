#include <iostream>
#include <chrono>
#include <omp.h>
#include <immintrin.h>
#include <bits/stdc++.h> 

using namespace std;



# define BLOCK_SIZE 16

void mul(double* a, double* b, double* c,const uint64_t n1,const uint64_t n2,const uint64_t n3) {
  
#pragma omp parallel for num_threads(8) collapse(3)
for (int ii = 0; ii < n1; ii += BLOCK_SIZE){
		for (int jj = 0; jj < n2; jj += BLOCK_SIZE){
			for (int kk = 0; kk < n3; kk += BLOCK_SIZE){
        
        // NOTE: for n != 2**s, use std::min(ii+BLOCK_SIZE, n)
        double rot_buf[BLOCK_SIZE * BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
          memcpy(&rot_buf[i * BLOCK_SIZE], &a[(i + ii) * n2 + (jj)], 8 * BLOCK_SIZE);
        }
        double *rot_buf_ptr = rot_buf;
        for (int i = ii; i < ii + BLOCK_SIZE; i++) {
          for (int j = jj; j < jj + BLOCK_SIZE; j++) {
            __m512d ra = _mm512_set1_pd(*rot_buf_ptr);
            rot_buf_ptr ++;
            int k = kk;
            for (; k < kk + BLOCK_SIZE; k+=8) {
                *(__m512d *)(&c[i * n3 + k]) = _mm512_fmadd_pd(ra, *(__m512d *)(&b[j * n3 + k]), *(__m512d *)(&c[i * n3 + k]));
            }
          }
        }


      }
    }
  }
}



int main() {
 uint64_t n1, n2, n3;
 FILE* fi;

 fi = fopen("conf.data", "rb");
 fread(&n1, 1, 8, fi);
 fread(&n2, 1, 8, fi);
 fread(&n3, 1, 8, fi);

 double* a = (double*)aligned_alloc(64, n1 * n2 * 8);
 double* b = (double*)aligned_alloc(64, n2 * n3 * 8);
 double* c = (double*)aligned_alloc(64, n1 * n3 * 8);
 memset(c, 0, n1 * n3 * 8);

 fread(a, 1, n1 * n2 * 8, fi);
 fread(b, 1, n2 * n3 * 8, fi);
 fclose(fi);

 

 auto t1 = std::chrono::steady_clock::now();
 mul(a, b, c, n1, n2, n3);
 auto t2 = std::chrono::steady_clock::now();
 int d1 = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
 printf("%d\n", d1);


 fi = fopen("out.data", "wb");
 fwrite(c, 1, n1 * n3 * 8, fi);
 fclose(fi);

 return 0;
}