#include <iostream>
#include <chrono>
#include <omp.h>
#include <immintrin.h>

#include <bits/stdc++.h> 
#define NPROC 8
#define BLOCK_SIZE 8



void itv(const double r, double* x, const int64_t n, const int64_t itn) {
    double *x_ptr = x;
    // __m512d m512_buf[n / 8];
    const __m512d r512 = _mm512_set1_pd(r);
    const __m512d one512 = _mm512_set1_pd(1.0);
    __m512d m512_tmp;
    __m512d *m512_arr = (__m512d *)x;

    // printf("r512 data: %lf,%lf,%lf,%lf", ((double *)(&r512))[0], ((double *)(&r512))[1], ((double *)(&r512))[2], ((double *)(&r512))[3]);

    

    for (int64_t i = 0; i < n / 8; i++) {
        // m512_tmp = _mm512_loadu_pd(x_ptr);
        for (int64_t j = 0; j < itn; j++) {


            m512_arr[0] = _mm512_mul_pd(_mm512_mul_pd(r512, m512_arr[0]),
                     _mm512_sub_pd(one512, m512_arr[0]));
        }
        // _mm512_storeu_pd(x_ptr, m512_tmp);
        // x_ptr += 8;
        m512_arr ++;
    }
    return;
}

int main() {

    FILE* fi;
    fi = fopen("conf.data", "rb");

    int64_t itn;
    double r;
    int64_t n;
    double* x;

    fread(&itn, 1, 8, fi);
    fread(&r, 1, 8, fi);
    fread(&n, 1, 8, fi);
    x = (double*)aligned_alloc(64, n * 8);
    fread(x, 1, n * 8, fi);
    fclose(fi);

    const __m512d r512 = _mm512_set1_pd(r);
    const __m512d one512 = _mm512_set1_pd(1.0);
    __m512d *m512_arr = (__m512d *)x;

    auto t1 = std::chrono::steady_clock::now();
    #pragma omp parallel for num_threads(NPROC)
    for (int64_t i = 0; i < n / 8; i+=BLOCK_SIZE) {
        for (int64_t j = 0; j < itn; j++) {
            for(int64_t k=0; k < BLOCK_SIZE; k++){
                m512_arr[k] = _mm512_mul_pd(_mm512_mul_pd(r512, m512_arr[k]),
                        _mm512_sub_pd(one512, m512_arr[k]));
            }
        }
        m512_arr += BLOCK_SIZE;
    }
        

    auto t2 = std::chrono::steady_clock::now();
    int d1 = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    printf("%d\n", d1);

    fi = fopen("out.data", "wb");
    fwrite(x, 1, n * 8, fi);
    fclose(fi);


  return 0;
}