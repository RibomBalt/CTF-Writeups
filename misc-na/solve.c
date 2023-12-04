#include <stdio.h>
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

unsigned int KNOWN_RES[100000] = {0xffffffff};

void dump(int n_case){
    
    for (int i = 0; i < n_case; i++) {
        int t, l, r;
        scanf("%d %d %d", &t, &l, &r);
        printf("%08x%08x%08x",t,l,r);
    }
}

unsigned int masked_min(unsigned int *arr, unsigned int *mask, int len){
    if (len == 1){
        return (mask[0]) ? arr[0] : 0xffffffff;
    }else{
        return MIN(masked_min(arr, mask, (len >> 1)), 
            masked_min(arr + (len >> 1), mask + (len >> 1), (len >> 1) + (len & 1)));
    }
}

int main() {
    int nswi;
    scanf("%d", &nswi);
    
    unsigned int an[100000];
    for (int i = 0; i < nswi; i++) {
        scanf("%d", &an[i]);
    }
    
    unsigned int onoff[100000];

    char tmp[2];
    fread(tmp, 1, 1, stdin);
    
    for (int i = 0; i < nswi; i++) {
        char s;
        fread(&s, 1, 1, stdin);
        onoff[i] = (s == '1');
    }
    
    int n_case;
    scanf("%d", &n_case);

    // if (nswi == 100000){
    //     dump(n_case);
    // }
    
    unsigned int t, l, r, t_o=0, l_o=0, r_o=0;
    for (int i = 0; i < n_case; i++) {
        t_o = t; l_o = l; r_o = r;
        scanf("%d %d %d", &t, &l, &r);

        // if ((t == 2) && (t_o == 2) && (l_o == l) && (r_o == r)){

        // }
        
        if (t == 1) {
            for (int j = l-1; j < r; j++) {
                onoff[j] = !onoff[j];
            }
        } else {
            int ok_switch[r-l+1];
            unsigned int min_switch = 0xffffffff;

            min_switch = masked_min(
                &an[l - 1],
                &onoff[l - 1],
                r - l + 1
            );

            // for (int j = l-1; j < r; j++) {
            //     if (onoff[j]) {
            //         if (an[j] < min_switch){
            //             min_switch = an[j];
            //         }
            //     }
            // }
            
            if(min_switch == 0xffffffff){
                min_switch = 0;
            }
            printf("%d\n", min_switch);
        }
    }
    
    return 0;
}

