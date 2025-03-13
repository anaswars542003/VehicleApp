
#include<string.h>
#include<time.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <asm-generic/socket.h>
#include"sok.h"
#include"oer.h"

#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define COUNTER_FILE "sends/counter.txt"
#define FILE_PREFIX "sends/data"


void read_keys_init(big sk, char* c, epoint* c1, char* cid);
size_t read_message(char* msg);
size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid, uint8_t* encoded_data);
void decode_example(uint8_t *encoded_data, size_t encoded_size);
void send_enc_data(char* encoded_buffer,size_t encoded_msg_size);


void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        else if ((i + 1) % 4 == 0)
            printf(" ");
    }
    printf("\n");
}


int main(int argc, char* argv[])
{
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;

    
    signature_t sig;

    big a = mirvar(0);
    big b = mirvar(0);
    big q = mirvar(0);

    cinstr(a, a_str);
    cinstr(b, b_str);
    cinstr(q, q_str);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, x_str);
    cinstr(b, y_str);
    epoint* p = epoint_init();
    int n = epoint_set(a,b,1,p);
    cinstr(q, n_str);
    
    

    big sk = mirvar(0);
    epoint* c1 = epoint_init();
    unsigned char c[128];
    unsigned char cid[32];
    unsigned char encoded_buffer[300];
    
    char msg[200];
    char encoded_msg[300];
    size_t msg_size;
    size_t encoded_msg_size;
    int t = 0;
    
    //use a file with sk,c1_x,c1_y,c2_x,c2_y,cid stored in continuos byte stream. (read using "rb")
    
    read_keys_init(sk, c, c1, cid);    //read apk and public key part c1

    
    clock_t start_s, end_s, start,end;
    clock_t start_v, end_v;
    double time_taken_s = 0.0;
    double time_taken_v = 0.0;
    
    start_s = clock();
    for(int i = 0; i < 1000; i++){
        msg_size = read_message(msg);
        gen_proof(q, p, sk, c, msg, msg_size, t, sig);
    }
    end_s = clock();

    time_taken_s = (double)(end_s - start_s)/CLOCKS_PER_SEC; 


    gen_proof(q, p, sk, c, msg, msg_size, t, sig);
    start_s = clock();
    for(int i = 0; i < 1000; i++){
        verify_proof(q, p, c, msg, msg_size, t, sig);
    }
    end_s = clock();


    time_taken_v = (double)(end_s - start_s)/CLOCKS_PER_SEC; 
    printf("---------------------------\nTime taken for 1000 message signing 120 byte BSM messages : %lf ms\n---------------------------\n", time_taken_s * 1000);
    printf("---------------------------\nAverage signing time : %lf ms\n---------------------------\n",time_taken_s);
    printf("---------------------------\nTime taken for 1000 message verification 120 byte BSM messages : %lf ms\n---------------------------\n ", time_taken_v * 1000);
    printf("---------------------------\nAverage verification time : %lf ms\n---------------------------\n",time_taken_v);
    

    epoint_free(c1);
    epoint_free(p);
    mirkill(sk);
    mirkill(a);
    mirkill(b);
    mirkill(q);
    mirexit();
    return 0;


}




void read_keys_init(big sk, char* c, epoint* c1, char* cid)
{
    big a = mirvar(0);
    big b = mirvar(0);
    FILE* f = fopen("apk.key","rb");
    fread(c, 32, 1, f);
    bytes_to_big(32, c, sk);
    fread(c, 32, 4, f);
    bytes_to_big(32, c, a);
    bytes_to_big(32, c+32, b);
    int n = epoint_set(a,b,0,c1);
    fread(cid,32,1,f);


    fclose(f);
    mirkill(a);
    mirkill(b);
}




#define PORT 65432

size_t read_message(char* msg) {
    
    ssize_t valread  = 120;

    srand(time(NULL));

    // Fill the buffer with random bytes (0-255)
    for (int i = 0; i < 120; i++) {
        msg[i] = rand() % 256;  // Generate a random byte
    }
   
    return (size_t)valread;
}

