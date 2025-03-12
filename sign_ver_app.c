
#include<string.h>
#include<time.h>
#include<hiredis/hiredis.h>
#include"sok.h"
#include"oer.h"

#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define FILE_PREFIX "sends/data"


void read_keys_init(big sk, char* c, epoint* c1, char* cid);
size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid, uint8_t* encoded_data);
void decode_example(uint8_t *encoded_data, size_t encoded_size);
size_t recv_msg(char* encoded_msg, char* filename);
size_t parse_msg(char* encoded_msg,char* msg, char* c,signature_t sig);
void retriev_apk(unsigned char* cid, unsigned char* c);

int main(int argc, char* argv[])
{
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;

    

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

    unsigned char msg[200];
    size_t msg_size;
    char c[128];
    unsigned char cid[32];
    unsigned char encoded_msg[300];
    size_t encoded_msg_size = 300;
    signature_t sig;
    int t = 0;
    
    char filename[200];
    strcpy(filename,"sends/data0");
    recv_msg(encoded_msg, filename);
    msg_size = parse_msg(encoded_msg, msg, cid, sig);


    printf("\n\nsignature: ");
    for(int i = 0; i < 65; i++){
        if(i % 32 == 0)
            printf("\n");
        printf("%02x",(unsigned char)sig[i]);
    }

    printf("\n\ncid: ");
    for(int i = 0; i < 32; i++){
        if(i % 32 == 0)
            printf("\n");
        printf("%02x",(unsigned char)cid[i]);
    }

    retriev_apk(cid, c);
    n = verify_proof(q, p, c, msg, msg_size, t, sig);

    printf("\n------------------------------\nTRUE OR FALSE : %d", n);

    epoint_free(p);
    mirkill(a);
    mirkill(b);
    mirkill(q);
    mirexit();
    return 0;
 
}


size_t recv_msg(char* encoded_msg, char* filename){
    FILE* f = fopen(filename, "rb");
    fread(encoded_msg, 300, 1, f);
    fclose(f);
    return 300;
}


size_t parse_msg(char* encoded_msg,char* msg, char* cid,signature_t sig){
    struct oer_send_data_send_data_t decoded_message;
    ssize_t decoded_size;
    decoded_size = oer_send_data_send_data_decode(&decoded_message, encoded_msg, 219);
    
    printf("protocol version : %d", decoded_message.protocolVersion);
    memcpy(msg, decoded_message.content.value.signedData.data.buf, 120);
    memcpy(cid, decoded_message.content.value.signedData.signer.buf, 32);
    memcpy(sig,  decoded_message.content.value.signedData.signature.buf, 65);
    return 120;
}

void retriev_apk(unsigned char* cid, unsigned char* c){
    
    redisContext *context = redisConnect("127.0.0.1", 6379);
    if (context == NULL || context->err) {
        if (context) {
            printf("Connection error: %s\n", context->errstr);
            redisFree(context);
        } else {
            printf("Connection error: cannot allocate redis context\n");
        }
        exit(1);
    }
    const char *argv[] = {"GET", cid};
    size_t argvlen[] = {3, 32};
    redisReply *reply = redisCommandArgv(context, 2, argv, argvlen);
    if (reply == NULL) {
        printf("GET command failed\n");
        redisFree(context);
        exit(0);
    }

    if (reply->type == REDIS_REPLY_STRING) {
        memcpy(c, reply->str, 128);

    } else {
        printf("Key not found or error occurred\n");
    }
    freeReplyObject(reply);
    redisFree(context);
}