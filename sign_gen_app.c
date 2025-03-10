
#include<string.h>
#include<time.h>
#include"sok.h"
#include"oer.h"

#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

void read_keys_init(big sk, char* c, epoint* c1, char* cid);
size_t read_message(char* msg);
size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid);
void decode_example(uint8_t *encoded_data, size_t encoded_size);
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
    unsigned char c[126];
    unsigned char cid[32];
    
    char msg[200];
    char encoded_msg[300];
    size_t msg_size;
    size_t encoded_msg_size;
    int t = 0;
    
    //use a file with sk,c1_x,c1_y,c2_x,c2_y,cid stored in continuos byte stream. (read using "rb")
    
    read_keys_init(sk, c, c1, cid);    //read apk and public key part c1


    
    msg_size = read_message(msg);
    gen_proof(q, p, sk, c, msg, msg_size, t, sig);
    encoded_msg_size = encode_message_and_sign(msg, msg_size, c,  sig,cid);
    printf("\n\nsignature: ");
    for(int i = 0; i < 65; i++){

        if(i % 32 == 0)
            printf("\n");
        printf("%02x",(unsigned char)sig[i]);
    }
    n = verify_proof(q, p, c, msg, msg_size, t, sig);
    n ? printf("\nTRUE") : printf("\nFALSE");

    


    epoint_free(c1);
   //epoint_free(c2);
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

size_t read_message(char* msg)
{
    char a[] = "HELLO WORLD";
    strcpy(msg, a);
    return sizeof(a);
}


size_t encode_message_and_sign(char* msg, size_t msg_size, char* c, signature_t sig, char* cid){
    struct oer_send_data_send_data_t message;
    struct oer_send_data_send_data_t decoded_message;
    uint8_t encoded_data[300];
    size_t encoded_size;
    ssize_t decoded_size;

    message.protocolVersion = 3;
    message.content.choice = oer_send_data_content_choice_signedData_e;
    memcpy(message.content.value.signedData.data.buf, msg, msg_size);
    memcpy(message.content.value.signedData.signer.buf, cid, 32);
    memcpy(message.content.value.signedData.signature.buf, sig, 65);

    encoded_size = oer_send_data_send_data_encode(encoded_data, sizeof(encoded_data), &message);
    if(encoded_size < 0){
        printf("Error encoding SignedData message: %zd\n", encoded_size);
    }

    
    print_hex(encoded_data, encoded_size);
    printf("Size of encoded message : %ld", encoded_size);

    printf("Signature: \n");
    for(int i = 0; i < 65; i++){
        printf("%02x",(unsigned char)message.content.value.signedData.signature.buf[i]);
    }

    decoded_size = oer_send_data_send_data_decode(&decoded_message, encoded_data, encoded_size);
    int n ;

    printf("Signature encoded: \n");
    for(int i = 0; i < 65; i++){
        printf("%02x",(unsigned char)message.content.value.signedData.signature.buf[i]);
    }

    printf("Signature decoded: \n");
    for(int i = 0; i < 65; i++){
        printf("%02x",(unsigned char)decoded_message.content.value.signedData.signature.buf[i]);
    }

    decode_example(encoded_data, encoded_size);
}   




void decode_example(uint8_t *encoded_data, size_t encoded_size) {
    struct oer_send_data_send_data_t decoded_message;
    ssize_t decoded_size;
    
    printf("\n=== Decoding Example ===\n");
    
    // Decode the message
    decoded_size = oer_send_data_send_data_decode(&decoded_message, encoded_data, encoded_size);
    
    if (decoded_size < 0) {
        printf("Error decoding message: %zd\n", decoded_size);
        return;
    }
    
    printf("Successfully decoded message (%zd bytes):\n", decoded_size);
    printf("Protocol Version: %d\n", decoded_message.protocolVersion);
    
    if (decoded_message.content.choice == oer_send_data_content_choice_signedData_e) {
        printf("Content Type: SignedData\n");
        
        printf("Data (first 16 bytes): ");
        printf("%s\n",decoded_message.content.value.signedData.data.buf);
        
        printf("Signer:\n");
        print_hex(decoded_message.content.value.signedData.signer.buf, 32);
        
        printf("Signature z: \n");
        print_hex(decoded_message.content.value.signedData.signature.buf, 32);
        printf("Signature Rx: \n");
        print_hex(decoded_message.content.value.signedData.signature.buf+32, 32);
        printf("Signature odd_or_even: \n");
        print_hex(decoded_message.content.value.signedData.signature.buf+64, 1);

    } else {
        printf("Content Type: SignedCertificateRequest\n");
        
        printf("Certificate Request: ");
        print_hex(decoded_message.content.value.signedCertificateRequest.buf, 32);
    }


}