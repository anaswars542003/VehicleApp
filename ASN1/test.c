#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "CertificateBase.h"

#define HEX_STRING "03964576AF51A9D0218D9A43DB0786276B1849A3CFA4346E2DB939EE081007365567D73526768400EA2CB413A1721CB97D6E4DEF90BF3C8366FDA5BBD8E9EBB25198FFCE2E8C018BCC39D82F307F9A52227F52B8B85598766806ABC3E7314DC7F44CE8FC60291AA848A004E91A9DBBEB9E36D9489F9F9368B2D56F09FFBFAD27B3667763EC958B0BBE61D6BC367C2F7C800A32A7A925ACE998D4C43F64BB0B2B0091E2AE7710D0C334F919973D369DAE9405CA97DEF87198DDF9B46C25448D410EBDB144505BA4876936FA1AC269A6584CC3AE1EEF3BEF080A6E581E4102C8FB99978889813D"

// Function to convert hex string to byte buffer
void hex_to_bytes(const char *hex, uint8_t *buffer, size_t *length) {
    size_t hex_len = strlen(hex);
    *length = hex_len / 2; // Each byte is represented by 2 hex characters
    
    for (size_t i = 0; i < *length; i++) {
        sscanf(hex + (i * 2), "%2hhx", &buffer[i]);
    }
}

int main() {
    size_t byte_len;
    size_t hex_len = strlen(HEX_STRING);
    uint8_t *byte_buffer = (uint8_t *)malloc(hex_len / 2);

    if (!byte_buffer) {
        printf("Memory allocation failed!\n");
        return 1;
    }

    hex_to_bytes(HEX_STRING, byte_buffer, &byte_len);

    printf("Binary data (in hex for display):\n");
    for (size_t i = 0; i < byte_len; i++) {
        printf("%02X ", byte_buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
 
    struct oer_certificate_base_certificate_base_t decoded_cert;
    memset(&decoded_cert, 0, sizeof(decoded_cert));

    // Decode the buffer
    size_t decoded_size = oer_certificate_base_certificate_base_decode(&decoded_cert, byte_buffer, byte_len);

    if (decoded_size < 0) {
        printf("Decoding failed with error code: %zd\n", decoded_size);
        return 1;
    }

    printf("Decoded Certificate:\n");
    printf("Version: %u\n", decoded_cert.version);
    
    printf("ID: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X", decoded_cert.tobeSignedData.id.buf[i]);
    }

    printf("\n");

    printf("Validity End: %u\n", decoded_cert.tobeSignedData.validity.end);

    printf("Anonymous PK: ");
    for (int i = 0; i < 128; i++) {
        printf("%02X", decoded_cert.tobeSignedData.anonymousPK.buf[i]);
    }
    printf("\n");
    printf("Signature (rSig.x): ");
    for (int i = 0; i < 32; i++) {
        printf("%02X", decoded_cert.signature.value.ecdsaNistP256Signature.rSig.x.buf[i]);
    }
    printf("\n");

    printf("Signature (sSig): ");
    for (int i = 0; i < 32; i++) {
        printf("%02X", decoded_cert.signature.value.ecdsaNistP256Signature.sSig.buf[i]);
    }
    printf("\n");


    printf("\n\nlength :: %ld", byte_len);
    return 0;
}
