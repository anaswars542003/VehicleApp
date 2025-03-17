#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct Memory {
    char *response;
    size_t size;
};

size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    struct Memory *mem = (struct Memory *)userp;
    
    char *ptr = realloc(mem->response, mem->size + total_size + 1);
    if(ptr == NULL) {
        printf("Failed to allocate memory.\n");
        return 0;
    }
    
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, total_size);
    mem->size += total_size;
    mem->response[mem->size] = 0;
    
    return total_size;
}

int main() {
    CURL *curl;
    CURLcode res;
    struct Memory chunk = {NULL, 0};
    
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if(curl) {
        const char *url = "http://127.0.0.1:5000/get_cert";
        const char *json_data = "{\"cid\": \"964576AF51A9D0218D9A43DB0786276B1849A3CFA4346E2DB939EE0810073655\"}";
        
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        res = curl_easy_perform(curl);
        
        if(res == CURLE_OK) {
            FILE *file = fopen("output.oer", "wb");
            if (file) {
                fwrite(chunk.response, 1, chunk.size, file);
                fclose(file);
                printf("OER data saved to output.oer\n");
            } else {
                printf("Failed to open file for writing.\n");
            }
        } else {
            printf("Request failed: %s\n", curl_easy_strerror(res));
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(chunk.response);
    }
    
    curl_global_cleanup();
    return 0;
}
