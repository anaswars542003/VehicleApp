#include<stdio.h>
#include<string.h>
#include<stdint.h>

int main()
{
    
    uint32_t a = 5;
    char* b = (char*)&a;
    
    
    FILE* f = fopen("apk.key","rb");
    fread(b, 4, 1, f);
    printf("%d",a);

}