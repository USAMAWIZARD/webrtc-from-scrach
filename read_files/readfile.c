#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
char *file_buffer[100];
int open_file(char *file_name)
{
    FILE *input;
    uint8_t byte_count;
    uint8_t buffer_size=1;
    unsigned char chunk[1];
    if ((input = fopen(file_name, "rb")) != NULL)
    {
        while (!feof(input))
        {
            
                fread(chunk, 1, 1, input);
                printf("%d     %d\n", chunk[0],byte_count);
                byte_count+=buffer_size;
                if(byte_count==31){
                    exit(0);
                }
        }
    }
}
    void main()
    {
        open_file("test.h264");
    }