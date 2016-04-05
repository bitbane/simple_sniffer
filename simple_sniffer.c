#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <unistd.h>

const int MAX_SIZE = 16384;

int main(int argc, char** argv)
{
    int saddr_size, data_size;
    struct sockaddr saddr;
    char buffer[MAX_SIZE];

    if (argc < 2)
    {
        printf("Usage: %s filename\n", argv[0]);
        exit(-1);
    }

    // Open the file to save data to
    FILE *outfile = fopen(argv[1], "wb");
    if(outfile == NULL)
    {
        perror("Unable to open file: ");
        exit(-1);
    }

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw < 0)
    {
        perror("Socket Error");
        exit(-1);
    }

    for(;;)
    {
        saddr_size = sizeof(saddr);
        data_size = recvfrom(sock_raw, buffer, MAX_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            exit(-1);
        }
        fwrite(buffer, 1, data_size, outfile);
    }
    fclose(outfile);
    close(sock_raw);
    return 0;
}

