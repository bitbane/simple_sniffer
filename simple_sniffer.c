#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>

/** PCAP file header */
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

/** PCAP packet header */
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

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

    // Set up the PCAP file header (Magic Number, Major Version, Minor Version, UTC Timezone, Accuracy, Snaplen, Link Type Ethernet)
    pcap_hdr_t pcap_hdr = {0xa1b2c3d4, 2, 4, 0, 0, MAX_SIZE, 1};
    fwrite((char*)&pcap_hdr, 1, sizeof(pcap_hdr_t), outfile);

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
        pcaprec_hdr_t packet_hdr;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        packet_hdr.incl_len = data_size;
        packet_hdr.orig_len = data_size; // FIXME: This could be wrong if packet length was > MAX_SIZE
        packet_hdr.ts_sec = tv.tv_sec;
        packet_hdr.ts_usec = tv.tv_usec;
        fwrite((char*)&packet_hdr, 1, sizeof(pcaprec_hdr_t), outfile);
        fwrite(buffer, 1, data_size, outfile);
    }
    fclose(outfile);
    close(sock_raw);
    return 0;
}

