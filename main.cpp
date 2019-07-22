#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define IP 0x0800

/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};

void usage();
int print_ether(const u_char* packet );
int print_ip(const u_char* packet );
void print_tcp(const u_char* packet, u_int size);
void print_data(const u_char* packet, u_int size);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1]; //network adapter
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  // (ens33, pk size, if(1) all pk capture, timeout delay, err save)
  // return ( pcap_t*, NULL )
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr *header; //
    const u_char* packet;
    u_char payload = 0;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //printf("%u bytes captured\n", header->caplen);
    printf("\n");

    u_int compare=print_ether(packet);
    //compare ntohs(ether type)
    packet = packet + SIZE_ETHERNET;
    if( compare == IP) {
        payload = print_ip(packet);
        packet += payload;
        //packet = packet + size_ETHERNET + ip_size
        print_tcp(packet,header->caplen);
    }
}

  pcap_close(handle);
  return 0;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int print_ether(const u_char * packet ) {
    struct sniff_ethernet *eth;
    eth=(struct sniff_ethernet *)packet;
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
           eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],
           eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[6]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x / ",
           eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],
           eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[6]);

    return ntohs(eth->ether_type);
}

int print_ip(const u_char * packet) {
    struct sniff_ip* ip;
    ip = (struct sniff_ip *)packet;
        printf("%15s ", inet_ntoa(ip->ip_dst));
        printf("%15s / ", inet_ntoa(ip->ip_src));

    return IP_HL(ip)*4;
}

void print_tcp(const u_char* packet, u_int size) {
    struct sniff_tcp *tcp;
    tcp=(struct sniff_tcp *)packet;
    printf("%d ", ntohs(tcp->th_dport));
    printf("%d /", ntohs(tcp->th_sport));

    packet = ( packet + (TH_OFF(tcp)*4));

    if ( ntohs(tcp->th_dport) == 80) {
        size = size - (TH_OFF(tcp)*4);
        print_data(packet,size);
    }
}

void print_data(const u_char* packet, u_int size) {
    if ( size >=10 ) size = 10;
    printf(" ");
    for ( int i = 0; i < size; i++) {
        printf("%x",packet[i]);
    }
}
