#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

void packet_parse(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;

    static int packet_num;
    int pckt_len = header->len;
    int i, j;

    eth_hdr = (struct ether_header *)packet;

    printf("\n---- [ packet %d ] ----------------------------------------------------\n\n", packet_num++);

    /* print source and destination MAC address */
    printf("Source MAC Address\t: ");
    for(i = 0; i < 6; i++) printf("%02X%c", *(eth_hdr->ether_shost + i), (i == 5)? '\n' : '.');
    printf("Destination MAC Address\t: ");
    for(i = 0; i < 6; i++) printf("%02X%c", *(eth_hdr->ether_dhost + i), (i == 5)? '\n' : '.');

    /* if procotol is IP */
    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        /* get ip header offset */
        ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

        /* print source and destination ip address */
        printf("Source IP Address\t: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("Destination IP Address\t: %s\n", inet_ntoa(ip_hdr->ip_dst));

        if(ip_hdr->ip_p == IPPROTO_TCP) {
            /* get tcp header offset */
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);

            /* print source and destination port */
            printf("Source Port\t\t: %d\n", ntohs(tcp_hdr->source));
            printf("Destination Port\t: %d\n", ntohs(tcp_hdr->dest));
        }
    }

    /* print hexical and ascii packet data */
    printf("\n\t");
    for(i = 0; i < 16; i++) printf("%02X ", i);
    for(i = 0; i < pckt_len; i++) {
        if(i % 16 == 0) {
            if(i) {
                for(j = i - 16; j < i; j++)
                    if(0x21 <= packet[j] && packet[j] <= 0x7E) printf("%c", packet[j]);
                    else printf(".");
                j = i;
            }
            printf("\n0x%04X  ", i);
        }
        printf("%02X ", packet[i]);
    }
    for(i = 0; i <= 15 - pckt_len % 16; i++) printf("   ");
    for(i = j; i < pckt_len; i++)
        if(0x21 <= packet[i] && packet[i] <= 0x7E) printf("%c", packet[i]);
        else printf(".");
    printf("\n");
}

int main(void)
{
   struct bpf_program fp;		/* The compiled filter */
   struct pcap_pkthdr header;	/* The header that pcap gives us */

   pcap_t *handle;			/* Session handle */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */

   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   char filter_exp[] = "";	/* The filter expression */
   const u_char *packet;		/* The actual packet */

   char *track = "취약점";
   char *name = "신동민";
   printf("[bob5][%s]pcap_test[%s]\n", track, name);

   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }

   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }

   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }

   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }

   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }

   /* register callback function which do behavior when packet is captured */
   pcap_loop(handle, 0, packet_parse, NULL);

   while( 1 ) {
       /* Grab a packet */
       packet = pcap_next(handle, &header);
       if(!packet) continue;
   }

   /* And close the session */
   pcap_close(handle);
   return 0;
}
