#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>//ip -> bin

#define PCAP_OPENFLAG_PROMISCUOUS   1   // Even if it isn't my mac, receive packet

struct _ether_hdr{
    uint8_t Dst_mac[6];
    uint8_t Src_mac[6];
    uint8_t ether_type[2];
};
struct _arp_hdr {
  uint8_t htype[2];
  uint8_t ptype[2];
  uint8_t hlen[1];
  uint8_t plen[1];
  uint8_t opcode[2];
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};
//device SendIp SendMac TargetIp TargetMac
int main(int argc,char *argv[])
{
    struct _ether_hdr eh;
    struct _arp_hdr ah;
    u_char sndPkt[42];
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    char *dev = argv[1];    //get device name

    if(argc != 6)
    {
        printf("not enough argument!\n");
        printf("EX : DEVICE SENDER_IP SENDER_MAC TARGET_IP TARGET_MAC\n");
        return 1;
    }
    if ( (fp= pcap_open_live(dev, 42, PCAP_OPENFLAG_PROMISCUOUS , 1000, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", argv[1]);
        return 1;
    }
    inet_pton(AF_INET,argv[2],&ah.sender_ip);
    sscanf(argv[3],"%x:%x:%x:%x:%x:%x",&eh.Src_mac[0],&eh.Src_mac[1],&eh.Src_mac[2],&eh.Src_mac[3],&eh.Src_mac[4],&eh.Src_mac[5]);
    inet_pton(AF_INET,argv[4],&ah.target_ip);
    sscanf(argv[5],"%x:%x:%x:%x:%x:%x",&eh.Dst_mac[0],&eh.Dst_mac[1],&eh.Dst_mac[2],&eh.Dst_mac[3],&eh.Dst_mac[4],&eh.Dst_mac[5]);
    for(i=0;i<6;i++)
        ah.sender_mac[i] = eh.Src_mac[i];
    for(i=0;i<6;i++)
        ah.target_mac[i] = eh.Dst_mac[i];
    eh.ether_type[0] = 0x08;
    eh.ether_type[1] = 0x06;
    ah.ptype[0] = 0x08;
    ah.ptype[1] = 0x00;
    ah.htype[0] = 0x00;
    ah.htype[1] = 0x01;
    ah.hlen[0] = 0x06;
    ah.plen[0] = 0x04;
    ah.opcode[0] = 0x00;
    ah.opcode[1] = 0x02;

    memset(sndPkt,0,42*sizeof(u_char)); //write '0' with 42*1bite

    memcpy(sndPkt,eh.Dst_mac,sizeof(eh.Dst_mac));
    memcpy(sndPkt+6,eh.Src_mac,sizeof(eh.Src_mac));
    memcpy(sndPkt+12,eh.ether_type,sizeof(eh.ether_type));
    memcpy(sndPkt+14,ah.htype,sizeof(ah.htype));
    memcpy(sndPkt+16,ah.ptype,sizeof(ah.ptype));
    memcpy(sndPkt+18,ah.hlen,sizeof(ah.hlen));
    memcpy(sndPkt+19,ah.plen,sizeof(ah.plen));
    memcpy(sndPkt+20,ah.opcode,sizeof(ah.opcode));
    memcpy(sndPkt+22,ah.sender_mac,sizeof(ah.sender_mac));
    memcpy(sndPkt+28,ah.sender_ip,sizeof(ah.sender_ip));
    memcpy(sndPkt+32,ah.target_mac,sizeof(ah.target_mac));
    memcpy(sndPkt+38,ah.target_ip,sizeof(ah.target_ip));
   pcap_sendpacket(fp,sndPkt,42);
}
