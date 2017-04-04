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
  uint8_t hlen[1];  //mac len
  uint8_t plen[1];  //ip len
  uint8_t opcode[2];
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};
struct my_hdr {
    struct _ether_hdr eh;
    struct _arp_hdr ah;
};

//device SendIp SendMac TargetIp TargetMac
int main(int argc,char *argv[])
{
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;
//    u_char sndPkt[42];
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
    inet_pton(AF_INET,argv[2],&ah->sender_ip);
    sscanf(argv[3],"%x:%x:%x:%x:%x:%x",&mh.eh.Src_mac[0],&mh.eh.Src_mac[1],&mh.eh.Src_mac[2],&mh.eh.Src_mac[3],&mh.eh.Src_mac[4],&mh.eh.Src_mac[5]);
    inet_pton(AF_INET,argv[4],&mh.ah.target_ip);
    sscanf(argv[5],"%x:%x:%x:%x:%x:%x",&mh.eh.Dst_mac[0],&mh.eh.Dst_mac[1],&mh.eh.Dst_mac[2],&mh.eh.Dst_mac[3],&mh.eh.Dst_mac[4],&mh.eh.Dst_mac[5]);
    for(i=0;i<6;i++)
        mh.ah.sender_mac[i] = eh->Src_mac[i];
    for(i=0;i<6;i++)
        mh.ah.target_mac[i] = mh.eh.Dst_mac[i];
    mh.eh.ether_type[0] = 0x08;
    mh.eh.ether_type[1] = 0x06;
    mh.ah.ptype[0] = 0x08;
    mh.ah.ptype[1] = 0x00;
    mh.ah.htype[0] = 0x00;
    mh.ah.htype[1] = 0x01;
    mh.ah.hlen[0] = 0x06;
    mh.ah.plen[0] = 0x04;
    mh.ah.opcode[0] = 0x00;
    mh.ah.opcode[1] = 0x02;

 //   u_char *etherhdr = &my_hdr;

  /*  memset(sndPkt,0,42*sizeof(u_char)); //write '0' with 42*1bite

    memcpy(sndPkt,mh.eh.Dst_mac,sizeof(mh.eh.Dst_mac));
    memcpy(sndPkt+6,mh.eh.Src_mac,sizeof(mh.eh.Src_mac));
    memcpy(sndPkt+12,mh.eh.ether_type,sizeof(mh.eh.ether_type));
    memcpy(sndPkt+14,mh.ah.htype,sizeof(mh.ah.htype));
    memcpy(sndPkt+16,mh.ah.ptype,sizeof(mh.ah.ptype));
    memcpy(sndPkt+18,mh.ah.hlen,sizeof(mh.ah.hlen));
    memcpy(sndPkt+19,mh.ah.plen,sizeof(mh.ah.plen));
    memcpy(sndPkt+20,mh.ah.opcode,sizeof(mh.ah.opcode));
    memcpy(sndPkt+22,mh.ah.sender_mac,sizeof(mh.ah.sender_mac));
    memcpy(sndPkt+28,mh.ah.sender_ip,sizeof(mh.ah.sender_ip));
    memcpy(sndPkt+32,mh.ah.target_mac,sizeof(mh.ah.target_mac));
    memcpy(sndPkt+38,mh.ah.target_ip,sizeof(mh.ah.target_ip));*/
   pcap_sendpacket(fp,(const u_char*)mh,42);
}
