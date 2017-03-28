#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>//ip -> bin

//device SendIp SendMac TargetIp TargetMac
int main(int argc,char *argv[])
{
    if(argc != 6)
    {
        printf("not enough argument!\n");
    }
    char *dev = argv[1];    //get device name
    char *Snd_ip = argv[2]; //get My_ip by Send ip
    char *Snd_mac = argv[3];//get My_mac by Send mac
    char *tar_ip = argv[4]; //get target's ip
 //   char *tar_mac = argv[5];//get target's mac
    int i;

  //  char *My_ip= strcpy(My_ip,Snd_ip); //Send ip
    char *My_ip = Snd_ip;
    unsigned int My_mac[6] ;
    sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &My_mac[0], &My_mac[1], &My_mac[2], &My_mac[3], &My_mac[4], &My_mac[5]);
    //char 00:0c:29:75:04:db to int 000c297504db
    unsigned int tar_mac[6];
    sscanf(argv[5], "%x:%x:%x:%x:%x:%x", &tar_mac[0], &tar_mac[1], &tar_mac[2], &tar_mac[3], &tar_mac[4], &tar_mac[5]);
    //char 00:0c:29:71:0b:ac to int 000c29710bac

    printf("ETHER_HEADER\n");
    printf("Dst MAC : %s\n",argv[5]);
    printf("Src MAC : %s\n",argv[3]);
    printf("ETHERTYPE : 0x0806\n");
    printf("ARP_HEADER\n");
    printf("SenderIP : %s\n",My_ip);   //192.168.205.130
    printf("SenderMac : %s\n",argv[3]); //00:0c:29:75:04:db
    printf("TargetIp : %s\n",tar_ip);  //192.168.205.131
    printf("TargetMac : %s\n",argv[5]);//00:0c:29:71:0b:ac

    inet_pton(AF_INET,argv[2],&Snd_ip);
    inet_pton(AF_INET,argv[4],&tar_ip);
    printf("inet_pton : %02x\n",Snd_ip);
    printf("inet_pton : %02x\n",tar_ip);
    printf("SenderMac : ");
    for(i=0;i<6;i++)
    printf("%02x",My_mac[i]);
    printf("\nTargetMac : ");
    for(i=0;i<6;i++)
    printf("%02x",tar_mac[i]);

    /*

    printf("ETHER_HEADER\n");
    printf("Dst MAC : %s\n",*tar_mac);
    printf("Src MAC : %s\n",*My_mac);
    printf("ETHERTYPE : 0x0806\n");
    printf("ARP_HEADER\n");
    printf("SenderIP : %s\n",*My_ip);   //192.168.205.130
    printf("SenderMac : %s\n",*My_mac); //00:0c:29:75:04:db
    printf("TargetIp : %s\n",*tar_ip);  //192.168.205.131
    printf("TargetMac : %s\n",*tar_mac);//00:0c:29:71:0b:ac

//    char Snd_pac[42] = tar_mac+My_mac+0x0806+My_ip+tar_ip+tar_mac; //Target_Mac+My_Mac+ETHER_TYPE+My_ip+Target_ip+Target_mac

*/
}

