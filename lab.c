// PAR Laboratory on Capture
// Carmelo Riolo


// Headers
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <assert.h>


#define BYTELIMIT   2048
#define TO_MS       512


/* DataTypes */
struct ether_header 
{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};


/* Prototype */
void do_something_on_packet(u_char*, const struct pcap_pkthdr*,const u_char*);


/* main() */
int main(int argc,char *argv[]){


   
    int count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
   
    /* Reading interface */

    if(argc>1)
        /* Take the name of the interface as argument from command line */
        device = argv[1];
    else
        /* Get the name of the first interface suitable for capture*/
        device = pcap_lookupdev(errbuf);
    

    assert(device!=NULL);
    
    /* DEBUG_INFO */
    printf("device: %s\n",device);
    
    /* Opening Interface in Promiscuos Mode*/
    descr = pcap_open_live(device,BYTELIMIT,1,TO_MS,errbuf);

    assert(descr!=NULL && "pcap_open_live() failed");


    /* Start Capturing Packets */
    /* Loop forever(-1) and call callback function for every received packets */
    pcap_loop(descr,-1,do_something_on_packet,(u_char*)&count);

    return 0;


}

/* CALLBACK FUNCTION */

void do_something_on_packet(u_char* arg, const struct pcap_pkthdr* pkthdr,const u_char* packet){


    printf("Packet Received\n");
    /* TODO: Parsing Here */


}
