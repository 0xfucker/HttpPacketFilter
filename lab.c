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


#define IP_ETH_TYPE 0x800
#define ARP_ETH_TYPE 0x806

#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

/* DataTypes */

/* Ethernet Packet */
struct ether_header 
{
    u_int8_t    dhost[6];
    u_int8_t    shost[6];
    u_int16_t   eth_type;
};

typedef struct ether_header ether_header_t;

/* IP Packet */
struct ip_header{

    u_int8_t    lenver;     //  version(4) + length(4)
    u_int8_t    tos;        //  type of service
    u_int16_t   len;        //  lunghezza del datagramma in byte
    u_int16_t   id;         //  id -> frammentazione
    u_int16_t   frag;       //  frammentazione(flag(3)+offset(13))
    u_int8_t    ttl;        //  time-to-live
    u_int8_t    prot;       //  protocollo di livello superiore
    u_int16_t   checksum;   //  checksum intestazione
    
    /* also possible to use u_int32_t */
    u_int8_t    source[4];
    u_int8_t    dest[4];




};

typedef struct ip_header ip_header_t;


/* Level 4  HEADER */
struct udp_header{

    u_int16_t sport;
    u_int16_t dport;
    u_int16_t len; //header+dati
    u_int16_t checksum;


};

typedef struct udp_header udp_header_t;


struct tcp_header{

    u_int16_t sport;
    u_int16_t dport;
    u_int32_t seq;
    u_int32_t ack;
    u_int8_t  datares;
    u_int8_t  flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urg;

};

typedef struct tcp_header tcp_header_t;

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

void printURL(char *data){


    if(!strncmp(data,"GET ",4)){
        
        int old = 0;
        int offset = 4;
        
        while(data[offset]!=' ')
            offset++;

        old = offset;
        offset += 17;
        while(data[offset]!='\r') // \r\n
            offset++;

        printf("URL: ");
        for(int i=old+17;i<offset;i++)
            printf("%c",data[i]);
        for(int i=4;i<old;i++)
            printf("%c",data[i]);
        printf("\n");

        



    }

}

void do_something_on_packet(u_char* arg, const struct pcap_pkthdr* pkthdr,const u_char* packet){



  

    if(pkthdr->caplen!=pkthdr->len)
        return;

    int payload_size = 0;
    int offset = 0;
    


    u_int16_t          eth_type;
    ether_header_t     *eptr    = (ether_header_t*)packet;
    ip_header_t        *ipptr   = NULL; 
 

    printf("\n");
  
    //timestamp
    printf("%ld ",pkthdr->ts.tv_sec);

    eth_type = ntohs(eptr->eth_type);

    //MAC_src -> MAC_dest
    printf("%x:%x:%x:%x:%x:%x -> \%x:%x:%x:%x:%x:%x "
            ,eptr->shost[0],eptr->shost[1],eptr->shost[2],eptr->shost[3],eptr->shost[4],eptr->dhost[5]
            ,eptr->dhost[0],eptr->dhost[1],eptr->dhost[2],eptr->dhost[3],eptr->dhost[4],eptr->shost[5]);
   
    offset += 14;

    switch(eth_type){
   
        case IP_ETH_TYPE:
         
            // IP PACKET
            //
            ipptr = (ip_header_t*)(packet+offset); //14 offset
            //IP_src -> IP_dest
            printf("%d.%d.%d.%d -> %d.%d.%d.%d"
                    ,ipptr->source[0],ipptr->source[1],ipptr->source[2],ipptr->source[3]
                    ,ipptr->dest[0],ipptr->dest[1],ipptr->dest[2],ipptr->dest[3]);  

           // printf("\nip_header_len: %d\n",LO_NIBBLE(ipptr->lenver));
              
            offset += LO_NIBBLE(ipptr->lenver)*4;  

            if(ipptr->prot == 6){
            
                printf(" TCP");
                tcp_header_t *tptr = (tcp_header_t*)(packet+offset);
                printf(" %d -> %d\n",ntohs(tptr->sport),ntohs(tptr->dport));
                
                offset+=HI_NIBBLE(tptr->datares)*4; 
                
              
                payload_size = pkthdr->caplen-offset; 
                if(ntohs(tptr->dport)==80){ 
                    //TODO Gestire Pacchetto HTTP con URL   
                    if(payload_size > 0){
                        char *data =(char*)(packet+offset);
                        data[payload_size]='\0';  
                      
                       
                        printURL(data);

                    }
            
                  
                 
            
                }
            }else if(ipptr->prot == 17){
                printf(" UDP");
                udp_header_t *tptr = (udp_header_t*)(packet+14+20);
                printf(" %d -> %d\n",ntohs(tptr->sport),ntohs(tptr->dport));
                 
            }

            

            
            break;

        case ARP_ETH_TYPE:
           
            // ARP PACKET


            break;

        default:
            printf("UNKNOWN PACKET\n");
            break;
 

    }

  
}
