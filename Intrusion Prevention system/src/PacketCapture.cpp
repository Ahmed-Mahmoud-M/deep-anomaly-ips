#include "../include/PacketCapture.hpp"
#include<iostream>
#include <pcap/pcap.h>
#include<stdexcept>
#include <string>
#include <vector>



PacketCapture::PacketCapture(const std::string& interface) : interface(interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    /*c_str() convert std::string to char* string */


    /*pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms,
    char *ebuf) 
    
    snaplen --> maximum # of bytes to be captured by pcap   
    promisc --> set to true bring the interface into promiscuous mode
    to_ms --> is the read time in millieseconds 
    ebuf --> store any error messages within the session 
    
    */
    session_handler = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!session_handler) throw std::runtime_error("failed to open device: "+std::string(errbuf));
//     if (pcap_datalink(session_handler) != DLT_EN10MB) {
// 	fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface.c_str());

// }

    std::cout << "sucessfully open the interface" ;


    // start capturing press ctr-c to stop 
     pcap_loop(session_handler,0,packetHandler,nullptr); // 0 for infinite packets
     pcap_close(session_handler);
    
    
}


PacketCapture::~PacketCapture() {
    if (session_handler) pcap_close(session_handler);
}


                    
void PacketCapture::packetHandler(unsigned char *userData,const struct pcap_pkthdr *pkthdr,const unsigned char *packet){
    std::cout << "captured a packet (" << pkthdr->len << " bytes) " << std::endl;
}



/*
    prototype of pcap_compile() :
        int pcap_compile(pcap_t * handler, struct bpf_program *fp , char * str , int optimize , bpf_uint32 netmask)

        0 with no error 


    prototype of pcap_setFIliter()
        pcap_setfiliter(pcap_t * handler , struct bpf_program *fp)

    
    struct bpf_program *fp --> compiled version of  a specific string 

    steps of set the filiter : 
        1 recieve the experession string
        2 compiled it that pcap can understand
        3 apply to the handler pcap 





*/


void PacketCapture::precompileFilters(){
    const std::vector<std::string> defualtFiliters {
        "tcp port 80",    // HTTP
            "tcp port 22",    // SSH
            "udp port 53",    // DNS
            "icmp",           // Ping
            "net 192.168.1.0/24"  // Internal traffic
    };

    for (const auto& filiter : defualtFiliters) {
        bpf_program pragma;
        if(pcap_compile(session_handler, &pragma, filiter.c_str(), 1,PCAP_NETMASK_UNKNOWN)==0) {
            precompiledFiliter[filiter] = pragma;
        }
    }
}

bool PacketCapture::setFilter(const std::string& filter){
        if(precompiledFiliter.find(filter)!=precompiledFiliter.end()) {
            return pcap_setfilter(session_handler, &precompiledFiliter[filter])==0;
        }else{

            bpf_program pragma;
        if(pcap_compile(session_handler, &pragma, filter.c_str(), 1,PCAP_NETMASK_UNKNOWN)==0) {
            bool success = pcap_setfilter(session_handler, &pragma)==0;
            pcap_freecode(&pragma);
            return success;
        }
        }

        return false;
}

