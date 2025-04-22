#include "../include/PacketCapture.hpp"
#include<iostream>
#include<stdexcept>



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
    sniffingSession = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!sniffingSession) throw std::runtime_error("failed to open device: "+std::string(errbuf));

    std::cout << "sucessfully open the interface" ;


    // start capturing press ctr-c to stop 
     pcap_loop(sniffingSession,0,packetHandler,nullptr); // 0 for infinite packets
     pcap_close(sniffingSession);
    
    
}


PacketCapture::~PacketCapture() {
    if (sniffingSession) pcap_close(sniffingSession);
}


                    
void PacketCapture::packetHandler(unsigned char *userData,const struct pcap_pkthdr *pkthdr,const unsigned char *packet){
    std::cout << "captured a packet (" << pkthdr->len << " bytes) " << std::endl;
}

