#include "../../include/sniffing/PacketCapture.hpp"
#include <cstdint>
#include <cstdio>
#include <pcap/pcap.h>
#include <stdexcept>
#include <string>
#include <vector>




PacketCapture::PacketCapture() :pcap_handle(nullptr),timeout_ms(1000),promiscuous(true),capturing(false),packets_dropped(0),packets_captured(0){}


PacketCapture::~PacketCapture(){
    start_capture();
    cleanup_pcap();
}


bool PacketCapture::set_interface(const std::string&interface) {
    if(capturing) return false;
    current_interface = interface;
    return true;
}


bool PacketCapture::set_filiter(const std::string& filiter_expression) {
    if (capturing) return false;
    current_filiter = filiter_expression;

    return true;
}


bool PacketCapture::set_timeout(int timeout_ms) {
    if(capturing) return false;
    this->timeout_ms = timeout_ms;
    return true;
}

bool PacketCapture::set_promiscuous(bool enable) {
    if (capturing) return false;

    promiscuous = enable;

    return true;
}


bool PacketCapture::start_capture(){
    if (capturing || current_interface.empty()) return false;

    if (!pcap_handle) init_pcap();

    capturing = true;
    return true;
}


void PacketCapture::stop_capture(){
    capturing = false;
}


bool PacketCapture::is_capturing(){
    return capturing;
}


void PacketCapture::process_next_packet(){
    if (!capturing || !pcap_handle) return;


    pcap_pkthdr * header;
    const u_char * packet;

    int result = pcap_next_ex(pcap_handle, &header, &packet);

    if (result == 1){
        current_packet.assign(packet,packet+header->caplen);
        packets_captured ++;
    }else if (result == 0) {
            // continue
    }else{
        packets_dropped ++;
    }



}

bool PacketCapture::has_packets() {
    return ! current_packet.empty();
}

const std::vector<uint8_t>& PacketCapture::get_current_packet(){
    return  current_packet;
}


uint32_t PacketCapture::get_packets_captured() {
    return packets_captured;
}


uint32_t PacketCapture::get_packets_dropped(){
    return packets_dropped;
}

        
void PacketCapture::cleanup_pcap(){
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
}


void PacketCapture::init_pcap(){
    char errbuf [PCAP_ERRBUF_SIZE];

    pcap_handle = pcap_open_live(
        current_interface.c_str(),
        BUFSIZ,
        promiscuous,
        timeout_ms,
        errbuf   
    );

    if (!pcap_handle) {
        throw std::runtime_error("Failed to open interface: " + std::string(errbuf));
    }



    // set filiter 

    if (!current_filiter.empty()) {
        struct bpf_program fp;

        if (pcap_compile(pcap_handle, &fp, current_filiter.c_str(), 0, PCAP_NETMASK_UNKNOWN)==-1){
                cleanup_pcap();
            throw std::runtime_error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle)));

        }


        if (pcap_setfilter(pcap_handle, &fp)== -1){
            pcap_freecode(&fp);
            cleanup_pcap();
            throw std::runtime_error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle)));
        }

        pcap_freecode(&fp);
    }
}

