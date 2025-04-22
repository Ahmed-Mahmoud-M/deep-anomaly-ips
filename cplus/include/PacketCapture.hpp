#pragma once

#include<string>
#include<pcap.h>

class PacketCapture {
    public:
        PacketCapture(const std::string& interface);
        ~PacketCapture();

	
    	void startCapture(int packetCount = -1);// by defualt -1 infinite
	    void setFilter(const std::string& filter);




    private:
        pcap_t *sniffingSession;
        std::string interface;
        static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        


		

};

