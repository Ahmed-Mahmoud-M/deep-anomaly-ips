#pragma once
#include <atomic>
#include <bits/types/struct_timeval.h>
#include <mutex>
#include <pcap/pcap.h>
#include <queue>
#include<string>
#include<pcap.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>


struct Packet {

    std::vector<uint8_t> data; //Raw data bytes
    struct timeval timestamp;//Packet arrival time 
};

class PacketCapture {
    public:
        PacketCapture(const std::string& interface);
        ~PacketCapture();

	
    	void startCapture(int packetCount = -1);// by defualt -1 infinite
        // start capturing in a background thread
        void startBackgroundCapture();
        // stop background capture
        void stopCapture();

        // set BPF filiter 
        void precompileFilters(); 
	    bool setFilter(const std::string& filter);


        // Fetech a batch of packets 

        std::vector<Packet> getPacketBatch();



    private:
        pcap_t *session_handler;
        std::string interface;
        std::atomic<bool> isRunnig;
        std::queue<Packet> packetQueue;
        std::mutex queueMutex;
        std::unordered_map<std::string ,  bpf_program >precompiledFiliter; // caching compiled Filiters
        static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* PacketData);


        // internal packet processing 
        void processPacket(const struct pcap_pkthdr* pkthdr,const u_char *PacketData);
        


		

};

