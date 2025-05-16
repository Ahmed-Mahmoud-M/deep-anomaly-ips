#pragma  once 


/*

PacketCapture class 

purpose : Core class for capturing network packets
Responsibilities:
        1) initalize network interface
        2)set filiter (BPF filiter)
        3) start , stop sniffing
        4)Handle capture packets
*/

#include <cstdint>
#include <pcap/pcap.h>
#include <string>
#include <sys/types.h>
#include <vector>
class PacketCapture {

    public:
        // constructor and destructor 
        PacketCapture();
        ~PacketCapture();


        // configuration 

        bool set_interface(const std::string & interface);
        bool set_filiter(const std::string& filiter_expression);
        bool set_timeout(int timeout_ms);
        bool set_promiscuous(bool enable);


        // capture control 

        bool start_capture();
        void stop_capture();
        bool is_capturing();



        // packet processing 


        void process_next_packet();
        bool has_packets();
        const std::vector<uint8_t> & get_current_packet();



        uint32_t get_packets_captured();
        uint32_t get_packets_dropped();



    private:
        // internal processing

        void init_pcap();
        void cleanup_pcap();

        static void packet_handler(
            u_char * user_data,
            const struct pcap_pkthdr * pkthdr,
            const u_char * packet
        );

    
    pcap_t * pcap_handle;
    std::string current_interface;
    std::string current_filiter;
    int timeout_ms;
    bool promiscuous;
    bool capturing;

    // packet storage
    std::vector<uint8_t> current_packet;
    uint32_t packets_captured;
    uint32_t packets_dropped;




};


