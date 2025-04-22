#include <iostream>
#include "cplus/src/PacketCapture.cpp"


int main() {

    try {
    PacketCapture capture("eth0");

    }catch(std::exception& e){
        std::cerr << "Error " << e.what() << std::endl;
        return 1;
    }


    return 0;

}