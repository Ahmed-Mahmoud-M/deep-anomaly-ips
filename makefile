run:
	g++ main.cpp -o main  -lpcap
	./main




test:
	g++ draftcode/*.cpp -o sniffer -lpcap
	./sniffer