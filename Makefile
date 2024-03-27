all: pcap-test

pcap-test: pcap-test.o net.o
	g++ -o pcap-test pcap-test.o net.o -lpcap

pcap-test.o: net.h pcap-test.cpp

net.o: net.h net.cpp

clean:
	rm -f pcap-test *.o

