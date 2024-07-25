all: pcap-test

pcap-test: pcap-test.cpp pcap-test.h
	g++ -o pcap-test pcap-test.cpp -lpcap

clean:
	rm -f pcap-test

