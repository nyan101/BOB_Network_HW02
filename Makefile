SendARP: SendARP.o getLocalAddress.o getLocalAddress.h
	gcc -o SendARP SendARP.o getLocalAddress.o -lpcap

SendARP.o: SendARP.c getLocalAddress.h
	gcc -c SendARP.c

getLocalAddress.o: getLocalAddress.c getLocalAddress.h
	gcc -c getLocalAddress.c

clean:
	rm *.o SendARP
