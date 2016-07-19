SendARP: SendARP.c
	gcc -o SendARP SendARP.c -lpcap

clean:
	rm SendARP

