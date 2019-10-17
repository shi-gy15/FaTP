server:server.o operation.o
	# gcc operation.c
	gcc -o server server.o operation.o
server.o:server.c operation.h
	gcc -c server.c
operation.o: operation.c operation.h
	cc -c operation.c
clean:
	rm *.o server

