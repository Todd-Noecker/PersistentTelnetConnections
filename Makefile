SPORT := 1025
SIP := 192.168.6.4
CIP := 192.168.6.3

##################################### SERVER ##################################
run_server: build_server
	cd build_server && ./server $(SPORT)

build_server: src/server.c
	mkdir build_server
	gcc -Wall -Werror -std=c11 src/server.c -o build_server/server

##################################### CLIENT ##################################
run_client: build_client
	cd build_client && ./client $(SIP) $(SPORT)

build_client: src/client.c
	mkdir build_client
	gcc -Wall -Werror -std=c11 src/client.c -o build_client/client

clean: 
	rm -rf build_*
