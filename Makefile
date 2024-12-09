sandbox:
	gcc -Wall -o sandbox sandbox.c

hello:
	g++ -Wall -o hello hello.cc

run_hello_malware:
	sudo ./sandbox guest_dir/test_malware 1000 ./hello

clean:
	rm sandbox
