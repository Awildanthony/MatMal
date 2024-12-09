sandbox:
	gcc -Wall -o sandbox sandbox.c

hello:
	g++ -Wall -o hello hello.cc

run_hello_malware:
	sudo ./sandbox guest_dir/test_malware 1000 ./hello

run_actual_malware:
	sudo ./sandbox guest_dir/test_malware 1000 ./00bbe47a7af460fcd2beb72772965e2c3fcff93a91043f0d74ba33c92939fe9d

clean:
	rm sandbox
