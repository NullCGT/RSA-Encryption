Testencrypt: Testencrypt.c
	gcc -o Testencrypt Testencrypt.c -lssl -lcrypto
	gcc -o client client.c  