#include "minimalSHA256.h"
#include <stdio.h>

int main(int argc, char *argv[]){
	if(argc > 1){
		char *input = argv[1];
		uint8_t hash[32];
		sha256((const uint8_t *)input,strlen(input),hash);
		print_hash(hash);
		return 0;
	}
	else{
		printf("\nExample: ./test Hello\n");
		return -1;
	}
}

