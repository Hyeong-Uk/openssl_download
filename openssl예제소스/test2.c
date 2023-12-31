/* bn_sample.c */ 
#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) 
{ 
	/* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */ 
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str); 
	OPENSSL_free(number_str); 
} 



int main () 
{ 
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *res = BN_new();
	// Initialize a, b, n
	BN_hex2bn(&a, "111");
	BN_hex2bn(&b, "222");
	printBN("a = ", a);
	printBN("b = ", b);
	BN_mul(res,a,b,ctx);
	printBN("a*b = ", res);
	BN_add(res,a,b);
	printBN("a+b = ", res);
	return 0;
}
