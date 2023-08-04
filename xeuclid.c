//#include "pch.h"
#include <stdio.h>
#include <openssl/bn.h>

BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b)
{
    BIGNUM* a_t = BN_new();
    BIGNUM* b_t = BN_new();
    BN_copy(a_t, a); //BN-dup?
    BN_copy(b_t, b);
    BIGNUM* x_t2 = BN_new();
    BIGNUM* y_t2 = BN_new();
    BIGNUM* x_t1 = BN_new();
    BIGNUM* y_t1 = BN_new();
    BN_one(x_t2);
    BN_zero(y_t2);
    BN_zero(x_t1);
    BN_one(y_t1);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* q = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* r_t = BN_new(); // r_temp
    BIGNUM* qxy = BN_new();

    while (BN_is_zero(r_t) == 0) { // until r == 0, use compare
        /*
        1. a_t를 b_t로 나눠서 q와 r를 얻는다.
        2. q와 이전 x를 바탕으로 현재 x를 얻는다. y도 마찬가지.
        3. 조건부가 끝나면 gcd인 최종 r를 얻는다.
        */
        BN_div(q, r, a_t, b_t, ctx);

        BN_mul(qxy, q, x_t1, ctx);
        BN_sub(x, x_t2, qxy);
        BN_mul(qxy, q, y_t1, ctx);
        BN_sub(y, y_t2, qxy);

        BN_copy(x_t2, x_t1);
        BN_copy(x_t1, x);
        BN_copy(y_t2, y_t1);
        BN_copy(y_t1, y);
        BN_copy(a_t, b_t);
        BN_copy(b_t, r);
        BN_div(q, r, a_t, b_t, ctx);
    }
    BN_free(a_t);
    BN_free(b_t);
    BN_free(x_t1);
    BN_free(y_t1);
    BN_free(x_t2);
    BN_free(y_t2);
    BN_free(q);
    BN_free(r);
    BN_free(qxy);
    BN_CTX_free(ctx);
    return r;
}

int main(int argc, char *argv[])
{
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* gcd;

    if (argc != 3) {
        printf("usage: xeuclid num1 num2");
        return -1;
    }
    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&b, argv[2]);
    gcd = XEuclid(x, y, a, b);

    //
    BN_CTX* ctx2 = BN_CTX_new();
    BIGNUM* rr = BN_new();
    BN_gcd(rr, a, b, ctx2);
    printf("equlity: %d\n", BN_cmp(gcd, rr) == 0);
    BN_free(rr);
    BN_CTX_free(ctx2);
    /*
    printBN("(a,b) = ", gcd);
    printBN("a = ", a);
    printBN("b = ", b);
    printBN("x = ", x);
    printBN("y = ", y);
    printf("%s*(%s) + %s*(%s) = %s\n", BN_bn2dec(a), BN_bn2dec(x), BN_bn2dec(b), BN_bn2dec(y), BN_bn2dec(gcd));
    */
    if (a != NULL) BN_free(a);
    if (b != NULL) BN_free(b);
    if (x != NULL) BN_free(x);
    if (y != NULL) BN_free(y);
    if (gcd != NULL) BN_free(gcd);

    return 0;
}