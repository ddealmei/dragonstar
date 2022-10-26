#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <Hacl_HKDF.h>
#include <Hacl_HMAC.h>
#include <Hacl_Bignum256.h>
#include <Hacl_Bignum.h>
#include <Hacl_P256.h>
#include <Lib_RandomBuffer_System.h>

#include "common.h"
#include "const_time.h"
#include "crypto.h"

#ifdef CONFIG_SHA256

/* No HMAC_update mecanism exposed in HaCl, we need to expose one, or to allocate a new buffer and copy all the elements of addr into it before calling HMAC, which will induce an overhead... */
int hmac_sha256_vector(const u8* key, size_t key_len, size_t num_elem,
                const u8* addr[], const size_t* len, u8* mac)
{
    u8 *buf;
    size_t buf_len = 0;
    for (size_t i = 0; i < num_elem; i++)
        buf_len += len[i];
    buf = os_malloc(buf_len);
    int offset = 0;
    for (size_t i = 0; i < num_elem; i++) {
        memcpy(buf + offset, addr[i], len[i]);
        offset += len[i];
    }

    Hacl_HMAC_compute_sha2_256(mac, (u8*) key, key_len, buf, buf_len);

    Lib_Memzero0_memzero(buf, buf_len);
    os_free(buf);
    return 1;
}


int hmac_sha256(const u8* key, size_t key_len, const u8* data,
        size_t data_len, u8* mac)
{
    Hacl_HMAC_compute_sha2_256(mac, (u8*) key, key_len, (u8 *)data, data_len);
    return 1;
}

#endif /* CONFIG_SHA256 */

int crypto_get_random(void* buf, size_t len)
{
    // Loop until we read enough data, we might want to expose the inner function to avoid infinite loop, and return an error instead.
    Lib_RandomBuffer_System_crypto_random(buf, len);
    return 0;
}


struct bignum_static_methods {
    Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* (*init_ctx)(u64* n);
    void (*free_ctx)(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64*);
    u64* (*new_bn_from_bytes)(u32, u8*);
    void (*bn_to_bytes)(u64*, u8*);
    u64(*add)(u64*, u64*, u64*);
    u64(*sub)(u64*, u64*, u64*);
    void (*mul)(u64*, u64*, u64*);
    void (*sqr)(u64*, u64*);
    bool (*mod)(u64*, u64*, u64*);
    void (*mod_precomp)(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64*, u64*, u64*);
    bool (*modexp_consttime)(u64*, u64*, u32, u64*, u64*);
    void (*modexp_consttime_precomp)(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64*, u64*, u32, u64*, u64*);
    bool (*modinv)(u64*, u64*, u64*);
    void (*modinv_precomp)(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64*, u64*, u64*);
    void (*add_mod)(u64*, u64*, u64*, u64*);
    u64 (*is_lt)(u64*, u64*);
    u64 (*is_eq)(u64*, u64*);
};

const static struct bignum_static_methods bignum_static_methods_256 =
{
    .init_ctx = Hacl_Bignum256_mont_ctx_init,
    .free_ctx = Hacl_Bignum256_mont_ctx_free,
    .new_bn_from_bytes = Hacl_Bignum256_new_bn_from_bytes_be,
    .bn_to_bytes = Hacl_Bignum256_bn_to_bytes_be,
    .add = Hacl_Bignum256_add,
    .sub = Hacl_Bignum256_sub,
    .mul = Hacl_Bignum256_mul,
    .sqr = Hacl_Bignum256_sqr,
    .mod = Hacl_Bignum256_mod,
    .mod_precomp = Hacl_Bignum256_mod_precomp,
    .modexp_consttime = Hacl_Bignum256_mod_exp_consttime,
    .modexp_consttime_precomp = Hacl_Bignum256_mod_exp_consttime_precomp,
    .modinv = Hacl_Bignum256_mod_inv_prime_vartime,
    .modinv_precomp = Hacl_Bignum256_mod_inv_prime_vartime_precomp,
    .add_mod = Hacl_Bignum256_add_mod,
    .is_lt = Hacl_Bignum256_lt_mask,
    .is_eq = Hacl_Bignum256_eq_mask,
};


struct crypto_bignum {
    u64* data;
    size_t data_size;
    const struct bignum_static_methods* meth;
    Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* ctx;
};


void crypto_bignum_print(char* label, const struct crypto_bignum* x) {
    fprintf(stdout, "%s: ", label);
    for (int i = (x->data_size >> 3) - 1; i >= 0; i--)
        fprintf(stdout, "%016lX", x->data[i]);
    fprintf(stdout, "\n");
}


struct crypto_bignum* crypto_bignum_static_init(size_t len)
{
    struct crypto_bignum* bn;

    if (TEST_FAIL())
        return NULL;

    bn = os_zalloc(sizeof(*bn));
    if(bn == NULL)
        return NULL;

    bn->data_size = len;
    bn->data = os_zalloc(len);
    if (bn->data == NULL) {
        os_free(bn);
        return NULL;
    }

    switch (len) {
    case 32:
        bn->meth = &bignum_static_methods_256;
        break;
    default:
        // For now we do not have methods for other length
        bn->meth = NULL;
        break;
    }
    bn->ctx = NULL;

    return bn;
}


struct crypto_bignum* crypto_bignum_static_init_set(const u8* buf, size_t buflen, size_t len)
{
    struct crypto_bignum* bn;
    u8* tmp;

    if (TEST_FAIL())
        return NULL;

    if (buflen > len)
        return NULL;

    bn = os_zalloc(sizeof(*bn));
    if (bn == NULL)
        return NULL;
    bn->data_size = len;
    switch (len) {
    case 32:
        bn->meth = &bignum_static_methods_256;
        break;
    default:
        // For now we do not have methods for other length
        bn->meth = NULL;
    }

    /* use a temporary buffer to ensure we deal with the right length */
    if (buflen != len) {
        tmp = os_zalloc(len);
        memcpy(tmp + (len - buflen), buf, buflen);
    }
    else
        tmp = (u8*) buf;

    if (bn->meth)
        bn->data = bn->meth->new_bn_from_bytes(len, tmp);
    else 
        bn->data = Hacl_Bignum256_new_bn_from_bytes_be(len, tmp);
    bn->ctx = NULL;

    if (bn->data == NULL) {
        free(bn);
        bn = NULL;
        goto end;
    }

    
end:
    if (tmp != buf && tmp)
        free(tmp);
    return (struct crypto_bignum*) bn;
}


struct crypto_bignum* crypto_bignum_static_init_uint(unsigned int val, size_t len)
{
    struct crypto_bignum* bn;
    u8 *buf = NULL;
    buf = os_malloc(sizeof(val));
    for (int i = sizeof(val)-1; i > -1; i--) {
        buf[i] = (u8) val & 0xFF;
        val >>= 8;
    }

    bn = crypto_bignum_static_init_set(buf, sizeof(val), len);

    os_free(buf);
    return bn;
}


void crypto_bignum_deinit(struct crypto_bignum* n, int clear)
{
    if (n == NULL)
        return;
    if (clear)
        Lib_Memzero0_memzero((u8 *)n->data, n->data_size);
    if (n->data) 
        os_free(n->data);
    if (n->ctx)
        n->meth->free_ctx(n->ctx);
    os_free(n);
}


size_t crypto_bignum_static_size(const struct crypto_bignum* n)
{
    return n ? n->data_size : 0;
}


int crypto_bignum_to_bin(const struct crypto_bignum* a,
    u8* buf, size_t buflen, size_t padlen)
{
    int offset;

    if (TEST_FAIL())
        return -1;

    if (padlen > buflen || buflen < a->data_size)
        return -1;
    if (a->data_size > buflen)
        return -1;

    if (padlen > (size_t) a->data_size)
        offset = padlen - a->data_size;
    else
        offset = 0;

    memset(buf, 0, offset);
    a->meth->bn_to_bytes((u64*) a->data, buf + offset);

    return a->data_size + offset;
}


int crypto_bignum_rand(struct crypto_bignum* r, const struct crypto_bignum* m)
{
    if (TEST_FAIL())
        return -1;

    do {
        crypto_get_random((u8 *)r->data, r->data_size);
    } while (crypto_bignum_cmp(r, m) > 0);
    return 0;
}

/* Carefull, this retruns the carry */
int crypto_bignum_add(const struct crypto_bignum* a,
    const struct crypto_bignum* b, struct crypto_bignum* c)
{
    if (a->data_size != b->data_size || b->data_size != c->data_size)
        return -1;
    /* carefull with the carry... */
    return a->meth->add(a->data, b->data, c->data);
}


static inline void static_mod_even(const struct crypto_bignum* a,
    const struct crypto_bignum* b, struct crypto_bignum* c)
{
    struct crypto_bignum* zero = crypto_bignum_static_init_uint(0, a->data_size);
    crypto_bignum_addmod(a, zero, b, c);
    crypto_bignum_deinit(zero, 0);
}


static inline void static_mod_odd(const struct crypto_bignum* a,
    const struct crypto_bignum* b, struct crypto_bignum* c)
{
    u64* tmp;

    // The operand should be twice the size of the modulus
    if (a->data_size != 2 * b->data_size) {
        tmp = os_zalloc(2 * b->data_size);
        os_memcpy(tmp, a->data, a->data_size);
    }
    else
        tmp = a->data;

    if (b->ctx)
        b->meth->mod_precomp(b->ctx, tmp, c->data);
    else
        b->meth->mod(b->data, tmp, c->data);

    if (a->data_size != 2 * b->data_size)
        os_free(tmp);
}


/* Not ct wrt the modulus (leaks its parity), we could do only ststic_mod_even though */
int crypto_bignum_mod(const struct crypto_bignum* a,
    const struct crypto_bignum* b, struct crypto_bignum* c)
{
    if (crypto_bignum_is_odd(b))
        static_mod_odd(a, b, c);
    else
        static_mod_even(a, b, c);
    return 0;
}


int crypto_bignum_exptmod(const struct crypto_bignum *a,
			  const struct crypto_bignum *b,
			  const struct crypto_bignum *c,
			  struct crypto_bignum *d)
{
	int res = 1;
    if (c->ctx)
        c->meth->modexp_consttime_precomp(c->ctx, a->data, 256, b->data, d->data);
    else 
        res = a->meth->modexp_consttime(c->data, a->data, 256, b->data, d->data);
    return res ? 0 : -1;
}


int crypto_bignum_inverse(const struct crypto_bignum *a,
			  const struct crypto_bignum *b,
			  struct crypto_bignum *c)
{
    int res = 1;
    if (b->ctx)
        b->meth->modinv_precomp(b->ctx, a->data, c->data);
    else
        res = a->meth->modinv(b->data, a->data, c->data);
    return res ? 0 : -1;
}

/* Carefull, this retruns the carry */
int crypto_bignum_sub(const struct crypto_bignum* a, const struct crypto_bignum* b, struct crypto_bignum* c)
{
    if (TEST_FAIL())
        return -1;

    if (a->data_size != b->data_size || b->data_size != c->data_size)
        return -1;
    /* carefull with the carry... */
    return a->meth->sub(a->data, b->data, c->data);
}


int crypto_bignum_addmod(const struct crypto_bignum* a,
    const struct crypto_bignum* b,
    const struct crypto_bignum* c,
    struct crypto_bignum* d)
{
    if (TEST_FAIL())
        return -1;

    if (a->data_size != b->data_size || b->data_size != c->data_size || c->data_size != d->data_size)
        return -1;
    c->meth->add_mod(c->data, a->data, b->data, d->data);
    return 0;
}


int crypto_bignum_mulmod(const struct crypto_bignum* a,
    const struct crypto_bignum* b,
    const struct crypto_bignum* c,
    struct crypto_bignum* d)
{
    int success = 1;
    struct crypto_bignum* tmp;

    if (TEST_FAIL())
        return -1;

    if (a->data_size != b->data_size || b->data_size != c->data_size || c->data_size != d->data_size)
        return -1;

    tmp = crypto_bignum_static_init(a->data_size*2);
    if (tmp == NULL)
        return -1;

    a->meth->mul(a->data, b->data, tmp->data);
    if (c->ctx)
        a->meth->mod_precomp(c->ctx, tmp->data, d->data);
    else
        success = a->meth->mod(c->data, tmp->data, d->data);

    crypto_bignum_deinit(tmp, 1);
    return success ? 0 : -1;
}


int crypto_bignum_sqrmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 struct crypto_bignum *c)
{
    int success = 1;
    struct crypto_bignum* tmp;

    if (TEST_FAIL())
        return -1;

    if (a->data_size != b->data_size || b->data_size != c->data_size)
        return -1;

    tmp = crypto_bignum_static_init(a->data_size * 2);
    if (tmp == NULL)
        return -1;

    b->meth->sqr(a->data, tmp->data);
    if (b->ctx)
        b->meth->mod_precomp(b->ctx, tmp->data, c->data);
    else
        success = b->meth->mod(b->data, tmp->data, c->data);

    crypto_bignum_deinit(tmp, 1);
    return success ? 0 : -1;
}


static int crypto_bignum_rshift1(const struct crypto_bignum* a, struct crypto_bignum* r) {
    u64* ap, * rp, t, c;
    int i;
    u64 limb_size_2, limb_mask_2;

    if (r == NULL)
        r = crypto_bignum_static_init(a->data_size);

    // if (crypto_bignum_is_zero(a)) {
    //     memset(r->data, 0, r->data_size);
    //     return 0;
    // }
    limb_size_2 = sizeof(a->data[0]) << 3;
    limb_mask_2 = -1;

    ap = a->data;
    rp = r->data;
    i = a->data_size >> 3;
    t = ap[--i];
    rp[i] = t >> 1;
    c = t << (limb_size_2 - 1);

    while (i > 0) {
        t = ap[--i];
        rp[i] = ((t >> 1) & limb_mask_2) | c;
        c = t << (limb_size_2 - 1);
    }

    return 0;
}

int crypto_bignum_rshift(const struct crypto_bignum* a, int n, struct crypto_bignum* r) {
    int err = 0;
    for (size_t i = 0; i < n; i++)
        err |= crypto_bignum_rshift1(a, r);
    return err;
}


int crypto_bignum_cmp(const struct crypto_bignum* a,
    const struct crypto_bignum* b)
{
    u64 is_lt, is_eq;
    u64 res = 1;
    u64 eq = 0, lt = -1;

    is_lt = a->meth->is_lt(a->data, b->data);
    is_eq = a->meth->is_eq(a->data, b->data);
    res = (is_lt & lt) | (~is_lt & res);
    res = (is_eq & eq) | (~is_eq & res);

    return (int) res;
}


int crypto_bignum_is_zero(const struct crypto_bignum* a)
{
    int zero_limbs = 0;

    if (a == NULL || a->data == NULL)
        return -1;
    zero_limbs = a->data[0] == 0;
    for (int i = 1; i < a->data_size >> 3 ; i++)
        zero_limbs += a->data[i] == 0;
    return zero_limbs == a->data_size >> 3;
}


int crypto_bignum_is_one(const struct crypto_bignum* a)
{
    int valid_limbs = 0;

    if (a == NULL || a->data == NULL)
        return -1;
    valid_limbs = a->data[0] == 1;
    for (int i = 1; i < a->data_size >> 3; i++)
        valid_limbs += a->data[i] == 0;
    return valid_limbs == a->data_size >> 3;
}


// CHECK THIS FOR CORRECTNESS...
int crypto_bignum_is_odd(const struct crypto_bignum* a)
{
    return (a->data)[0] & 1;
}


static const u64 one_bn256[4U] =
{
    0x1U,
    0x0U,
    0x0U,
    0x0U
};


int crypto_bignum_legendre(const struct crypto_bignum* a,
    const struct crypto_bignum* p)
{
    struct crypto_bignum* tmp = NULL, *exp = NULL;
    int res = -2;
    unsigned int mask;

    if (TEST_FAIL())
        return -2;

    if (a->data_size != p->data_size)
        goto fail;

    exp = crypto_bignum_static_init(a->data_size);
    if (exp == NULL)
        goto fail;
    tmp = crypto_bignum_static_init(a->data_size);
    if (tmp == NULL)
        goto fail;

    if (a->meth->sub(p->data, (u64*)one_bn256, exp->data))
        goto fail;
    if (crypto_bignum_rshift1(exp, exp))
        goto fail;

    if (p->ctx)
        a->meth->modexp_consttime_precomp(p->ctx, a->data, 256, exp->data, tmp->data);
    else
        if (!a->meth->modexp_consttime(p->data, a->data, 256, exp->data, tmp->data))
            goto fail;

    /* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need to use
     * constant time selection to avoid branches here. */
    res = -1;
    mask = const_time_eq(crypto_bignum_is_one(tmp), 1);
    res = const_time_select_int(mask, 1, res);
    mask = const_time_eq(crypto_bignum_is_zero(tmp), 1);
    res = const_time_select_int(mask, 0, res);

fail:
    crypto_bignum_deinit(tmp, 1);
    crypto_bignum_deinit(exp, 1);

    return res;
}

#ifdef CONFIG_ECC

/* P256 related constants */

const u8 p256prime_bin[32U] =
{
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


const u8 p256order_bin[32U] =
{
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};


const u8 p256a_bin[32U] =
{
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
};


const u8 p256b_bin[32U] =
{
  0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};


struct ec_methods {
    void(*point_to_bin)(u8*, u8*);
    void(*add)(u64*, u64*, u64*);
    u64(*scalar_mult)(u8*, u8*, u8*);
    void(*point_inv)(u64*, u64*);
    bool(*set_compressed_coordinates)(u8*, u8*); // FIXME : 2nd arg should be u64*
    bool(*is_on_curve)(u8*);  // FIXME: should take u64*
    void (*jacobianToAffine)(u64* , u64*);
    void (*affineToJacobian)(u64* , u64*);
    void (*toBin)(u64* , u8*);
    void (*fromBin)(u8* , u64*);
};


const static struct ec_methods p256_methods =
{
    .point_to_bin = Hacl_P256_compression_not_compressed_form_p256,
    .add = Hacl_P256_point_add_out, // FIXME: input format is currently not indomain
    .scalar_mult = Hacl_P256_ecp256dh_r_private_radix,
    .point_inv = Hacl_P256_point_inv,
    .set_compressed_coordinates = Hacl_P256_decompression_compressed_form_p256,
    .is_on_curve = Hacl_P256_verify_q_private, //FIXME: currently take a u8...
    .affineToJacobian = Hacl_P256_point_toDomain,
    .jacobianToAffine = Hacl_P256_point_norm,
    .toBin = Hacl_P256_point_fromForm,
    .fromBin = Hacl_P256_point_toForm,
};


struct crypto_ec {
    struct crypto_bignum* prime;
    struct crypto_bignum* order;
    struct crypto_bignum* a;
    struct crypto_bignum* b;
    const struct ec_methods* meth;
};


struct crypto_ec* crypto_ec_init(int group)
{
    struct crypto_ec* e;
    e = os_malloc(sizeof(*e));
    if (e == NULL)
        return e;

    switch (group) {
    case 19:
        e->prime = crypto_bignum_static_init_set(p256prime_bin, 32, 32);
        e->prime->ctx = e->prime->meth->init_ctx(e->prime->data);
        e->order = crypto_bignum_static_init_set(p256order_bin, 32, 32);        
        e->order->ctx = e->order->meth->init_ctx(e->order->data);
        e->a = crypto_bignum_static_init_set(p256a_bin, 32, 32);
        e->b = crypto_bignum_static_init_set(p256b_bin, 32, 32);
        e->meth = &p256_methods;
        break;
        /* Only support P256 for now
        case 20:
            break;
        case 21:
            break;
        case 25:
            break;
        case 26:
            break;
        case 27:
            break;
    #ifdef NID_brainpoolP256r1
        case 28:
            break;
        case 29:
            break;
        case 30:
            break;
    */
    default:
        return NULL;
    }
    return e;
}


void crypto_ec_deinit(struct crypto_ec* e)
{
    if (e == NULL)
        return;
    crypto_bignum_deinit(e->order, 0);
    crypto_bignum_deinit(e->prime, 0);
    crypto_bignum_deinit(e->a, 0);
    crypto_bignum_deinit(e->b, 0);
    os_free(e);
}


struct crypto_ec_point {
    u64 *data;
    size_t size_bytes;
    int in_domain;
};


struct crypto_ec_point* crypto_ec_point_init(struct crypto_ec *e)
{
    if (TEST_FAIL())
        return NULL;
    if (e == NULL)
        return NULL;

    struct crypto_ec_point *point;
    point = os_malloc(sizeof(*point));
    if (point == NULL)
        return NULL;
    point->in_domain = 0;
    // store x, y, z in a row
    point->size_bytes = 3 * e->prime->data_size;
    point->data = os_zalloc(point->size_bytes);
    if (point->data == NULL) {
        os_free(point);
        return NULL;
    }
    // set the third coordinate to 1
    size_t pos_z = 2 * (point->size_bytes / (3 * sizeof(*point->data)));
    point->data[pos_z] = 1U;

    return point;
}


size_t crypto_ec_prime_len(struct crypto_ec *e)
{
    return e == NULL ? 0 : crypto_bignum_static_size(e->prime);
}


size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
    return e == NULL ? 0 : crypto_bignum_static_size(e->prime) << 3;
}


size_t crypto_ec_order_len(struct crypto_ec *e)
{
    return e == NULL ? 0 : crypto_bignum_static_size(e->order);
}


const struct crypto_bignum* crypto_ec_get_prime(struct crypto_ec *e)
{
    return e->prime;
}


const struct crypto_bignum* crypto_ec_get_order(struct crypto_ec *e)
{
    return e->order;
}


const struct crypto_bignum * crypto_ec_get_a(struct crypto_ec *e)
{
	return (const struct crypto_bignum *) e->a;
}


const struct crypto_bignum * crypto_ec_get_b(struct crypto_ec *e)
{
	return (const struct crypto_bignum *) e->b;
}


void crypto_ec_point_deinit(struct crypto_ec_point* p, int clear)
{
    if (p == NULL)
        return;
    if (p->data) {
        if (clear)
            Lib_Memzero0_memzero((u8 *) p->data, p->size_bytes);
        os_free(p->data);
    }
    os_free(p);
}


/* x and y should already be allocated if we want their coordinate */
int crypto_ec_point_to_bin(struct crypto_ec *e,
    const struct crypto_ec_point* point, u8* x, u8* y)
{
    int ret = -1;
    size_t len = crypto_ec_prime_len(e);
    struct crypto_ec_point* q = (struct crypto_ec_point*) point;

    if (TEST_FAIL())
        return -1;

    if (q->in_domain)
    {
        q = crypto_ec_point_init(e);
        e->meth->jacobianToAffine(point->data, q->data);
    }
    u8* buf = os_malloc(2 * len);
    if (buf == NULL) {
        if (q != point && q) {
            crypto_ec_point_deinit(q, 1);
        }
        return -1;
    }
    e->meth->toBin(q->data, buf);
    //FIXME: shouldn't be needed...
    u8 waste[112];
    e->meth->toBin(q->data, waste);

    if (x)
        memcpy(x, buf, len);
    if (y)
        memcpy(y, buf+len, len);
    ret = 0;

    if (q != point && q) {
        crypto_ec_point_deinit(q, 1);
    }

    Lib_Memzero0_memzero(buf, 2*len);
    os_free(buf);

    return ret;
}


struct crypto_ec_point* crypto_ec_point_from_bin(struct crypto_ec *e, const u8* val)
{
    struct crypto_ec_point* point = NULL;

    if (TEST_FAIL())
        return NULL;

    point = crypto_ec_point_init(e);
    if (point == NULL)
        return NULL;
    e->meth->fromBin((u8 *) val, point->data);

    return point;
}


int crypto_ec_point_add(struct crypto_ec *e,
    const struct crypto_ec_point* a, const struct crypto_ec_point* b,
    struct crypto_ec_point* c)
{
    int ret = -1;
    struct crypto_ec_point *p = (struct crypto_ec_point*) a;
    struct crypto_ec_point* q = (struct crypto_ec_point*) b;

    if (TEST_FAIL())
        return -1;

    if (!a->in_domain) {
        p = crypto_ec_point_init(e);
        e->meth->affineToJacobian(a->data, p->data);
        p->in_domain = 1;
    }
    if (!b->in_domain) {
        q = crypto_ec_point_init(e);
        e->meth->affineToJacobian(b->data, q->data);
        q->in_domain = 1;
    }

    e->meth->add(p->data, q->data, c->data);
    c->in_domain = 1;

    ret = 0;
    if (p != a && p)
        crypto_ec_point_deinit(p, 1);
    if (q != b && q)
        crypto_ec_point_deinit(q, 1);
    return ret;
}


int crypto_ec_point_mul(struct crypto_ec *e,
    const struct crypto_ec_point* p, const struct crypto_bignum* b,
    struct crypto_ec_point* res)
{
    int ret = -1;
    u8 *scalar;
    u8* res_buf;
    u8* point_buf;

    if (TEST_FAIL())
        return -1;

    scalar = os_malloc(b->data_size);
    res_buf = os_malloc(p->size_bytes);
    point_buf = os_malloc(p->size_bytes);
    if (scalar != NULL && p->data != NULL && res_buf != NULL && point_buf != NULL) {
        // Convert our u64* point into unit8_t*
        crypto_ec_point_to_bin(e, p, point_buf, point_buf + 32);
        point_buf[p->size_bytes - 1] = 1U;
        // Convert our bignum into u8
        crypto_bignum_to_bin(b, scalar, b->data_size, b->data_size);

        ret = e->meth->scalar_mult(res_buf, point_buf, scalar);
        res->in_domain = 0;
        e->meth->fromBin(res_buf, res->data);
        int limb_size = (p->size_bytes / (3 * sizeof(*p->data)));
        res->data[2*limb_size] = 1U;
    }

    if (scalar) os_free(scalar);
    if (res_buf) os_free(res_buf);
    if (point_buf) os_free(point_buf);

    return ret == 1 ? 0 : -1;
}


int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point* p) {
    int ret = -1;
    // FIXME: Inplace inversion instead ? For now w zero out the result at the begining...
    u64 *buf;

    if (TEST_FAIL())
        return -1;

    buf = os_malloc(p->size_bytes);
    if (buf == NULL)
        return -1;
    memcpy((u8*) buf, (u8*) p->data, p->size_bytes);
    if (e != NULL && p != NULL && p->data != NULL) {
        e->meth->point_inv(buf, p->data);
        ret = 0;
    }

    Lib_Memzero0_memzero((u8*)buf, p->size_bytes);
    os_free(buf);
    return ret;
}


struct crypto_bignum* crypto_ec_point_compute_y_sqr(
    struct crypto_ec *e, const struct crypto_bignum* x)
{
    struct crypto_bignum *ysqr;

    if (TEST_FAIL())
        return NULL;

    ysqr = crypto_bignum_static_init(x->data_size);
    if (ysqr == NULL)
        return NULL;

    // (x^2 + a)*x + b % p
    crypto_bignum_sqrmod(x, e->prime, ysqr);
    crypto_bignum_addmod(ysqr, e->a, e->prime, ysqr);
    crypto_bignum_mulmod(ysqr, x, e->prime, ysqr);
    crypto_bignum_addmod(ysqr, e->b, e->prime, ysqr);

    return ysqr;
}


int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
    const struct crypto_ec_point* p)
{
    u64 res = 0;
    struct crypto_ec_point* q = (struct crypto_ec_point*) p;

    if (p->in_domain) {
        q = crypto_ec_point_init(e);
        e->meth->jacobianToAffine(p->data, q->data);
        q->in_domain = 0;
    }
    // Discard the check on Z coordinate
    size_t pos_z = 2 * (q->size_bytes / (3 * sizeof(*q->data)));
    for (size_t i = 0; i < pos_z; i++) {
        res |= q->data[i] != 0;
    }

    if (q != p && q)
        crypto_ec_point_deinit(q, 1);

    return res == 0 ? 1 : 0;
}


// FIXME: u64 instead of u8
int crypto_ec_point_is_on_curve(struct crypto_ec *e,
    const struct crypto_ec_point* p)
{
    int ret = -1;
    u64 *q = p->data;
    u8* buf = os_malloc(p->size_bytes);
    if (buf == NULL) {
        os_free(q);
        return -1;
    }
    if (p->in_domain) {
        q = os_malloc(p->size_bytes);
        if (q == NULL) {
            os_free(buf);
            return -1;
        }
        e->meth->jacobianToAffine(p->data, q);
    }
    e->meth->toBin(q, buf);
    if (q == p->data) {
        //FIXME: shouldn't be needed...
        u8 waste[112];
        e->meth->toBin(q, waste);
    }
    ret = e->meth->is_on_curve(buf) == 0 ? 0 : -1;
    if (q != p->data && q) {
        Lib_Memzero0_memzero((u8*) q, p->size_bytes);
        os_free(q);
    }
    Lib_Memzero0_memzero((u8*) buf, p->size_bytes);
    os_free(buf);
    return ret;
}


int crypto_ec_point_cmp(const struct crypto_ec *e,
    const struct crypto_ec_point* a, const struct crypto_ec_point* b)
{
    int ret = 0;
    struct crypto_ec_point *p, *q;
    
    if (a == NULL || b == NULL)
        return -1;
    p = (struct crypto_ec_point*) a;
    q = (struct crypto_ec_point*) b;
    if (p->in_domain != q->in_domain){
        if (!a->in_domain) {
            p = crypto_ec_point_init((struct crypto_ec *)e);
            e->meth->affineToJacobian(a->data, p->data);
        }
        else {
            q = crypto_ec_point_init((struct crypto_ec *)e);
            e->meth->affineToJacobian(b->data, q->data);
        }
    }

    for (int i = 0; i < a->size_bytes/sizeof(*(a->data)); i++)
        ret |= p->data[i] != q->data[i];

    if (p != a && p)
        crypto_ec_point_deinit(p, 1);
    if (q != b && q)
        crypto_ec_point_deinit(q, 1);
    return ret;
}


#endif /* CONFIG_ECC */
