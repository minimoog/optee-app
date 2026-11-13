#include <stdbool.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "hpke.h"

#define NH    32	/* SHA-256 output */
#define NK    32	/* AES-256 key */
#define NN    12	/* GCM nonce */
#define P256  32
#define BUFSZ 320

static const uint8_t KEM_SUITE[]  = { 'K','E','M',     0x00,0x10 };
static const uint8_t HPKE_SUITE[] = { 'H','P','K','E', 0x00,0x10, 0x00,0x01, 0x00,0x02 };

struct buf { uint8_t d[BUFSZ]; size_t n; };

// put p to buf
static bool put(struct buf *b, const void *p, size_t n)
{
	if (!n)
		return true;

	if (n > sizeof(b->d) - b->n)
		return false;

	memcpy(b->d + b->n, p, n);

	b->n += n;
	return true;
}

/* ---------- HMAC-SHA256 / HKDF ---------- */

static TEE_Result hmac_sha256(const uint8_t *key, size_t key_len,  //key
			      const uint8_t *msg, size_t msg_len,              //msg
			      uint8_t out[NH])                                 //output
{
	TEE_ObjectHandle k = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute attr;
	uint32_t out_len = NH;
	TEE_Result res;

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_len * 8, &k);
	if (res)
		return res;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_len);
	res = TEE_PopulateTransientObject(k, &attr, 1);
	if (res)
		goto out;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
				    key_len * 8);
	if (res)
		goto out;

	res = TEE_SetOperationKey(op, k);
	if (res)
		goto out;

	TEE_MACInit(op, NULL, 0);
	res = TEE_MACComputeFinal(op, msg, msg_len, out, &out_len);

out:
	TEE_FreeOperation(op);
	TEE_FreeTransientObject(k);
	return res;
}

/* LabeledExtract(salt, label, ikm) = HMAC(salt, "HPKE-v1" || suite_id || label || ikm) */

static TEE_Result labeled_extract(const uint8_t *suite, size_t suite_len,
				  const uint8_t *salt, size_t salt_len,
				  const char *label,
				  const uint8_t *ikm, size_t ikm_len,
				  uint8_t out[NH])
{
	static const uint8_t zeros[NH];
	struct buf b = { .n = 0 };
	TEE_Result res;

	if (!put(&b, "HPKE-v1", 7) || 								// + HPKE-v1
		!put(&b, suite, suite_len) ||                           // + suite
	    !put(&b, label, strlen(label)) ||                       // + label
	    !put(&b, ikm, ikm_len))                                 // + ikm
		return TEE_ERROR_BAD_PARAMETERS;

	if (!salt_len) {		/* RFC 5869: empty salt = Nh zero bytes */
		salt = zeros;
		salt_len = NH;
	}

	res = hmac_sha256(salt, salt_len, b.d, b.n, out);
	TEE_MemFill(&b, 0, sizeof(b));

	return res;
}

/* LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L) */

static TEE_Result labeled_expand(const uint8_t *suite, size_t suite_len,
				 const uint8_t prk[NH],
				 const char *label,
				 const uint8_t *info, size_t info_len,
				 size_t L, 
				 uint8_t *out)
{
	struct buf li = { .n = 0 }, ib;

	uint8_t l2[2] = { (uint8_t)(L >> 8), (uint8_t)L };

	uint8_t t[NH], i = 1;
	size_t tlen = 0, done = 0, n;
	TEE_Result res = TEE_SUCCESS;

	if (L > 255 * NH)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!put(&li, l2, 2) ||
	    !put(&li, "HPKE-v1", 7) ||
	    !put(&li, suite, suite_len) || 
	    !put(&li, label, strlen(label)) ||
	    !put(&li, info, info_len))
		return TEE_ERROR_BAD_PARAMETERS;

	while (done < L) {		/* T(i) = HMAC(prk, T(i-1) || info || i) */
		ib.n = 0;

		if (!put(&ib, t, tlen) || 
			!put(&ib, li.d, li.n) ||
		    !put(&ib, &i, 1)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
		}

		res = hmac_sha256(prk, NH, ib.d, ib.n, t);
		if (res)
			break;

		tlen = NH;
		n = (L - done < NH) ? L - done : NH;
		memcpy(out + done, t, n);

		done += n;
		i++;
	}

	TEE_MemFill(t, 0, sizeof(t));
	TEE_MemFill(&li, 0, sizeof(li));
	TEE_MemFill(&ib, 0, sizeof(ib));

	return res;
}

static TEE_Result get_padded(TEE_ObjectHandle o,
	                         uint32_t attr,
			                 uint8_t *dst, size_t len)
{
	uint8_t tmp[P256];
	uint32_t n = sizeof(tmp);
	TEE_Result res = TEE_GetObjectBufferAttribute(o, attr, tmp, &n);

	if (res)
		return res;

	memset(dst, 0, len - n);	/* big-endian, left-pad to fixed size */
	memcpy(dst + len - n, tmp, n);

	return TEE_SUCCESS;
}
