#ifndef HPKE_H
#define HPKE_H

#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>

#define HPKE_NPK   65	/* uncompressed P-256 point */
#define HPKE_NENC  65
#define HPKE_NT    16	/* GCM tag */

TEE_Result hpke_seal_base(const uint8_t pkR[HPKE_NPK],
			  const uint8_t *info, size_t info_len,
			  const uint8_t *aad, size_t aad_len,
			  const uint8_t *pt, size_t pt_len,
			  uint8_t enc[HPKE_NENC],
			  uint8_t *ct /* pt_len + HPKE_NT bytes */);


#endif //HPKE_H