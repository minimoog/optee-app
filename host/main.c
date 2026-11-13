// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <my_ta.h>

#include "recipient_pk.h"

#define HPKE_NPK  65
#define HPKE_NENC 65
#define HPKE_NT   16

static void hex(const char *tag, const uint8_t *p, size_t n)
{
	printf("%s: ", tag);
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	static const uint8_t pkR[HPKE_NPK] = RECIPIENT_PK;
	const char *msg = argc > 1 ? argv[1] : "hello hpke";
	size_t msg_len = strlen(msg);
	uint8_t enc[HPKE_NENC], ct[256 + HPKE_NT];
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_MY_UUID;
	uint32_t origin;
	TEEC_Result res;

	if (msg_len > 256) {
		fprintf(stderr, "message too long\n");
		return 1;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("InitContext: 0x%x\n", res); return 1;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
		printf("OpenSession: 0x%x (origin %u)\n", res, origin); return 1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = (void *)pkR;
	op.params[0].tmpref.size   = sizeof(pkR);
	op.params[1].tmpref.buffer = (void *)msg;
	op.params[1].tmpref.size   = msg_len;
	op.params[2].tmpref.buffer = enc;
	op.params[2].tmpref.size   = sizeof(enc);
	op.params[3].tmpref.buffer = ct;
	op.params[3].tmpref.size   = sizeof(ct);

	res = TEEC_InvokeCommand(&sess, TA_MY_CMD_HPKE_SEAL, &op, &origin);
	if (res != TEEC_SUCCESS) {
		printf("Invoke: 0x%x (origin %u)\n", res, origin); return 1;
	}

	hex("enc", enc, op.params[2].tmpref.size);
	hex("ct ", ct,  op.params[3].tmpref.size);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
