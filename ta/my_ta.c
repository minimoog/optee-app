// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <my_ta.h>

#include "hpke.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Goodbye!\n");
}

static TEE_Result cmd_seal(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		                                 TEE_PARAM_TYPE_MEMREF_INPUT,
		                                 TEE_PARAM_TYPE_MEMREF_OUTPUT,
		                                 TEE_PARAM_TYPE_MEMREF_OUTPUT);

	uint8_t pkR[HPKE_NPK];
	uint8_t enc[HPKE_NENC];
	uint32_t pt_len, ct_len;
	TEE_Result res;

	//check params

	if (param_types != exp || params[0].memref.size != HPKE_NPK)
		return TEE_ERROR_BAD_PARAMETERS;

	pt_len = params[1].memref.size;
	if (pt_len > UINT32_MAX - HPKE_NT)
		return TEE_ERROR_BAD_PARAMETERS;

	ct_len = pt_len + HPKE_NT;

	if (params[2].memref.size < HPKE_NENC || params[3].memref.size < ct_len) {
		params[2].memref.size = HPKE_NENC;
		params[3].memref.size = ct_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* copy out of shared memory before using it */
	memcpy(pkR, params[0].memref.buffer, HPKE_NPK);

	res = hpke_seal_base(pkR, NULL, 0, NULL, 0,
			     params[1].memref.buffer, pt_len,
			     enc, params[3].memref.buffer);
	if (res)
		return res;

	memcpy(params[2].memref.buffer, enc, HPKE_NENC);
	params[2].memref.size = HPKE_NENC;
	params[3].memref.size = ct_len;
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_MY_CMD_HPKE_SEAL:
		return cmd_seal(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
