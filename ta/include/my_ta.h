#ifndef MY_TA_H
#define MY_TA_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */

//ef5a9bc1-251a-4081-9fbf-14694164610e

#define TA_MY_UUID \
	{ 0xef5a9bc1, 0x251a, 0x4081, \
		{ 0x9f, 0xbf, 0x14, 0x69, 0x41, 0x64, 0x61, 0x0e} }

#define TA_MY_CMD_HPKE_SEAL   0
/*
 * params[0] MEMREF_INPUT  : pkR, 65 bytes
 * params[1] MEMREF_INPUT  : plaintext
 * params[2] MEMREF_OUTPUT : enc, 65 bytes  (encapsulated key)
 * params[3] MEMREF_OUTPUT : ciphertext || tag (pt_len + 16)
 */

#endif /*MY_TA_H*/
