/*
 * Copyright 2019 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "seco_nvm.h"

// input  Qx||lsb_Qy
static uint8_t ECC_P256_Qx[32+1] =
{ 0xCE, 0x4D, 0xCF, 0xA7, 0x38, 0x4C, 0x83, 0x44, 0x3A, 0xCE, 0x0F, 0xB8, 0x2C, 0x4A, 0xC1, 0xAD,
  0xFA, 0x10, 0x0A, 0x9B, 0x2C, 0x7B, 0xF0, 0x9F, 0x09, 0x3F, 0x8B, 0x6D, 0x08, 0x4E, 0x50, 0xC2, 0x01};

static uint8_t ECC_BRAINPOOL_R1_256_Qx[32+1] =
{ 0x7D, 0x91, 0x41, 0xD7, 0x4A, 0xCB, 0x3F, 0xD8, 0x65, 0xF0, 0xB4, 0xE2, 0x92, 0x16, 0x67, 0x37,
  0x96, 0x04, 0xAB, 0xE6, 0x6E, 0x25, 0x5A, 0x37, 0x71, 0x63, 0x99, 0xE4, 0x5A, 0x51, 0xB9, 0xCB, 0x01};

static uint8_t ECC_P384_Qx[48+1] =
{ 0xCB, 0x90, 0x8B, 0x1F, 0xD5, 0x16, 0xA5, 0x7B, 0x8E, 0xE1, 0xE1, 0x43, 0x83, 0x57, 0x9B, 0x33,
  0xCB, 0x15, 0x4F, 0xEC, 0xE2, 0x0C, 0x50, 0x35, 0xE2, 0xB3, 0x76, 0x51, 0x95, 0xD1, 0x95, 0x1D,
  0x75, 0xBD, 0x78, 0xFB, 0x23, 0xE0, 0x0F, 0xEF, 0x37, 0xD7, 0xD0, 0x64, 0xFD, 0x9A, 0xF1, 0x44,0x01 };

/* ECIES test vectors */
static uint8_t ecies_input[16] = {0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
                            0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D};

static uint8_t ecies_p1[32] = {0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F,
                               0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
                               0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA,
                               0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9 };

static uint8_t ecies_pubk[2*32] = {
    0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
    0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
    0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
    0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9
};

static void public_key_test(hsm_hdl_t hsm_session_hdl)
{
    op_pub_key_rec_args_t hsm_op_pub_key_rec_args;
    op_pub_key_dec_args_t hsm_op_pub_key_dec_args;
    uint8_t out[64];
    uint8_t out_384[96];
    uint32_t i;
    hsm_err_t err;

    /* P256 */
    hsm_op_pub_key_dec_args.key = ECC_P256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 2*32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\n", err);
#ifdef DEBUG
    printf("output:\n");
    for (i=0; i<64; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

    /* Brainpool R1 256 */
    hsm_op_pub_key_dec_args.key = ECC_BRAINPOOL_R1_256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 2*32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\n", err);
#ifdef DEBUG
    printf("output:\n");
    for (i=0; i<64; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

    /* P384 */
    hsm_op_pub_key_dec_args.key = ECC_P384_Qx;
    hsm_op_pub_key_dec_args.out_key = out_384;
    hsm_op_pub_key_dec_args.key_size = 49;
    hsm_op_pub_key_dec_args.out_key_size = 96;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P384;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\n", err);
#ifdef DEBUG
    printf("output:\n");
    for (i=0; i<96; i++) {
        printf("0x%x ", out_384[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif
}

static void ecies_tests(hsm_hdl_t hsm_session_hdl)
{
    op_ecies_enc_args_t op_ecies_enc_args;
    op_ecies_dec_args_t op_ecies_dec_args;
    uint8_t out[3*32]; //VCT
    uint8_t key_plain[16];
    hsm_err_t err;

    op_ecies_enc_args.input = ecies_input;
    op_ecies_enc_args.pub_key = ecies_pubk;
    op_ecies_enc_args.p1 = ecies_p1;
    op_ecies_enc_args.p2 = NULL;
    op_ecies_enc_args.output = out;
    op_ecies_enc_args.input_size = 16;
    op_ecies_enc_args.p1_size = 32;
    op_ecies_enc_args.p2_size = 0;
    op_ecies_enc_args.pub_key_size = 2*32;
    op_ecies_enc_args.mac_size = 16;
    op_ecies_enc_args.out_size = 3*32;
    op_ecies_enc_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_enc_args.flags = 0u;
    op_ecies_enc_args.reserved= 0u;

    err = hsm_ecies_encryption(hsm_session_hdl, &op_ecies_enc_args);
    printf("hsm_ecies_encrypt ret:0x%x \n", err);
#if DEBUG
    printf("hsm_ecies_encrypt output:\n");
    for (uint32_t i=0; i<96; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }
#endif

}

static void transient_key_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl)
{
	open_svc_key_management_args_t key_mgmt_args;
	hsm_hdl_t key_mgmt_hdl;
	uint8_t pub_key[64];
	op_generate_key_args_t key_gen_args;
	uint32_t master_key_id;
	op_butt_key_exp_args_t butterfly_gen_args;
	uint32_t butterfly_key_id;
	uint8_t exp_data[32] = {
		0xA4, 0x3A, 0x19, 0x55, 0x9A, 0xA4, 0x15, 0xE5,
		0xCB, 0xD7, 0x84, 0xEB, 0x44, 0x14, 0xC0, 0x37,
		0x44, 0xC8, 0xFE, 0xF6, 0x15, 0xF6, 0x5E, 0x9B,
		0x63, 0x23, 0x5E, 0x2F, 0xDE, 0x44, 0xA3, 0x8E };
	open_svc_sign_gen_args_t open_sig_gen_args;
	hsm_hdl_t  sig_gen_hdl;
	op_generate_sign_args_t sig_gen_args;
	uint8_t hash_data[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	uint8_t signature_data[65];
	open_svc_sign_ver_args_t open_sig_ver_args;
	hsm_hdl_t sig_ver_hdl;
	op_verify_sign_args_t sig_ver_args;
	hsm_verification_status_t verif_status;
	uint32_t sym_key_id;
	open_svc_cipher_args_t open_cipher_args;
	op_cipher_one_go_args_t cipher_args;
	hsm_hdl_t cipher_hdl;
	uint8_t ciphered_data[32 + 16 + 12]; /* Include space for CCM tag + iv */
	uint8_t deciphered_data[32];
	uint8_t iv_data[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	op_manage_key_args_t del_args;
	hsm_err_t hsmret;

	memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));
	hsmret = hsm_open_key_management_service(
		key_store_hdl, &key_mgmt_args, &key_mgmt_hdl);
	printf("hsm_open_key_store_service ret:0x%x\n", hsmret);

	memset(&key_gen_args, 0, sizeof(key_gen_args));
	key_gen_args.key_identifier = &master_key_id;
	key_gen_args.out_size = sizeof(pub_key);
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_group = 1;
	key_gen_args.key_info = HSM_KEY_INFO_TRANSIENT | HSM_KEY_INFO_MASTER;
	key_gen_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
	key_gen_args.out_key = pub_key;
	hsmret = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	printf("hsm_generate_key ret:0x%x\n", hsmret);

	memset(&butterfly_gen_args, 0, sizeof(butterfly_gen_args));
	butterfly_gen_args.key_identifier = master_key_id;
	butterfly_gen_args.expansion_function_value = exp_data;
	butterfly_gen_args.hash_value = NULL;
	butterfly_gen_args.pr_reconstruction_value = NULL;
	butterfly_gen_args.expansion_function_value_size = sizeof(exp_data);
	butterfly_gen_args.hash_value_size = 0;
	butterfly_gen_args.pr_reconstruction_value_size = 0;
	butterfly_gen_args.flags = HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE |
				HSM_OP_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF;
	butterfly_gen_args.dest_key_identifier = &butterfly_key_id;
	butterfly_gen_args.output = pub_key;
	butterfly_gen_args.output_size = sizeof(pub_key);
	butterfly_gen_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
	butterfly_gen_args.key_group = 101;
	butterfly_gen_args.key_info = HSM_KEY_INFO_TRANSIENT;
	hsmret = hsm_butterfly_key_expansion(key_mgmt_hdl, &butterfly_gen_args);
	printf("hsm_butterfly_key_expansion ret:0x%x\n", hsmret);

	memset(&open_sig_gen_args, 0, sizeof(open_sig_gen_args));
	hsmret = hsm_open_signature_generation_service(key_store_hdl,
					&open_sig_gen_args, &sig_gen_hdl);
	printf("hsm_open_signature_generation_service ret:0x%x\n", hsmret);

	memset(&sig_gen_args, 0, sizeof(sig_gen_args));
	sig_gen_args.key_identifier = butterfly_key_id;
	sig_gen_args.message = hash_data;
	sig_gen_args.signature = signature_data;
	sig_gen_args.message_size = sizeof(hash_data);
	sig_gen_args.signature_size = sizeof(signature_data);
	sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
	sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	hsmret = hsm_generate_signature(sig_gen_hdl, &sig_gen_args);
	printf("hsm_generate_signature ret:0x%x\n", hsmret);

	hsmret = hsm_close_signature_generation_service(sig_gen_hdl);
	printf("hsm_close_signature_generation_service ret:0x%x\n", hsmret);

	memset(&open_sig_ver_args, 0, sizeof(open_sig_ver_args));
	hsmret = hsm_open_signature_verification_service(sess_hdl,
					&open_sig_ver_args, &sig_ver_hdl);
	printf("hsm_open_signature_verification_service ret:0x%x\n", hsmret);

	memset(&sig_ver_args, 0, sizeof(sig_ver_args));
	sig_ver_args.key = pub_key;
	sig_ver_args.message = hash_data;
	sig_ver_args.signature = signature_data;
	sig_ver_args.key_size = sizeof(pub_key);
	sig_ver_args.signature_size = sizeof(signature_data);
	sig_ver_args.message_size = sizeof(hash_data);
	sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
	sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
	hsmret = hsm_verify_signature (sig_ver_hdl, &sig_ver_args,
							&verif_status);
	printf("hsm_verify_signature ret:0x%x\n", hsmret);
	if (verif_status == HSM_VERIFICATION_STATUS_SUCCESS)
		printf("Verification PASS\n");
	else
		printf("Verification FAIL, status:0x%x\n", verif_status);

	hsmret = hsm_close_signature_verification_service(sig_ver_hdl);
	printf("hsm_close_signature_verification_service ret:0x%x\n", hsmret);

	memset(&del_args, 0, sizeof(del_args));
	del_args.key_identifier = &master_key_id;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	del_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
	del_args.key_group = 1;
	hsmret = hsm_manage_key(key_mgmt_hdl, &del_args);
	printf("hsm_manage_key ret:0x%x\n", hsmret);

	memset(&del_args, 0, sizeof(del_args));
	del_args.key_identifier = &butterfly_key_id;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	del_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
	del_args.key_group = 101;
	hsmret = hsm_manage_key(key_mgmt_hdl, &del_args);
	printf("hsm_manage_key ret:0x%x\n", hsmret);

	memset(&key_gen_args, 0, sizeof(key_gen_args));
	key_gen_args.key_identifier = &sym_key_id;
	key_gen_args.out_size = 0;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_group = 1001;
	key_gen_args.key_info = HSM_KEY_INFO_TRANSIENT;
	key_gen_args.key_type = HSM_KEY_TYPE_AES_256;
	key_gen_args.out_key = NULL;
	hsmret = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	printf("hsm_generate_key ret:0x%x\n", hsmret);

	memset(&open_cipher_args, 0, sizeof(open_cipher_args));
	hsmret = hsm_open_cipher_service (key_store_hdl, &open_cipher_args,
						&cipher_hdl);
	printf("hsm_open_cipher_service ret:0x%x\n", hsmret);

	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = 32;
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CBC hsm_cipher_one_go ret:0x%x\n", hsmret);

	memset(&deciphered_data, 0, sizeof(deciphered_data));
	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = sizeof(iv_data);
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CBC;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = 32;
	cipher_args.output_size = sizeof(deciphered_data);
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CBC hsm_cipher_one_go ret:0x%x\n", hsmret);
	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("AES CBC Decrypted data matches encrypted data [PASS]\n");
	else
		printf("AES CBC Decrypted data doesn't match encrypted data [FAIL]\n");

	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = iv_data;
	cipher_args.iv_size = 4;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT | HSM_CIPHER_ONE_GO_FLAGS_GENERATE_COUNTER_IV;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CCM counter IV hsm_cipher_one_go ret:0x%x\n", hsmret);

	memset(&deciphered_data, 0, sizeof(deciphered_data));
	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = &ciphered_data[32 + 16];
	cipher_args.iv_size = 12;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = 32 + 16;
	cipher_args.output_size = sizeof(deciphered_data);
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CCM counter IV hsm_cipher_one_go ret:0x%x\n", hsmret);
	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("AES CCM counter IV Decrypted data matches encrypted data [PASS]\n");
	else
		printf("AES CCM counter IV Decrypted data doesn't match encrypted data [FAIL]\n");

	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = NULL;
	cipher_args.iv_size = 0;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT | HSM_CIPHER_ONE_GO_FLAGS_GENERATE_FULL_IV;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CCM generate IV hsm_cipher_one_go ret:0x%x\n", hsmret);

	memset(&deciphered_data, 0, sizeof(deciphered_data));
	memset(&cipher_args, 0, sizeof(cipher_args));
	cipher_args.key_identifier = sym_key_id;
	cipher_args.iv = &ciphered_data[32 + 16];
	cipher_args.iv_size = 12;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = 32 + 16;
	cipher_args.output_size = sizeof(deciphered_data);
	hsmret = hsm_cipher_one_go(cipher_hdl, &cipher_args);
	printf("AES CCM generate IV hsm_cipher_one_go ret:0x%x\n", hsmret);
	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("AES CCM generate IV Decrypted data matches encrypted data [PASS]\n");
	else
		printf("AES CCM generate IV Decrypted data doesn't match encrypted data [FAIL]\n");


	hsmret = hsm_close_cipher_service (cipher_hdl);
	printf("hsm_close_cipher_service ret:0x%x\n", hsmret);

	memset(&del_args, 0, sizeof(del_args));
	del_args.key_identifier = &sym_key_id;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	del_args.key_type = HSM_KEY_TYPE_AES_256;
	del_args.key_group = 1001;
	hsmret = hsm_manage_key(key_mgmt_hdl, &del_args);
	printf("hsm_manage_key ret:0x%x\n", hsmret);

	hsmret = hsm_close_key_management_service(key_mgmt_hdl);
	printf("hsm_close_key_management_service ret:0x%x\n", hsmret);
}


static uint32_t nvm_status;

static void *hsm_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);
}


/* Test entry function. */
int main(int argc, char *argv[])
{
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;

    open_session_args_t open_session_args = {'\0'};
    open_svc_key_store_args_t open_svc_key_store_args = {'\0'};

    pthread_t tid;

    hsm_err_t err;

    do {
        nvm_status = NVM_STATUS_UNDEF;

        (void)pthread_create(&tid, NULL, hsm_storage_thread, NULL);

        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            printf("nvm manager failed to start\n");
            break;
        }

        open_session_args.session_priority = 0;
        open_session_args.operating_mode = 0;
        err = hsm_open_session(&open_session_args,
                                    &hsm_session_hdl);
        if (err != HSM_NO_ERROR) {
            printf("hsm_open_session failed err:0x%x\n", err);
            break;
        }
        printf("hsm_open_session PASS\n");

        open_svc_key_store_args.key_store_identifier = 0xABCD;
        open_svc_key_store_args.authentication_nonce = 0x1234;
        open_svc_key_store_args.max_updates_number   = 100;
        open_svc_key_store_args.flags                = 1;
        err = hsm_open_key_store_service(hsm_session_hdl, &open_svc_key_store_args, &key_store_hdl);
        printf("hsm_open_key_store_service ret:0x%x\n", err);

        public_key_test(hsm_session_hdl);

        ecies_tests(hsm_session_hdl);

        transient_key_tests(hsm_session_hdl, key_store_hdl);

        err = hsm_close_key_store_service(key_store_hdl);
        printf("hsm_close_key_store_service ret:0x%x\n", err);

        err = hsm_close_session(hsm_session_hdl);

        printf("hsm_close_session ret:0x%x\n", err);

        (void)pthread_cancel(tid);

        seco_nvm_close_session();

    } while (0);
    return 0;
}
