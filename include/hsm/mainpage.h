/*! \mainpage HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */

/*! \page  History Revision History
 *
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 -  | Mar 29 2019  | Preliminary draft
 * 0.8 -  | May 24 2019  | It adds the following API: \n-signature generation \n-signature verification \n-rng \n-hash \n-butterfly key expansion \n-ECIES enc/dec \n-public key reconstruction \n-public key decompression
 * 0.9 -  | May 28 2019  | Explicit addresses are replaced by pointers.
 * 1.0 -  | May 29 2019  | - bug/typos fix. \n- Change HSM_SVC_KEY_STORE_FLAGS definition
 * 1.1 -  | July 31 2019 | - hsm_butterfly_key_expansion argument definition: dest_key_identifier is now a pointer. \n- add error code definition. \n- improve argument comments clarity
 * 1.5 -  | Sept 13 2019 | - manage key argument: fix padding size\n - butterfly key expansion: change argument definition\n- introduce public key recovery API
 * 1.6 -  | Oct 14 2019  | - add Key store section in chapter 3\n- change key_info and flags definition, substitute key_type_ext with group_id\n- hsm_generate_key, hsm_manage_key, hsm_butterfly_key_expansion: change argument definition\n- hsm_manage_key: change argument definition\n- add hsm_manage_key_group API
 * 1.7 -  | Dec 20 2019  | - add generic data storage API \n- add GCM and CMAC support\n- add support for AES 192/256 key size for all cipher algorithms\n - add root KEK export API\n - add key import functionality\n- add get info API
 * 2.0 -  | Feb 21 2020  | - fix HSM_KEY_INFO_TRANSIENT definition: delete erroneous "not supported" comment \n- add Key Encryption Key (HSM_KEY_INFO_KEK) support \n- key store open service API: adding signed message support for key store reprovisionning \n- naming consistency: remove "hsm_" prefix from \n hsm_op_ecies_dec_args_t \n hsm_op_pub_key_rec_args_t \n hsm_op_pub_key_dec_args_t \n hsm_op_ecies_enc_args_t \n hsm_op_pub_key_recovery_args_t \n hsm_op_get_info_args_t
 * 2.1 - subject to change | Apr 16 2020  | - Preliminary version: Add the support of the chinese algorithms and update for i.MX8DXL
 * 2.2 | Apr 30 2020  | - fix erroneous number of supported key groups (correct number is 1000 while 1024 was indicated)\n- add missing status code definition \n- remove hsm_open_key_store_service unused flags: HSM_SVC_KEY_STORE_FLAGS_UPDATE, HSM_SVC_KEY_STORE_FLAGS_DELETE
 * 2.3 | June 30 2020  | - hsm_get_info fips mode definition: now specifying "FIPS mode of operation" and "FIPS certified part" bits.\n- Update i.MX8QXP specificities section specifying operations disabled when in FIPS approved mode. \n- Update comments related to cipher_one_go and SM2 ECES APIs for i.MX8DXL
 * 2.4 | July 9 2020 | - clarify support of hsm_import_public key API.
 * 2.5 | July 28 2020 | - add section in "i.MX8QXP specificities" chapter indicating the maximum number of keys per group.
 * 2.6 | Jul 29 2020  | - Key Exchange: add the definition of ECDH_P384 and TLS KDFs\n- mac_one_go: add definition of HMAC SHA256/384.
 * */

/*! \page page1 General concepts related to the API
  \tableofcontents
  \image latex hsm_services.png
  \section sec1 Session
  The API must be initialized by a potential requestor by opening a session.\n
  The session establishes a route (MU, DomainID...) between the requester and the HSM.
  When a session is opened, the HSM returns a handle identifying the session to the requester.
  \section sec2 Service flow
  For a given category of services, the requestor is expected to open a service flow by invoking the appropriate HSM API.\n
  The session handle, as well as the control data needed for the service flow, are provided as parameters of the call.\n
  Upon reception of the open request, the HSM allocates a context in which the session handle, as well as the provided control parameters are stored and return a handle identifying the service flow.\n
  The context is preserved until the service flow, or the session, are closed by the user and it is used by the HSM to proceed with the sub-sequent operations requested by the user on the service flow.
  \section sec3 Example
  \image latex code_example.PNG
  \section sec4 Key store
  A key store can be created by specifying the CREATE flag in the hsm_open_key_store_service API. Please note that the created key store will be not stored in the NVM till a key is generated/imported specyfing the "STRICT OPERATION" flag.\n
  Only symmetric and private keys are stored into the key store. Public keys can be exported during the key pair generation operation or recalculated through the hsm_pub_key_recovery API.\n
  Secret keys cannot be exported under any circumstances, while they can be imported in encrypted form.\n
  \subsection subsec2 Key management
  Keys are divided in groups, keys belonging to the same group are written/read from the NVM as a monolitic block.\n
  Up to 3 key groups can be handled in the HSM local memory (those immediatly available to perform crypto operations), while up to 1000 key groups can be handled in the external NVM and imported in the local memory as needed.\n
  If the local memory is full (3 key groups already reside in the HSM local memory) and a new key group is needed by an incoming user request, the HSM swaps one of the local key group with the one needed by the user request.\n
  The user can control which key group must be kept in the local memory (cached) through the manage_key_group API lock/unlock mechanism.\n
  As general concept, frequently used keys should be kept, when possible, in the same key group and locked in the local memory for performance optimization.\n
  \subsection subsec3 NVM writing
  All the APIs modyfing the content of the key store (key generation, key_management, key derivation functions) provide a "STRICT OPERATION" flag. If the flag is set, the HSM triggers and export of the encrypted key group into the external NVM and increments (blows one bit) the OTP monotonic counter used as roll back protection. Please note that the "STRICT OPERATION" has effect only on the current key group.\n
  Any update to the key store must be considered as effective only after an operation specifing the flag "STRICT OPERATION" is aknowledged by the HSM. All the operations not specifying the "STRICT OPERATION" flags impact the HSM local memory only and will be lost in case of system reset\n
  Due to the limited monotonic counter size (QXPB0 up to 1620 update available by default), the user should, when possible, perform multiple udates before setting the "STRICT OPERATION" flag (i.e. keys to be updated should be kept in the same key group).\n
  Once the monotonic counter is completely blown a warning is returned on each update operation to inform the user that the new updates are not roll-back protected.
  \section sec5 Implementation specificities
  HSM API is supported on different versions of the i.MX8 family. The API description below is the same for all of them but some features may not be available on some chips. The details of the supported features per chip can be found here:
  - for i.MX8QXP: \ref qxp_specific
  - for i.MX8DXL: \ref dxl_specific
 */

/**
 * \defgroup qxp_specific i.MX8QXP specificities
 *
 */

/**
 * \defgroup dxl_specific i.MX8DXL specificities
 *
 */

/**
 *\addtogroup qxp_specific
 * \ref sec4
 *
 * The table below summarizes the maximum number of keys per group in the QXP implementation:
 * Key size (bits)| Number of keys per group
 * :------------: | :-------------:
 * 128 | 169
 * 192 | 126
 * 224 | 101
 * 256 | 101
 * 384 | 72
 * 512 | 56
 *
 */
