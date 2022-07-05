/*
 * Copyright 2020 NXP
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

#include <INTEGRITY.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "seco.h"
#include "seco_os_abs.h"
#include "seco_mu_ioctl.h"

#include <dirent.h>
#include <errno.h>

#define SHE_DEFAULT_DID             0x0u
#define SHE_DEFAULT_TZ              0x0u
#define SHE_DEFAULT_MU              0x1u
#define SHE_DEFAULT_INTERRUPT_IDX   0x0u
#define SHE_DEFAULT_PRIORITY        0x0u
#define SHE_DEFAULT_OPERATING_MODE  0x0u

#define FLAG_WRITE 0x01

struct seco_os_abs_hdl {
    struct seco_handle seco_mu;
    uint32_t type;
};

#define SECO_OS_CRYPTO_DIR "/crypto"
/* SHE storege path */
static char SECO_NVM_SHE_STORAGE_FILE[] = "/crypto/seco_she_nvm";
/* HSM storege path */
#define SECO_OS_HSM_DIR SECO_OS_CRYPTO_DIR"/seco_hsm"
static char SECO_NVM_HSM_STORAGE_FILE[] = SECO_OS_HSM_DIR"/seco_nvm_master";
static char SECO_NVM_HSM_STORAGE_CHUNK_PATH[] = SECO_OS_HSM_DIR"/";
/* SHX storege path */
static char V2X_NVM_SHE_STORAGE_FILE[] = SECO_OS_CRYPTO_DIR"/v2x_she_nvm";
#define SECO_OS_V2X_HSM_DIR SECO_OS_CRYPTO_DIR"/v2x_hsm"
static char V2X_NVM_HSM_STORAGE_FILE[] = SECO_OS_V2X_HSM_DIR"/v2x_nvm_master";
static char V2X_NVM_HSM_STORAGE_CHUNK_PATH[] = SECO_OS_V2X_HSM_DIR"/";

/* SECO MU Resource names used for SHE */
static char SECO_SHE_RES[] = "seco_mu_1_ch0";
static char SECO_SHE_NVM_RES[] = "seco_mu_1_ch1";
/* SECO MU Resource names used for HSM */
static char SECO_HSM_RES[] = "seco_mu_2_ch0";
static char SECO_HSM_SECONDARY_RES[] = "seco_mu_2_ch2";
static char SECO_HSM_NVM_RES[] = "seco_mu_2_ch1";
/* SECO MU Resource names used for V2X */
static char SECO_V2X_SV0_RES[] = "seco_mu_4_ch0";
static char SECO_V2X_SV1_RES[] = "seco_mu_5_ch0";
static char SECO_V2X_SHE_RES[] = "seco_mu_6_ch0";
static char SECO_V2X_SG0_RES[] = "seco_mu_7_ch0";
static char SECO_V2X_SG1_RES[] = "seco_mu_8_ch0";
static char SECO_V2X_SHE_NVM_RES[] = "seco_mu_6_ch1";
static char SECO_V2X_SG1_NVM_RES[] = "seco_mu_8_ch1";

static int get_mu_channel_info(uint32_t type, Value *is_listener,
                               char **resname, char **path, size_t *path_len,
                               char **chunk_path, size_t *chunk_path_len) {
    int result = 0;
    switch (type) {
        case MU_CHANNEL_SECO_SHE:
            if (resname != NULL) {
                *resname = SECO_SHE_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_SECO_SHE_NVM:
            if (resname != NULL) {
                *resname = SECO_SHE_NVM_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 1u;
            }
            if ((path != NULL) && (path_len != NULL)) {
                *path = SECO_NVM_SHE_STORAGE_FILE;
                *path_len = sizeof(SECO_NVM_SHE_STORAGE_FILE) - 1;
            }
            break;
        case MU_CHANNEL_SECO_HSM:
            if (resname != NULL) {
                *resname = SECO_HSM_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_SECO_HSM_2ND:
            if (resname != NULL) {
                *resname = SECO_HSM_SECONDARY_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_SECO_HSM_NVM:
            if (resname != NULL) {
                *resname = SECO_HSM_NVM_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 1u;
            }
            if ((path != NULL) && (path_len != NULL)) {
                *path = SECO_NVM_HSM_STORAGE_FILE;
                *path_len = sizeof(SECO_NVM_HSM_STORAGE_FILE) - 1;
            }
            if ((chunk_path != NULL) && (chunk_path_len != NULL)) {
                *chunk_path = SECO_NVM_HSM_STORAGE_CHUNK_PATH;
                *chunk_path_len = sizeof(SECO_NVM_HSM_STORAGE_CHUNK_PATH) - 1;
            }
            break;
        case MU_CHANNEL_V2X_SV0:
            if (resname != NULL) {
                *resname = SECO_V2X_SV0_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_V2X_SV1:
            if (resname != NULL) {
                *resname = SECO_V2X_SV1_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_V2X_SHE:
            if (resname != NULL) {
                *resname = SECO_V2X_SHE_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_V2X_SG0:
            if (resname != NULL) {
                *resname = SECO_V2X_SG0_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_V2X_SG1:
            if (resname != NULL) {
                *resname = SECO_V2X_SG1_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 0u;
            }
            break;
        case MU_CHANNEL_V2X_SHE_NVM:
            if (resname != NULL) {
                *resname = SECO_V2X_SHE_NVM_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 1u;
            }
            if ((path != NULL) && (path_len != NULL)) {
                *path = V2X_NVM_SHE_STORAGE_FILE;
                *path_len = sizeof(V2X_NVM_SHE_STORAGE_FILE) - 1;
            }
            break;
        case MU_CHANNEL_V2X_HSM_NVM:
            if (resname != NULL) {
                *resname = SECO_V2X_SG1_NVM_RES;
            }
            if (is_listener != NULL) {
                *is_listener = 1u;
            }
            if ((path != NULL) && (path_len != NULL)) {
                *path = V2X_NVM_HSM_STORAGE_FILE;
                *path_len = sizeof(V2X_NVM_HSM_STORAGE_FILE) - 1;
            }
            if ((chunk_path != NULL) && (chunk_path_len != NULL)) {
                *chunk_path = V2X_NVM_HSM_STORAGE_CHUNK_PATH;
                *chunk_path_len = sizeof(V2X_NVM_HSM_STORAGE_CHUNK_PATH) - 1;
            }
            break;
        default:
            result = 1;
#ifdef DEBUG
            printf("Unsupported channel number!\n");
#endif
            break;
    }
    return result;
}

int prepare_fs(void)
{
    int err = 0;
    DIR *dir = NULL;
    static volatile Address api_init = 0U;
    static Boolean fs_initialisated = false;

    while (TestAndSet(&api_init, 0U, 1U) != Success) {
        usleep(100);
    }
    if (!fs_initialisated) {
        WaitForFileSystemInitialization();
        dir = opendir(SECO_OS_CRYPTO_DIR);
        if (dir == NULL) {
            err = mkdir(SECO_OS_CRYPTO_DIR, 0600);
        }
        else {
            closedir(dir);
        }
#ifdef DEBUG
        if ((err != 0) && (errno != EEXIST)) {
            printf("Cannot create the /crypto folder! [%s]\n", strerror(errno));
        }
#endif
        if (err == 0) {
            dir = opendir(SECO_OS_HSM_DIR);
            if (dir == NULL) {
                err = mkdir(SECO_OS_HSM_DIR, 0600);
            }
            else {
                closedir(dir);
            }
#ifdef DEBUG
            if ((err != 0) && (errno != EEXIST)) {
                printf("Cannot create the /crypto/seco_hsm folder! [%s]\n", strerror(errno));
            }
#endif
        }
        if (err == 0) {
            dir = opendir(SECO_OS_V2X_HSM_DIR);
            if (dir == NULL) {
                err = mkdir(SECO_OS_V2X_HSM_DIR, 0600);
            }
            else {
                closedir(dir);
            }
#ifdef DEBUG
            if ((err != 0) && (errno != EEXIST)) {
                printf("Cannot create the /crypto/seco_hsm folder! [%s]\n", strerror(errno));
            }
#endif
        }
        if (err == 0) {
            fs_initialisated = true;
        }
    }
    api_init = 0U;
   
    return err;
}

uint32_t seco_os_abs_has_v2x_hw(void)
{
    char *resname = NULL;
    Value is_listener = 0;
    uint32_t result = 0;

    if (get_mu_channel_info(MU_CHANNEL_V2X_SV0, &is_listener, &resname,
                                     NULL, NULL, NULL, NULL) == 0) {
        if (seco_mu_exists(resname) == Success) {
            result = 1;
        }
    }
    return result;
}

struct seco_os_abs_hdl *seco_os_abs_open_mu_channel(uint32_t type, struct seco_mu_params *mu_params)
{
    struct seco_os_abs_hdl *phdl = NULL;
    char *resname = NULL;
    Value is_listener = 0;
    int status = (mu_params == NULL) ? 1 : 0;
    Error E;

    if (status == 0) {
        status = get_mu_channel_info(type, &is_listener, &resname,
                                     NULL, NULL, NULL, NULL);
    }
    if (status == 0) {
        status = prepare_fs();
    }
    if (status == 0) {
        phdl = (struct seco_os_abs_hdl *)malloc(sizeof(struct seco_os_abs_hdl));
        if (phdl == NULL) {
            status = 1;
        }
    }
    if (status == 0) {
        E = seco_mu_open(&phdl->seco_mu, type, resname, is_listener);
        if ((E == AlreadyRegistered) && (type == MU_CHANNEL_SECO_HSM)) {
            type = MU_CHANNEL_SECO_HSM_2ND;
            status = get_mu_channel_info(type, &is_listener, &resname,
                                         NULL, NULL, NULL, NULL);
            if (status == 0) {
                E = seco_mu_open(&phdl->seco_mu, type, resname, is_listener);
            }
        }
        if (E != Success) {
            status = 1;
        }
    }
    if (status == 0) {
        phdl->type = type;
        mu_params->interrupt_idx = phdl->seco_mu.info.interrupt_idx;
        mu_params->mu_id = phdl->seco_mu.info.idx;
        mu_params->tz = phdl->seco_mu.info.tz;
        mu_params->did = phdl->seco_mu.info.did;
    }
    else {
        if (phdl != NULL) {
            free(phdl);
        }
        phdl = NULL;
    }

    return phdl;
}

/* Close a previously opened session (SHE or storage). */
void seco_os_abs_close_session(struct seco_os_abs_hdl *phdl)
{
    if (phdl != NULL) {
        seco_mu_close(&phdl->seco_mu);
        free(phdl);
    }
}

/* Send a message to Seco on the MU. Return the size of the data written. */
int32_t seco_os_abs_send_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    int32_t retval = 0;
    if ((phdl != NULL) && (message != NULL) && (size != 0U)) {
        retval = seco_mu_write(&phdl->seco_mu, message, size);
    }
    return retval;
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
int32_t seco_os_abs_read_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    int32_t retval = 0;

    if ((phdl != NULL) && (message != NULL) && (size != 0U)) {
        retval = seco_mu_read(&phdl->seco_mu, message, size);
    }
    return retval;
}

/* Map the shared buffer allocated by Seco. */
int32_t seco_os_abs_configure_shared_buf(struct seco_os_abs_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
    int32_t error = (phdl == NULL) ? 1 : 0;
    
    if (error == 0) {
        if (seco_mu_config_shared_buff(&phdl->seco_mu, shared_buf_off, size) != Success) {
            error = 1;
        }
    }

    return error;
}

uint64_t seco_os_abs_data_buf(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
{
    uint64_t seco_addr = 0UL;

    if ((phdl != NULL) && (src != NULL) && (size != 0U)) {
        if (flags & FLAG_WRITE) {
            seco_addr = seco_shared_buff_write(&phdl->seco_mu, src, size, flags);
        } else {
            seco_addr = seco_shared_buff_read(&phdl->seco_mu, src, size, flags);
        }
    }

    return seco_addr;
}

uint32_t seco_os_abs_crc(uint8_t *data, uint32_t size)
{
    uint32_t crc = 0U;
    uint32_t i;
    uint32_t nb_words = size / (uint32_t)sizeof(uint32_t);

    for (i = (data == NULL) ? nb_words : 0U; i < nb_words; i++) {
        crc ^= *(data + i);
    }
    return crc;
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t seco_os_abs_storage_write(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path = NULL;
    size_t path_len = 0U;

    if ((phdl != NULL) && (src != NULL) && (size != 0U)) {
        get_mu_channel_info(phdl->type, NULL, NULL,
                            &path, &path_len, NULL, NULL);
    }
    if (path != NULL) {
        /* Open or create the file with access reserved to the current user. */
        fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
        if (fd >= 0) {
            /* Write the data. */
            l = (int32_t)write(fd, src, size);

            (void)close(fd);
        }
    }

    return l;
}

int32_t seco_os_abs_storage_read(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path = NULL;
    size_t path_len = 0U;

    if ((phdl != NULL) && (dst != NULL) && (size != 0U)) {
        get_mu_channel_info(phdl->type, NULL, NULL,
                            &path, &path_len, NULL, NULL);
    }

    if (path != NULL) {
        /* Open the file as read only. */
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            /* Read the data. */
            l = (int32_t)read(fd, dst, size);

            (void)close(fd);
        }
    }

    return l;
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t seco_os_abs_storage_write_chunk(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint64_t blob_id)
{
    int32_t fd = -1;
    int32_t l = 0;
    int n = -1;
    char *path = NULL;
    char *chunk_path = NULL;
    size_t chunk_path_len = 0U;

    if ((phdl != NULL) && (src != NULL) && (size != 0U)) {
        get_mu_channel_info(phdl->type, NULL, NULL,NULL, NULL, 
                            &chunk_path, &chunk_path_len);
    }
    if (chunk_path != NULL) {
        chunk_path_len += 1u + 16u;
        path = malloc(chunk_path_len);
    }
    if (path != NULL) {
        (void)mkdir(chunk_path, S_IRUSR|S_IWUSR);
        n = snprintf(path, chunk_path_len,
                        "%s%016lx", chunk_path, blob_id);
    }
    if (n > 0) {
        /* Open or create the file with access reserved to the current user. */
        fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
    }
    if (fd >= 0) {
        /* Write the data. */
        l = (int32_t)write(fd, src, size);

        (void)close(fd);
    }
    if(path != NULL) {
        free(path);
    }

    return l;
}

int32_t seco_os_abs_storage_read_chunk(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size, uint64_t blob_id)
{
    int32_t fd = -1;
    int32_t l = 0;
    int n = -1;
    char *path = NULL;
    char *chunk_path = NULL;
    size_t chunk_path_len = 0U;

    if ((phdl != NULL) && (dst != NULL) && (size != 0U)) {
        get_mu_channel_info(phdl->type, NULL, NULL,NULL, NULL, 
                            &chunk_path, &chunk_path_len);
    }
    if (chunk_path != NULL) {
        chunk_path_len += 1u + 16u;
        path = malloc(chunk_path_len);
    }
    if (path != NULL) {
        n = snprintf(path, chunk_path_len,
                        "%s%016lx",chunk_path, blob_id);
    }
    if (n > 0) {
        /* Open the file as read only. */
        fd = open(path, O_RDONLY);
    }
    if (fd >= 0) {
        /* Read the data. */
        l = (int32_t)read(fd, dst, size);

        (void)close(fd);
    }
    if(path != NULL) {
        free(path);
    }

    return l;
}

void seco_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len)
{
    (void)memset(dst, (int32_t)val, len);
}

void seco_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
    (void)memcpy(dst, src, len);
}

uint8_t *seco_os_abs_malloc(uint32_t size)
{
    return (uint8_t *)malloc(size);
}

void seco_os_abs_free(void *ptr)
{
    free(ptr);
}

void seco_os_abs_start_system_rng(struct seco_os_abs_hdl *phdl)
{
}

int32_t seco_os_abs_send_signed_message(struct seco_os_abs_hdl *phdl, uint8_t *signed_message, uint32_t msg_len)
{
    /* Send the message to the kernel that will forward to SCU.*/
    int32_t seco_err = ((phdl == NULL) || (signed_message == NULL) || (msg_len == 0U))? 1 : 0;

    if (seco_err == 0) {
        seco_err = seco_send_signed_msg(&phdl->seco_mu, signed_message, msg_len);
    }

    return seco_err;
}

