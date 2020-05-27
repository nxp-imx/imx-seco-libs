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

static char SECO_NVM_SHE_STORAGE_FILE[] = "/crypto/seco_she_nvm";
static char SECO_NVM_HSM_STORAGE_FILE[] = "/crypto/seco_hsm/seco_nvm_master";
static char SECO_NVM_HSM_STORAGE_CHUNK_PATH[] = "/crypto/seco_hsm/";

/* SECO MU Resource names used for SHE */
#define SECO_SHE_RES     "seco_mu_1_ch0"
#define SECO_SHE_NVM_RES "seco_mu_1_ch1"
/* SECO MU Resource names used for HSM */
#define SECO_HSM_RES     "seco_mu_2_ch0"
#define SECO_HSM_NVM_RES "seco_mu_2_ch1"

int prepare_fs(void)
{
    int err;

    WaitForFileSystemInitialization();

    err = mkdir("/crypto",0600);
    if ((err != 0) && (errno != EEXIST)) {
        printf("Cannot create the /crypto folder! [%s]\n", strerror(errno));
        return 1;
    } else if (err == 0) {
        printf("/crypto created \n");
    }
    err = mkdir("/crypto/seco_hsm",0600);
    if ((err != 0) && (errno != EEXIST)) {
        printf("Cannot create the /crypto/seco_hsm folder! [%s]\n", strerror(errno));
        return 1;
    } else if (err == 0){
        printf("/crypto/seco_hsm created\n");
    }

    return 0;
}

uint32_t seco_os_abs_has_v2x_hw(void)
{
    return 0;
}


struct seco_os_abs_hdl *seco_os_abs_open_mu_channel(uint32_t type, struct seco_mu_params *mu_params)
{
    struct seco_os_abs_hdl *phdl = malloc(sizeof(struct seco_os_abs_hdl));
    char *resname = NULL;
    Value is_listener = 0;

    if (prepare_fs()) {
        return NULL;
    }

    if ((phdl != NULL) && (mu_params != NULL)) {

        if (phdl != NULL) {
            phdl->type = type;

            mu_params->interrupt_idx = SHE_DEFAULT_INTERRUPT_IDX;

            switch (type) {
                case MU_CHANNEL_SECO_SHE:
                    resname = SECO_SHE_RES;
                    break;
                case MU_CHANNEL_SECO_SHE_NVM:
                    resname = SECO_SHE_NVM_RES;
                    is_listener = 1u;
                    break;
                case MU_CHANNEL_SECO_HSM:
                    resname = SECO_HSM_RES;
                    break;
                case MU_CHANNEL_SECO_HSM_NVM:
                    resname = SECO_HSM_NVM_RES;
                    is_listener = 1u;
                    break;
                default:
                    printf("Unsupported channel number!\n");
                    break;
            }

            if (!resname) {
                return NULL;
            }

            if (seco_mu_open(&phdl->seco_mu, type, resname, is_listener) != Success) {
                free(phdl);
                phdl = NULL;
            }

            mu_params->mu_id = phdl->seco_mu.mu_id;
            mu_params->tz = phdl->seco_mu.tz;
            mu_params->did = phdl->seco_mu.did;
        }
    }

    return phdl;
}

/* Close a previously opened session (SHE or storage). */
void seco_os_abs_close_session(struct seco_os_abs_hdl *phdl)
{
    free(phdl);
}

/* Send a message to Seco on the MU. Return the size of the data written. */
int32_t seco_os_abs_send_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    int32_t retval;

    retval = seco_mu_write(&phdl->seco_mu, message, size);

    return retval;
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
int32_t seco_os_abs_read_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    int32_t retval;

    retval = seco_mu_read(&phdl->seco_mu, message, size);
    return retval;
}

/* Map the shared buffer allocated by Seco. */
int32_t seco_os_abs_configure_shared_buf(struct seco_os_abs_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
    int32_t error = 0;

    if (seco_mu_config_shared_buff(&phdl->seco_mu, shared_buf_off, size) != Success) {
        error = 1;
    }

    return error;
}

uint64_t seco_os_abs_data_buf(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
{
    uint64_t seco_addr;

    if (flags & FLAG_WRITE) {
        seco_addr = seco_shared_buff_write(&phdl->seco_mu, src, size, flags);
    } else {
        seco_addr = seco_shared_buff_read(&phdl->seco_mu, src, size, flags);
    }

    return seco_addr;
}

uint32_t seco_os_abs_crc(uint8_t *data, uint32_t size)
{
    uint32_t crc;
    uint32_t i;
    uint32_t nb_words = size / (uint32_t)sizeof(uint32_t);

    crc = 0u;
    for (i = 0u; i < nb_words; i++) {
        crc ^= *(data + i);
    }
    return crc;
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t seco_os_abs_storage_write(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;

    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_SECO_SHE_NVM:
        path = SECO_NVM_SHE_STORAGE_FILE;
        break;
    case MU_CHANNEL_SECO_HSM_NVM:
        path = SECO_NVM_HSM_STORAGE_FILE;
        break;
    default:
        path = NULL;
        break;
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

    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_SECO_SHE_NVM:
        path = SECO_NVM_SHE_STORAGE_FILE;
        break;
    case MU_CHANNEL_SECO_HSM_NVM:
        path = SECO_NVM_HSM_STORAGE_FILE;
        break;
    default:
        path = NULL;
        break;
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
    char *path = malloc(sizeof(SECO_NVM_HSM_STORAGE_CHUNK_PATH)+16u);

    if ((path != NULL) && (phdl->type == MU_CHANNEL_SECO_HSM_NVM)) {
        (void)mkdir(SECO_NVM_HSM_STORAGE_CHUNK_PATH, S_IRUSR|S_IWUSR);
        n = snprintf(path, sizeof(SECO_NVM_HSM_STORAGE_CHUNK_PATH)+16u,
                        "%s%016lx", SECO_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
    }
    if (n > 0) {
        /* Open or create the file with access reserved to the current user. */
        fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
        if (fd >= 0) {
            /* Write the data. */
            l = (int32_t)write(fd, src, size);

            (void)close(fd);
        }
    }

    free(path);

    return l;
}

int32_t seco_os_abs_storage_read_chunk(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size, uint64_t blob_id)
{
    int32_t fd = -1;
    int32_t l = 0;

    int n = -1;
    char *path = malloc(sizeof(SECO_NVM_HSM_STORAGE_CHUNK_PATH)+16u);

    if ((path != NULL) && (phdl->type == MU_CHANNEL_SECO_HSM_NVM)) {
        n = snprintf(path, sizeof(SECO_NVM_HSM_STORAGE_CHUNK_PATH)+16u,
                        "%s%016lx",SECO_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
    }


    if (n > 0) {
        /* Open the file as read only. */
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            /* Read the data. */
            l = (int32_t)read(fd, dst, size);

            (void)close(fd);
        }
    }
    free(path);

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
    uint32_t seco_err = 0;

    if (seco_send_signed_msg(&phdl->seco_mu, signed_message, msg_len, &seco_err) != Success) {
        seco_err = 1;
    }

    return seco_err;
}