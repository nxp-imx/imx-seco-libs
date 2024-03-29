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

#ifndef SECO_MU_IOCTL_H
#define SECO_MU_IOCTL_H

/* IOCTL definitions. */
struct seco_mu_ioctl_setup_iobuf {
	uint8_t *user_buf;
	uint32_t length;
	uint32_t flags;
	uint64_t seco_addr;
};
struct seco_mu_ioctl_shared_mem_cfg {
	uint32_t base_offset;
	uint32_t size;
};

struct seco_mu_ioctl_get_mu_info {
	uint8_t seco_mu_idx;
	uint8_t interrupt_idx;
	uint8_t tz;
	uint8_t did;
	uint8_t cmd_tag;
	uint8_t rsp_tag;
	uint8_t success_tag;
	uint8_t base_api_ver;
	uint8_t fw_api_ver;
};

struct seco_mu_ioctl_signed_message {
	uint8_t *message;
	uint32_t msg_size;
	uint32_t error_code;
};

#define SECO_MU_IO_FLAGS_IS_INTPUT	(0x01u)
#define SECO_MU_IO_FLAGS_USE_SEC_MEM	(0x02u)
#define SECO_MU_IO_FLAGS_USE_SHORT_ADDR	(0x04u)

#define SECO_MU_IOCTL			0x0A /* like MISC_MAJOR. */
#define SECO_MU_IOCTL_ENABLE_CMD_RCV	_IO(SECO_MU_IOCTL, 0x01)
#define SECO_MU_IOCTL_SHARED_BUF_CFG	_IOW(SECO_MU_IOCTL, 0x02, \
			struct seco_mu_ioctl_shared_mem_cfg)
#define SECO_MU_IOCTL_SETUP_IOBUF	_IOWR(SECO_MU_IOCTL, 0x03, \
			struct seco_mu_ioctl_setup_iobuf)
#define SECO_MU_IOCTL_GET_MU_INFO	_IOR(SECO_MU_IOCTL, 0x04, \
			struct seco_mu_ioctl_get_mu_info)
#define SECO_MU_IOCTL_SIGNED_MESSAGE	_IOWR(SECO_MU_IOCTL, 0x05, \
			struct seco_mu_ioctl_signed_message)

#endif
