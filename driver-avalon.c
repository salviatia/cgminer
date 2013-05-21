/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2013 Xiangfu <xiangfu@openmobilefree.com>
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include "compat.h"
  #include <windows.h>
  #include <io.h>
#endif
#include <pthread.h>

#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "fpgautils.h"
#include "driver-avalon.h"
#include "hexdump.c"
#include "util.h"

static int option_offset = -1;
struct avalon_info **avalon_infos;
struct device_drv avalon_drv;

static int avalon_init_task(struct avalon_task *at,
			    uint8_t reset, uint8_t ff, uint8_t fan,
			    uint8_t timeout, uint8_t asic_num,
			    uint8_t miner_num, uint8_t nonce_elf,
			    uint8_t gate_miner, int frequency)
{
	uint8_t *buf;
	static bool first = true;

	if (unlikely(!at))
		return -1;

	if (unlikely(timeout <= 0 || asic_num <= 0 || miner_num <= 0))
		return -1;

	memset(at, 0, sizeof(struct avalon_task));

	if (unlikely(reset)) {
		at->reset = 1;
		at->fan_eft = 1;
		at->timer_eft = 1;
		first = true;
	}

	at->flush_fifo = (ff ? 1 : 0);
	at->fan_eft = (fan ? 1 : 0);

	if (unlikely(first && !at->reset)) {
		at->fan_eft = 1;
		at->timer_eft = 1;
		first = false;
	}

	at->fan_pwm_data = (fan ? fan : AVALON_DEFAULT_FAN_MAX_PWM);
	at->timeout_data = timeout;
	at->asic_num = asic_num;
	at->miner_num = miner_num;
	at->nonce_elf = nonce_elf;

	at->gate_miner_elf = 1;
	at->asic_pll = 1;

	if (unlikely(gate_miner)) {
		at-> gate_miner = 1;
		at->asic_pll = 0;
	}

	buf = (uint8_t *)at;
	buf[5] = 0x00;
	buf[8] = 0x74;
	buf[9] = 0x01;
	buf[10] = 0x00;
	buf[11] = 0x00;
	if (frequency == 256) {
		buf[6] = 0x03;
		buf[7] = 0x08;
	} else if (frequency == 270) {
		buf[6] = 0x73;
		buf[7] = 0x08;
	} else if (frequency == 282) {
		buf[6] = 0xd3;
		buf[7] = 0x08;
	} else if (frequency == 300) {
		buf[6] = 0x63;
		buf[7] = 0x09;
	}

	return 0;
}

static inline void avalon_create_task(struct avalon_task *at,
				      struct work *work)
{
	memcpy(at->midstate, work->midstate, 32);
	memcpy(at->data, work->data + 64, 12);
}

static bool avalon_buffer_full(struct cgpu_info *avalon)
{
	return avalon_infos[avalon->device_id]->buffer_full;
}

/* Wait till the  buffer can accept more writes. The usb status is updated
 * every 40ms. */
static void avalon_wait_ready(struct cgpu_info *avalon)
{
	while (avalon_buffer_full(avalon))
		nmsleep(50);
}

static int avalon_send_task(const struct avalon_task *at,
			    struct cgpu_info *avalon)

{
	int err;
	struct timespec p;
	uint8_t buf[AVALON_WRITE_SIZE + 4 * AVALON_DEFAULT_ASIC_NUM];
	size_t nr_len;
	struct avalon_info *info;
	uint64_t delay = 32000000; /* Default 32ms for B19200 */
	uint32_t nonce_range;
	int i, amount = 0;

	if (at->nonce_elf)
		nr_len = AVALON_WRITE_SIZE + 4 * at->asic_num;
	else
		nr_len = AVALON_WRITE_SIZE;

	memcpy(buf, at, AVALON_WRITE_SIZE);

	if (at->nonce_elf) {
		nonce_range = (uint32_t)0xffffffff / at->asic_num;
		for (i = 0; i < at->asic_num; i++) {
			buf[AVALON_WRITE_SIZE + (i * 4) + 3] =
				(i * nonce_range & 0xff000000) >> 24;
			buf[AVALON_WRITE_SIZE + (i * 4) + 2] =
				(i * nonce_range & 0x00ff0000) >> 16;
			buf[AVALON_WRITE_SIZE + (i * 4) + 1] =
				(i * nonce_range & 0x0000ff00) >> 8;
			buf[AVALON_WRITE_SIZE + (i * 4) + 0] =
				(i * nonce_range & 0x000000ff) >> 0;
		}
	}
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
	uint8_t tt = 0;

	tt = (buf[0] & 0x0f) << 4;
	tt |= ((buf[0] & 0x10) ? (1 << 3) : 0);
	tt |= ((buf[0] & 0x20) ? (1 << 2) : 0);
	tt |= ((buf[0] & 0x40) ? (1 << 1) : 0);
	tt |= ((buf[0] & 0x80) ? (1 << 0) : 0);
	buf[0] = tt;

	tt = (buf[4] & 0x0f) << 4;
	tt |= ((buf[4] & 0x10) ? (1 << 3) : 0);
	tt |= ((buf[4] & 0x20) ? (1 << 2) : 0);
	tt |= ((buf[4] & 0x40) ? (1 << 1) : 0);
	tt |= ((buf[4] & 0x80) ? (1 << 0) : 0);
	buf[4] = tt;
#endif
	info = avalon_infos[avalon->device_id];
	delay = nr_len * 10 * 1000000000ULL;
	delay = delay / info->baud;

	if (at->reset)
		nr_len = 1;
	if (opt_debug) {
		applog(LOG_DEBUG, "Avalon: Sent(%u):", (unsigned int)nr_len);
		hexdump((uint8_t *)buf, nr_len);
	}

	err = usb_write(avalon, (char *)at, (unsigned int)nr_len, &amount,
			C_AVALON_TASK);

	applog(LOG_DEBUG, "%s%i: usb_write got err %d",
	       avalon->drv->name, avalon->device_id, err);
	if (unlikely(err != 0))
		return AVA_SEND_ERROR;

	p.tv_sec = 0;
	p.tv_nsec = (long)delay + 4000000;
	nanosleep(&p, NULL);
	applog(LOG_DEBUG, "Avalon: Sent: Buffer delay: %ld", p.tv_nsec);

	return AVA_SEND_OK;
}

static bool avalon_valid_ar(struct cgpu_info *avalon, struct avalon_result *ar)
{
	return (!!(find_queued_work_bymidstate(avalon, (char *)ar->midstate, 32,
					       (char *)ar->data, 64, 12)));
}

static int avalon_get_result(struct cgpu_info *avalon, struct avalon_result *ar,
			     int *max_timeout)
{
	struct avalon_info *info = avalon_infos[avalon->device_id];;
	struct timeval now, then, tdiff;
	size_t copied, spare, offset;
	int ret = AVA_GETS_ERROR;
	struct timespec abstime;
	bool found = false;

	cgtime(&now);
	tdiff.tv_sec = *max_timeout / 1000;
	tdiff.tv_usec = *max_timeout * 1000 - (tdiff.tv_sec * 1000000);
	timeradd(&now, &tdiff, &then);
	abstime.tv_sec = then.tv_sec;
	abstime.tv_nsec = then.tv_usec * 1000;

	memset(ar, 0, sizeof(struct avalon_result));

	mutex_lock(&info->read_mutex);
	if (info->offset < AVALON_READ_SIZE || !info->aligned) {
		do {
			ret = pthread_cond_timedwait(&info->read_cond, &info->read_mutex, &abstime);
			if (ret) {
				ret = AVA_GETS_TIMEOUT;
				goto out_unlock;
			}
		} while (info->offset < AVALON_READ_SIZE);
	}

	copied = info->offset;
	spare = copied - AVALON_READ_SIZE;

	for (offset = 0; offset <= spare; offset++) {
		if (avalon_valid_ar(avalon, (struct avalon_result *)&info->readbuf[offset])) {
			found = true;
			break;
		}
	}

	if (!found) {
		if (opt_debug) {
			applog(LOG_DEBUG, "Avalon: No Valid:");
			hexdump((uint8_t *)info->readbuf, copied);
		}
		info->aligned = false;
		goto out_unlock;
	}

	if (offset) {
		applog(LOG_WARNING, "Avalon: Discarded %u bytes from read buffer",
		       (unsigned int)offset);
	}
	info->aligned = true;
	copied = AVALON_READ_SIZE + offset;
	memcpy(ar, &info->readbuf[offset], AVALON_READ_SIZE);
	info->offset -= copied;
	memmove(info->readbuf, &info->readbuf[copied], info->offset);
	if (opt_debug) {
		applog(LOG_DEBUG, "Avalon: get:");
		hexdump((uint8_t *)ar, AVALON_READ_SIZE);
	}
	ret = AVA_GETS_OK;
out_unlock:
	mutex_unlock(&info->read_mutex);

	cgtime(&then);
	timersub(&then, &now, &tdiff);
	*max_timeout -= (tdiff.tv_sec * 1000) + (tdiff.tv_usec / 1000);

	return ret;
}

static bool avalon_decode_nonce(struct thr_info *thr, struct avalon_result *ar,
				uint32_t *nonce)
{
	struct cgpu_info *avalon;
	struct avalon_info *info;
	struct work *work;

	avalon = thr->cgpu;
	if (unlikely(!avalon->works))
		return false;

	work = find_queued_work_bymidstate(avalon, (char *)ar->midstate, 32,
					   (char *)ar->data, 64, 12);
	if (!work)
		return false;

	info = avalon_infos[avalon->device_id];
	info->matching_work[work->subid]++;
	*nonce = htole32(ar->nonce);
	submit_nonce(thr, work, *nonce);

	return true;
}

static void avalon_get_reset(struct cgpu_info *avalon, struct avalon_result *ar)
{
	char result[AVALON_READ_SIZE];
	int err, amount;

	memset(result, 0, AVALON_READ_SIZE);
	memset(ar, 0, AVALON_READ_SIZE);

	err = usb_ftdi_read_timeout(avalon, result, AVALON_READ_SIZE, &amount,
				    2000, C_GET_AR);
	if (err < 0 || amount != AVALON_READ_SIZE) {
		applog(LOG_WARNING, "Avalon: Error %d on read in avalon_get_reset", err);
		applog(LOG_WARNING, "Avalon: USB read asked for %lu, got %d",
		       AVALON_READ_SIZE, amount);
		if (opt_debug && amount) {
			applog(LOG_DEBUG, "Avalon: got:");
			hexdump((uint8_t *)result, amount);
		}
		return;
	}

	if (opt_debug) {
		applog(LOG_DEBUG, "Avalon: get:");
		hexdump((uint8_t *)result, AVALON_READ_SIZE);
	}
	memcpy(ar, result, AVALON_READ_SIZE);
}

static void avalon_clear_readbuf(struct cgpu_info *avalon)
{
	int amount, err;
	char buf[512];

	do {
		err = usb_ftdi_read_timeout(avalon, buf, 510, &amount, 50,
					    C_GET_AVALON_READY);

		applog(LOG_DEBUG, "%s%i: Get avalon ready got err %d",
		       avalon->drv->name, avalon->device_id, err);
	} while (amount > 2);
}

static int avalon_reset(struct cgpu_info *avalon)
{
	struct avalon_result ar;
	uint8_t *buf;
	int err, i = 0, amount;
	struct timespec p;

	avalon_wait_ready(avalon);
	err = usb_write(avalon, "ad", 2, &amount, C_AVALON_RESET);
	applog(LOG_DEBUG, "%s%i: avalon reset got err %d",
	       avalon->drv->name, avalon->device_id, err);
	if (err != 0)
		return 1;

	avalon_get_reset(avalon, &ar);

	buf = (uint8_t *)&ar;
	if (buf[0] == 0xAA && buf[1] == 0x55 &&
	    buf[2] == 0xAA && buf[3] == 0x55) {
		for (i = 4; i < 11; i++)
			if (buf[i] != 0)
				break;
	}

	p.tv_sec = 0;
	p.tv_nsec = AVALON_RESET_PITCH;
	nanosleep(&p, NULL);

	if (i != 11) {
		applog(LOG_ERR, "Avalon: Reset failed! not an Avalon?"
		       " (%d: %02x %02x %02x %02x)",
		       i, buf[0], buf[1], buf[2], buf[3]);
		return 1;
	} else {
		applog(LOG_WARNING, "Avalon: Reset succeeded");
		/* If the reset went according to plan, we can read off the
		 * actual miner_num. */
		avalon_infos[avalon->device_id]->miner_count = ar.miner_num;
	}
	return 0;
}

static void avalon_idle(struct cgpu_info *avalon)
{
	struct avalon_info *info = avalon_infos[avalon->device_id];
	int avalon_get_work_count = info->miner_count;
	struct avalon_task at;
	int i, ret;

	for (i = 0; i < avalon_get_work_count; i++) {
		avalon_init_task(&at, 0, 0, info->fan_pwm,
				 info->timeout, info->asic_count,
				 info->miner_count, 1, 1, info->frequency);
		ret = avalon_send_task(&at, avalon);
		if (unlikely(ret == AVA_SEND_ERROR)) {
			applog(LOG_ERR, "AVA%i: Comms error", avalon->device_id);
			return;
		}
	}
	applog(LOG_WARNING, "Avalon: Goto idle mode");
}

static void get_options(int this_option_offset, int *baud, int *miner_count,
			int *asic_count, int *timeout, int *frequency)
{
	char err_buf[BUFSIZ+1];
	char buf[BUFSIZ+1];
	char *ptr, *comma, *colon, *colon2, *colon3, *colon4;
	size_t max;
	int i, tmp;

	if (opt_avalon_options == NULL)
		buf[0] = '\0';
	else {
		ptr = opt_avalon_options;
		for (i = 0; i < this_option_offset; i++) {
			comma = strchr(ptr, ',');
			if (comma == NULL)
				break;
			ptr = comma + 1;
		}

		comma = strchr(ptr, ',');
		if (comma == NULL)
			max = strlen(ptr);
		else
			max = comma - ptr;

		if (max > BUFSIZ)
			max = BUFSIZ;
		strncpy(buf, ptr, max);
		buf[max] = '\0';
	}

	*baud = AVALON_IO_SPEED;
	*miner_count = AVALON_DEFAULT_MINER_NUM - 8;
	*asic_count = AVALON_DEFAULT_ASIC_NUM;
	*timeout = AVALON_DEFAULT_TIMEOUT;
	*frequency = AVALON_DEFAULT_FREQUENCY;

	if (!(*buf))
		return;

	colon = strchr(buf, ':');
	if (colon)
		*(colon++) = '\0';

	tmp = atoi(buf);
	switch (tmp) {
	case 115200:
		*baud = 115200;
		break;
	case 57600:
		*baud = 57600;
		break;
	case 38400:
		*baud = 38400;
		break;
	case 19200:
		*baud = 19200;
		break;
	default:
		sprintf(err_buf,
			"Invalid avalon-options for baud (%s) "
			"must be 115200, 57600, 38400 or 19200", buf);
		quit(1, err_buf);
	}

	if (colon && *colon) {
		colon2 = strchr(colon, ':');
		if (colon2)
			*(colon2++) = '\0';

		if (*colon) {
			tmp = atoi(colon);
			if (tmp > 0 && tmp <= AVALON_DEFAULT_MINER_NUM) {
				*miner_count = tmp;
			} else {
				sprintf(err_buf,
					"Invalid avalon-options for "
					"miner_count (%s) must be 1 ~ %d",
					colon, AVALON_DEFAULT_MINER_NUM);
				quit(1, err_buf);
			}
		}

		if (colon2 && *colon2) {
			colon3 = strchr(colon2, ':');
			if (colon3)
				*(colon3++) = '\0';

			tmp = atoi(colon2);
			if (tmp > 0 && tmp <= AVALON_DEFAULT_ASIC_NUM)
				*asic_count = tmp;
			else {
				sprintf(err_buf,
					"Invalid avalon-options for "
					"asic_count (%s) must be 1 ~ %d",
					colon2, AVALON_DEFAULT_ASIC_NUM);
				quit(1, err_buf);
			}

			if (colon3 && *colon3) {
				colon4 = strchr(colon3, ':');
				if (colon4)
					*(colon4++) = '\0';

				tmp = atoi(colon3);
				if (tmp > 0 && tmp <= 0xff)
					*timeout = tmp;
				else {
					sprintf(err_buf,
						"Invalid avalon-options for "
						"timeout (%s) must be 1 ~ %d",
						colon3, 0xff);
					quit(1, err_buf);
				}
				if (colon4 && *colon4) {
					tmp = atoi(colon4);
					switch (tmp) {
					case 256:
					case 270:
					case 282:
					case 300:
						*frequency = tmp;
						break;
					default:
						sprintf(err_buf,
							"Invalid avalon-options for "
							"frequency must be 256/270/282/300");
							quit(1, err_buf);
					}
				}
			}
		}
	}
}

static void avalon_initialise(struct cgpu_info *avalon)
{
	int err, interface;

	if (avalon->usbinfo.nodev)
		return;

	interface = avalon->usbdev->found->interface;
	// Reset
	err = usb_transfer(avalon, FTDI_TYPE_OUT, FTDI_REQUEST_RESET,
				FTDI_VALUE_RESET, interface, C_RESET);

	applog(LOG_DEBUG, "%s%i: reset got err %d",
		avalon->drv->name, avalon->device_id, err);

	if (avalon->usbinfo.nodev)
		return;

	// Set data
	err = usb_transfer(avalon, FTDI_TYPE_OUT, FTDI_REQUEST_DATA,
				FTDIR_VALUE_DATA, interface, C_SETDATA);

	applog(LOG_DEBUG, "%s%i: data got err %d",
		avalon->drv->name, avalon->device_id, err);

	if (avalon->usbinfo.nodev)
		return;

	// Set the baud
	err = usb_transfer(avalon, FTDI_TYPE_OUT, FTDI_REQUEST_BAUD, FTDIR_VALUE_BAUD,
				(FTDIR_INDEX_BAUD & 0xff00) | interface,
				C_SETBAUD);

	applog(LOG_DEBUG, "%s%i: setbaud got err %d",
		avalon->drv->name, avalon->device_id, err);

	if (avalon->usbinfo.nodev)
		return;

	// Set Modem Control
	err = usb_transfer(avalon, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl got err %d",
		avalon->drv->name, avalon->device_id, err);

	if (avalon->usbinfo.nodev)
		return;

	// Set Flow Control
	err = usb_transfer(avalon, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl got err %d",
		avalon->drv->name, avalon->device_id, err);

	if (avalon->usbinfo.nodev)
		return;

	avalon_clear_readbuf(avalon);
}

static bool avalon_detect_one(libusb_device *dev, struct usb_find_devices *found)
{
	int baud, miner_count, asic_count, timeout, frequency = 0;
	struct cgpu_info *avalon;
	char devpath[20];
	int this_option_offset = ++option_offset;
	struct avalon_info *info;
	int ret;

	avalon = calloc(1, sizeof(struct cgpu_info));
	if (unlikely(!avalon))
		quit(1, "Failed to calloc avalon in avalon_detect_one");;
	avalon->drv = &avalon_drv;
	avalon->threads = AVALON_MINER_THREADS;

	get_options(this_option_offset, &baud, &miner_count, &asic_count,
		    &timeout, &frequency);

	if (!usb_init(avalon, dev, found))
		return false;

	/* We have a real Avalon! */
	sprintf(devpath, "%d:%d",
			(int)(avalon->usbinfo.bus_number),
			(int)(avalon->usbinfo.device_address));

	avalon_initialise(avalon);

	applog(LOG_DEBUG, "Avalon Detected: %s "
	       "(miner_count=%d asic_count=%d timeout=%d frequency=%d)",
	       devpath, miner_count, asic_count, timeout, frequency);

	avalon->device_path = strdup(devpath);
	add_cgpu(avalon);

	avalon_infos = realloc(avalon_infos,
			       sizeof(struct avalon_info *) *
			       (total_devices + 1));
	if (unlikely(!avalon_infos))
		quit(1, "Failed to malloc avalon_infos");

	avalon_infos[avalon->device_id] = calloc(sizeof(struct avalon_info), 1);
	if (unlikely(!(avalon_infos[avalon->device_id])))
		quit(1, "Failed to malloc avalon_infos device");
	info = avalon_infos[avalon->device_id];

	info->baud = baud;
	info->miner_count = miner_count;
	info->asic_count = asic_count;
	info->timeout = timeout;

	info->fan_pwm = AVALON_DEFAULT_FAN_MIN_PWM;
	info->temp_max = 0;
	/* This is for check the temp/fan every 3~4s */
	info->temp_history_count = (4 / (float)((float)info->timeout * ((float)1.67/0x32))) + 1;
	if (info->temp_history_count <= 0)
		info->temp_history_count = 1;

	info->temp_history_index = 0;
	info->temp_sum = 0;
	info->temp_old = 0;
	info->frequency = frequency;

	ret = avalon_reset(avalon);
	if (ret) {
		/* FIXME:
		 * avalon_close(fd);
		 * return false; */
	}

	return true;
}

static void avalon_detect(void)
{
	usb_detect(&avalon_drv, avalon_detect_one);
}

static void avalon_init(struct cgpu_info *avalon)
{
	applog(LOG_INFO, "Avalon: Opened on %s", avalon->device_path);
	avalon_clear_readbuf(avalon);
	avalon_idle(avalon);
	avalon_clear_readbuf(avalon);
}

static void avalon_reinit(struct cgpu_info *avalon)
{
	avalon_initialise(avalon);
	avalon_reset(avalon);
}

#define FTDI_RS0_CTS    (1 << 4)

static void *avalon_get_results(void *userdata)
{
	struct cgpu_info *avalon = (struct cgpu_info *)userdata;
	struct avalon_info *info = avalon_infos[avalon->device_id];
	struct cg_usb_device *usbdev = avalon->usbdev;
	const int rsize = 512;

	/* This lock prevents the reads from starting till avalon_prepare
	 * releses it */
	mutex_lock(&info->read_mutex);
	info->offset = 0;
	mutex_unlock(&info->read_mutex);

	while (42) {
		int amount, err;
		unsigned char buf[rsize];

		if (unlikely(info->offset + rsize >= AVALON_READBUF_SIZE)) {
			applog(LOG_ERR, "Avalon readbuf overflow, resetting buffer");
			mutex_lock(&info->read_mutex);
			info->offset = 0;
			mutex_unlock(&info->read_mutex);
		}

		err = libusb_bulk_transfer(usbdev->handle,
					   usbdev->found->eps[C_AVALON_READ].ep,
					   buf, 512, &amount, AVALON_READ_TIMEOUT);
		if (err) {
			applog(LOG_DEBUG, "%s%i: Get avalon read got err %d",
			       avalon->drv->name, avalon->device_id, err);
			nmsleep(AVALON_READ_TIMEOUT);
			continue;
		}

		/* Set out of lock but it's a simple bool */
		info->buffer_full = !(buf[0] & FTDI_RS0_CTS);
		amount -= 2;
		if (amount < 1) {
			nmsleep(AVALON_READ_TIMEOUT);
			continue;
		}

		mutex_lock(&info->read_mutex);
		memcpy(&info->readbuf[info->offset], &buf[2], amount);
		info->offset += amount;
		if (info->offset >= AVALON_READ_SIZE)
			pthread_cond_signal(&info->read_cond);
		mutex_unlock(&info->read_mutex);
	}
	return NULL;
}

static bool avalon_prepare(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct avalon_info *info = avalon_infos[avalon->device_id];
	struct timeval now;

	free(avalon->works);
	avalon->works = calloc(info->miner_count * sizeof(struct work *),
			       AVALON_ARRAY_SIZE);
	if (!avalon->works)
		quit(1, "Failed to calloc avalon works in avalon_prepare");

	mutex_init(&info->read_mutex);
	mutex_lock(&info->read_mutex);
	if (unlikely(pthread_cond_init(&info->read_cond, NULL)))
		quit(1, "Failed to pthread_cond_init avalon read_cond");

	if (pthread_create(&info->read_thr, NULL, avalon_get_results, (void *)avalon))
		quit(1, "Failed to create avalon read_thr");

	avalon_init(avalon);
	mutex_unlock(&info->read_mutex);

	cgtime(&now);
	get_datestamp(avalon->init, &now);
	return true;
}

static void avalon_free_work(struct thr_info *thr)
{
	struct cgpu_info *avalon;
	struct avalon_info *info;
	struct work **works;
	int i;

	avalon = thr->cgpu;
	avalon->queued = 0;
	if (unlikely(!avalon->works))
		return;
	works = avalon->works;
	info = avalon_infos[avalon->device_id];

	for (i = 0; i < info->miner_count * 4; i++) {
		if (works[i]) {
			work_completed(avalon, works[i]);
			works[i] = NULL;
		}
	}
}

static void do_avalon_close(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct avalon_info *info = avalon_infos[avalon->device_id];

	avalon_free_work(thr);
	sleep(1);
	avalon_reset(avalon);
	avalon_idle(avalon);
	//avalon_close(avalon->device_fd);

	info->no_matching_work = 0;
}

static inline void record_temp_fan(struct avalon_info *info, struct avalon_result *ar, float *temp_avg)
{
	info->fan0 = ar->fan0 * AVALON_FAN_FACTOR;
	info->fan1 = ar->fan1 * AVALON_FAN_FACTOR;
	info->fan2 = ar->fan2 * AVALON_FAN_FACTOR;

	info->temp0 = ar->temp0;
	info->temp1 = ar->temp1;
	info->temp2 = ar->temp2;
	if (ar->temp0 & 0x80) {
		ar->temp0 &= 0x7f;
		info->temp0 = 0 - ((~ar->temp0 & 0x7f) + 1);
	}
	if (ar->temp1 & 0x80) {
		ar->temp1 &= 0x7f;
		info->temp1 = 0 - ((~ar->temp1 & 0x7f) + 1);
	}
	if (ar->temp2 & 0x80) {
		ar->temp2 &= 0x7f;
		info->temp2 = 0 - ((~ar->temp2 & 0x7f) + 1);
	}

	*temp_avg = info->temp2 > info->temp1 ? info->temp2 : info->temp1;

	if (info->temp0 > info->temp_max)
		info->temp_max = info->temp0;
	if (info->temp1 > info->temp_max)
		info->temp_max = info->temp1;
	if (info->temp2 > info->temp_max)
		info->temp_max = info->temp2;
}

static inline void adjust_fan(struct avalon_info *info)
{
	int temp_new;

	temp_new = info->temp_sum / info->temp_history_count;

	if (temp_new < 35) {
		info->fan_pwm = AVALON_DEFAULT_FAN_MIN_PWM;
		info->temp_old = temp_new;
	} else if (temp_new > 55) {
		info->fan_pwm = AVALON_DEFAULT_FAN_MAX_PWM;
		info->temp_old = temp_new;
	} else if (abs(temp_new - info->temp_old) >= 2) {
		info->fan_pwm = AVALON_DEFAULT_FAN_MIN_PWM + (temp_new - 35) * 6.4;
		info->temp_old = temp_new;
	}
}

/* We use a replacement algorithm to only remove references to work done from
 * the buffer when we need the extra space for new work. */
static bool avalon_fill(struct cgpu_info *avalon)
{
	int subid, slot, mc = avalon_infos[avalon->device_id]->miner_count;
	struct work *work;

	if (avalon->queued >= mc)
		return true;
	work = get_queued(avalon);
	if (unlikely(!work))
		return false;
	subid = avalon->queued++;
	work->subid = subid;
	slot = avalon->work_array * mc + subid;
	if (likely(avalon->works[slot]))
		work_completed(avalon, avalon->works[slot]);
	avalon->works[slot] = work;
	if (avalon->queued >= mc)
		return true;
	return false;
}

static void avalon_rotate_array(struct cgpu_info *avalon)
{
	avalon->queued = 0;
	if (++avalon->work_array >= AVALON_ARRAY_SIZE)
		avalon->work_array = 0;
}

static int64_t avalon_scanhash(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct work **works;
	int ret = AVA_GETS_OK;

	struct avalon_info *info;
	struct avalon_task at;
	struct avalon_result ar;
	int i;
	int avalon_get_work_count;
	int start_count, end_count;

	struct timeval tv_start, tv_finish, elapsed;
	uint32_t nonce;
	int64_t hash_count;
	int result_wrong, max_ms;
	bool full = avalon_buffer_full(avalon);

	works = avalon->works;
	info = avalon_infos[avalon->device_id];
	avalon_get_work_count = info->miner_count;
	/* Do not try to read to the max nonce range or we may overshoot */
	max_ms = 400000 / info->frequency;

	start_count = avalon->work_array * avalon_get_work_count;
	end_count = start_count + avalon_get_work_count;
	for (i = start_count; i < end_count; i++) {
		if (full)
			break;

		avalon_init_task(&at, 0, 0, info->fan_pwm,
				 info->timeout, info->asic_count,
				 info->miner_count, 1, 0, info->frequency);
		avalon_create_task(&at, works[i]);
		ret = avalon_send_task(&at, avalon);
		if (unlikely(ret == AVA_SEND_ERROR)) {
			applog(LOG_ERR, "AVA%i: Comms error(buffer)",
			       avalon->device_id);
#if 0
			do_avalon_close(thr);
			dev_error(avalon, REASON_DEV_COMMS_ERROR);
			sleep(1);
			avalon_init(avalon);
#endif
			return 0;	/* This should never happen */
		}

		works[i]->blk.nonce = 0xffffffff;
		full = avalon_buffer_full(avalon);
	}

	if (!full) {
		applog(LOG_DEBUG, "AVA%i: One set of submits without full buffer",
		       avalon->device_id);
		avalon_rotate_array(avalon);
		return 0;
	}

	elapsed.tv_sec = elapsed.tv_usec = 0;
	cgtime(&tv_start);

	result_wrong = 0;
	hash_count = 0;
	while (true) {
		bool decoded;

		if (unlikely(!avalon_buffer_full(avalon)))
			break;
		
		ret = avalon_get_result(avalon, &ar, &max_ms);

		cgtime(&tv_finish);
		if (unlikely(ret == AVA_GETS_ERROR)) {
			applog(LOG_ERR,
			       "AVA%i: Comms error(read)", avalon->device_id);
			//dev_error(avalon, REASON_DEV_COMMS_ERROR);
			return 0;
		}

		decoded = avalon_decode_nonce(thr, &ar, &nonce);
		if (decoded)
			hash_count += 0xffffffff;

		if (unlikely(ret == AVA_GETS_RESTART))
			break;
		if (ret == AVA_GETS_TIMEOUT || max_ms <= 0) {
			timersub(&tv_finish, &tv_start, &elapsed);
			applog(LOG_DEBUG,
			       "Avalon: 0x%08llx hashes (%ld.%06lds)",
			       (unsigned long long)hash_count,
			       elapsed.tv_sec, elapsed.tv_usec);
			applog(LOG_DEBUG, "Avalon: Not looking for more nonces");
			break;
		}

		if (!decoded) {
			info->no_matching_work++;
			result_wrong++;

			if (unlikely(result_wrong >= avalon_get_work_count))
				break;

			if (opt_debug) {
				timersub(&tv_finish, &tv_start, &elapsed);
				applog(LOG_DEBUG,"Avalon: no matching work: %d"
				" (%ld.%06lds)", info->no_matching_work,
				elapsed.tv_sec, elapsed.tv_usec);
			}
			continue;
		}

		if (opt_debug) {
			timersub(&tv_finish, &tv_start, &elapsed);
			applog(LOG_DEBUG,
			       "Avalon: nonce = 0x%08x = 0x%08llx hashes "
			       "(%ld.%06lds)", nonce, (unsigned long long)hash_count,
			       elapsed.tv_sec, elapsed.tv_usec);
		}
	}
	if (hash_count && avalon->results < AVALON_ARRAY_SIZE)
		avalon->results++;
	if (unlikely((result_wrong >= avalon_get_work_count) ||
	    (!hash_count && ret != AVA_GETS_RESTART && --avalon->results < 0))) {
		applog(LOG_ERR,
			"AVA%i: FPGA controller messed up, %d wrong results",
			avalon->device_id, result_wrong);
#if 0
		/* Look for all invalid results, or consecutive failure
		 * to generate any results suggesting the FPGA
		 * controller has screwed up. */
		do_avalon_close(thr);
		dev_error(avalon, REASON_DEV_COMMS_ERROR);
		sleep(1);
		avalon_init(avalon);
		return 0;
#endif
	}

	avalon_rotate_array(avalon);

	if (hash_count) {
		record_temp_fan(info, &ar, &(avalon->temp));
		applog(LOG_INFO,
		       "Avalon: Fan1: %d/m, Fan2: %d/m, Fan3: %d/m\t"
		       "Temp1: %dC, Temp2: %dC, Temp3: %dC, TempMAX: %dC",
		       info->fan0, info->fan1, info->fan2,
		       info->temp0, info->temp1, info->temp2, info->temp_max);
		info->temp_history_index++;
		info->temp_sum += avalon->temp;
		applog(LOG_DEBUG, "Avalon: temp_index: %d, temp_count: %d, temp_old: %d",
		       info->temp_history_index, info->temp_history_count, info->temp_old);
		if (info->temp_history_index == info->temp_history_count) {
			adjust_fan(info);
			info->temp_history_index = 0;
			info->temp_sum = 0;
		}
	}

	/* This hashmeter is just a utility counter based on returned shares */
	return hash_count;
}

static struct api_data *avalon_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct avalon_info *info = avalon_infos[cgpu->device_id];
	int i;

	root = api_add_int(root, "baud", &(info->baud), false);
	root = api_add_int(root, "miner_count", &(info->miner_count),false);
	root = api_add_int(root, "asic_count", &(info->asic_count), false);
	root = api_add_int(root, "timeout", &(info->timeout), false);
	root = api_add_int(root, "frequency", &(info->frequency), false);

	root = api_add_int(root, "fan1", &(info->fan0), false);
	root = api_add_int(root, "fan2", &(info->fan1), false);
	root = api_add_int(root, "fan3", &(info->fan2), false);

	root = api_add_int(root, "temp1", &(info->temp0), false);
	root = api_add_int(root, "temp2", &(info->temp1), false);
	root = api_add_int(root, "temp3", &(info->temp2), false);
	root = api_add_int(root, "temp_max", &(info->temp_max), false);

	root = api_add_int(root, "no_matching_work", &(info->no_matching_work), false);
	for (i = 0; i < info->miner_count; i++) {
		char mcw[24];

		sprintf(mcw, "match_work_count%d", i + 1);
		root = api_add_int(root, mcw, &(info->matching_work[i]), false);
	}

	return root;
}

static void avalon_shutdown(struct thr_info *thr)
{
	do_avalon_close(thr);
}

struct device_drv avalon_drv = {
	.drv_id = DRIVER_AVALON,
	.dname = "avalon",
	.name = "AVA",
	.drv_detect = avalon_detect,
	.thread_prepare = avalon_prepare,
	.hash_work = hash_queued_work,
	.queue_full = avalon_fill,
	.scanwork = avalon_scanhash,
	.get_api_stats = avalon_api_stats,
	.reinit_device = avalon_reinit,
	.thread_shutdown = avalon_shutdown,
};
