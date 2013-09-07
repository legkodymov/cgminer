/*
 * device-bitfury.c - device functions for Bitfury chip/board library
 *
 * Copyright (c) 2013 bitfury
 * Copyright (c) 2013 legkodymov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
*/

#include "miner.h"
#include <unistd.h>
#include <sha2.h>
#include "libbitfury.h"
#include "util.h"

#define GOLDEN_BACKLOG 5

struct device_drv bitfury_drv;

// Forward declarations
static void bitfury_disable(struct thr_info* thr);
static bool bitfury_prepare(struct thr_info *thr);
int calc_stat(time_t * stat_ts, time_t stat, struct timeval now);
double shares_to_ghashes(int shares, int seconds);

static void bitfury_detect(void)
{
	int chip_n;
	int i;
	struct cgpu_info *bitfury_info;

	bitfury_info = calloc(1, sizeof(struct cgpu_info));
	bitfury_info->drv = &bitfury_drv;
	bitfury_info->threads = 1;

	applog(LOG_INFO, "INFO: bitfury_detect");
	chip_n = libbitfury_detectChips(bitfury_info->devices);
	if (!chip_n) {
		applog(LOG_WARNING, "No Bitfury chips detected!");
		return;
	} else {
		applog(LOG_WARNING, "BITFURY: %d chips detected!", chip_n);
	}

	bitfury_info->chip_n = chip_n;
	add_cgpu(bitfury_info);
}

static uint32_t bitfury_checkNonce(struct work *work, uint32_t nonce)
{
	applog(LOG_INFO, "INFO: bitfury_checkNonce");
}

static int64_t bitfury_scanHash(struct thr_info *thr)
{
	static struct bitfury_device *devices; // TODO Move somewhere to appropriate place
	int chip_n;
	int chip;
	uint64_t hashes = 0;
	unsigned char line[2048];
	
	char stat_lines[32][256] = {0};
	
	static first = 0; //TODO Move to detect()
	int i;
	
	static int shift_number = 1;
	
	devices = thr->cgpu->devices;
	chip_n = thr->cgpu->chip_n;

	if (!first) {
		for (i = 0; i < chip_n; i++) {
			devices[i].osc6_bits = opt_bitfury_chip_speed;
		}
		for (i = 0; i < chip_n; i++) {
			send_reinit(devices[i].slot, devices[i].fasync, devices[i].osc6_bits);
		}
	}
	first = 1;

	for (chip = 0; chip < chip_n; chip++) {
		devices[chip].job_switched = 0;
		if(!devices[chip].work) {
			devices[chip].work = get_queued(thr->cgpu);
			if (devices[chip].work == NULL) {
				return 0;
			}
			work_to_payload(&(devices[chip].payload), devices[chip].work);
		}
	}
	
	libbitfury_sendHashData(devices, chip_n);
	

	
	chip = 0;
	int high = 0;
	double aveg = 0.0;
	int total = 0;
	int futures =0;
	for (;chip < chip_n; chip++) {
		
		if (devices[chip].job_switched) {
			int i,j;
			int *res = devices[chip].results;
			struct work *work = devices[chip].work;
			struct work *owork = devices[chip].owork;
			struct work *o2work = devices[chip].o2work;
			i = devices[chip].results_n;
			for (j = 0; j < i;j++) {
				if (owork) {
					submit_nonce(thr, owork, bswap_32(res[j]));
				}
				if (o2work) {
					// TEST
					//submit_nonce(thr, owork, bswap_32(res[j]));
				}
			}
			res = devices[chip].old_results;
			int k = devices[chip].old_results_n;
			i=i+k;
			for (j = 0; j < k; j++) {
				if (o2work) {
					submit_nonce(thr, o2work, bswap_32(res[j]));
				}
			}
			
			res = devices[chip].future_results;
			k = devices[chip].future_results_n;
			i=i+k;
			for (j = 0; j < k; j++) {
				if (work) {
					submit_nonce(thr, work, bswap_32(res[j]));
				}
			}
			high = high > i?high:i;
			total+=i;
			futures+=devices[chip].future_results_n;
			devices[chip].future_results_n = 0;
			devices[chip].old_results_n = 0;

			devices[chip].results_n = 0;
			devices[chip].job_switched = 0;

			if (o2work)
				work_completed(thr->cgpu, o2work);

			devices[chip].o2work = devices[chip].owork;
			devices[chip].owork = devices[chip].work;
			devices[chip].work = NULL;
			hashes += 0xffffffffull * i;
		}
		/*
		if(shift_number % 100 == 0)
		{
			int len = strlen(stat_lines[devices[chip].slot]);
			snprintf(stat_lines[devices[chip].slot]+len,256-len,"%d: %d/%d ",chip,devices[chip].nonces_found/devices[chip].nonce_errors);
		}
		*/
		
	}
	aveg = (double) total / chip_n;
	//applog(LOG_WARNING, "high: %d aver: %4.2f total %d futures %d", high, aveg,total,futures);
	if(shift_number % 100 == 0)
	{
		/*
		applog(LOG_WARNING,stat_lines[0]);
		applog(LOG_WARNING,stat_lines[1]);
		applog(LOG_WARNING,stat_lines[2]);
		applog(LOG_WARNING,stat_lines[3]);
		*/
	}

	
	shift_number++;
	restart_wait(100);
	return hashes;
}

double shares_to_ghashes(int shares, int seconds) {
	return (double)shares / (double)seconds * 4.84387;  //orig: 4.77628
}

int calc_stat(time_t * stat_ts, time_t stat, struct timeval now) {
	int j;
	int shares_found = 0;
	for(j = 0; j < BITFURY_STAT_N; j++) {
		if (now.tv_sec - stat_ts[j] < stat) {
			shares_found++;
		}
	}
	return shares_found;
}

static void bitfury_statline_before(char *buf, struct cgpu_info *cgpu)
{
	applog(LOG_INFO, "INFO bitfury_statline_before");
}

static bool bitfury_prepare(struct thr_info *thr)
{
	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;

	cgtime(&now);
	get_datestamp(cgpu->init, &now);

	applog(LOG_INFO, "INFO bitfury_prepare");
	return true;
}

static void bitfury_shutdown(struct thr_info *thr)
{
	int chip_n;
	int i;

	chip_n = thr->cgpu->chip_n;

	applog(LOG_INFO, "INFO bitfury_shutdown");
	libbitfury_shutdownChips(thr->cgpu->devices, chip_n);
}

static void bitfury_disable(struct thr_info *thr)
{
	applog(LOG_INFO, "INFO bitfury_disable");
}

struct device_drv bitfury_drv = {
	.drv_id = DRIVER_BITFURY,
	.dname = "bitfury",
	.name = "BITFURY",
	.drv_detect = bitfury_detect,
	.get_statline_before = bitfury_statline_before,
	.thread_prepare = bitfury_prepare,
	.scanwork = bitfury_scanHash,
	.thread_shutdown = bitfury_shutdown,
	.hash_work = hash_queued_work,
};

