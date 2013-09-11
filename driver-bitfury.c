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

int submit_work(struct bitfury_work *w, struct thr_info *thr);

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
			devices[i].osc6_bits = 54;
		}
		set_chip_opts(devices, chip_n);
		for (i = 0; i < chip_n; i++) {
			send_reinit(devices[i].slot, devices[i].fasync, devices[i].osc6_bits);
		}
	}
	first = 1;

	for (chip = 0; chip < chip_n; chip++) {
		devices[chip].job_switched = 0;
		if(!devices[chip].bfwork.work) {
			devices[chip].bfwork.work = get_queued(thr->cgpu);
			if (devices[chip].bfwork.work == NULL) {
				return 0;
			}
			work_to_payload(&(devices[chip].bfwork.payload), devices[chip].bfwork.work);
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
			int i=0;
			struct work *work = devices[chip].bfwork.work;
			struct work *owork = devices[chip].obfwork.work;
			struct work *o2work = devices[chip].o2bfwork.work;

			if (owork)
				i+=submit_work(&devices[chip].obfwork, thr);
			if (o2work)
				i+=submit_work(&devices[chip].o2bfwork, thr);
			if (work)
				i+=submit_work(&devices[chip].bfwork, thr);	


			high = high > i?high:i;
			total+=i;

			devices[chip].job_switched = 0;

			if (o2work)
				work_completed(thr->cgpu, o2work);

			//printf("%d %d %d\n",devices[chip].o2bfwork.results_n,devices[chip].obfwork.results_n,devices[chip].bfwork.results_n);
			
			memcpy (&(devices[chip].o2bfwork),&(devices[chip].obfwork),sizeof(struct bitfury_work));
			memcpy (&(devices[chip].obfwork),&(devices[chip].bfwork),sizeof(struct bitfury_work));
			devices[chip].bfwork.work = NULL;
			devices[chip].bfwork.results_n = 0;
			devices[chip].bfwork.results_sent = 0;
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
	cgsleep_ms(200);
	return hashes;
}

void set_chip_opts(struct bitfury_device *devices, int chip_n)
{
	if (opt_bitfury_options == NULL)
		return;
	int chip, speed, i=0;
	char *comma;
	char *s = opt_bitfury_options;
	if(sscanf(s,"ALL:%d",&speed))
	{
		for(i=0; i < chip_n ; i++)
		{
			devices[i].osc6_bits = speed;
		}
		comma = strchr(s,',');
		if(comma != NULL)
		{
			s=comma+1;
		} else
		{
			return;
		}
	}
	
	comma = strchr(s,',');
	while (comma != NULL)
	{
		if(sscanf(s,"%d:%d",&chip,&speed) < 2)
			return;
		s=comma+1;
		comma = strchr(s,',');
		devices[chip].osc6_bits = speed;
	}

	if(sscanf(s,"%d:%d",&chip,&speed) < 2)
		return;
	devices[chip].osc6_bits = speed;
}

int submit_work(struct bitfury_work *w, struct thr_info *thr)
{
	int i=0,j;
	int *res = w->results;
	for (j = w->results_sent; j < w->results_n;j++) {
		submit_nonce(thr, w->work, bswap_32(res[j]));
		w->results_sent++;
		i++;
	}
	return i;
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
	get_datestamp(cgpu->init, sizeof(cgpu->init), &now);

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

