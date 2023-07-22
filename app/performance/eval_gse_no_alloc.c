/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2013 TAS
 *
 *
 * This file is part of the GSE library.
 *
 *
 * The GSE library is free software : you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/**
 * @file     eval_gse_no_alloc.c
 * @author   Audric Schiltknecht / Viveris Technologies
 * @date     01 mars 2013
 * @version  1.0
 * @brief    Evaluate libgse encapsulation performance
 */

#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "constants.h"
#include "encap.h"
#include "virtual_fragment.h"
#include "header_fields.h"

#define MIN(x, y)  (((x) < (y)) ? (x) : (y))

#define IP_PAYLOAD_LENGTH 40

#define BBFRAME_LENGTH 2001

#define NB_ITER 1E6

#define QOS_NR 1
#define FIFO_SIZE 1

#define PROTOCOL_TYPE 0x0800
#define QOS_VALUE 0

#define GSE_MIN_PACKET_LENGTH 12
#define GSE_MAX_PACKET_LENGTH (4095 + 2)

unsigned char ip_payload[IP_PAYLOAD_LENGTH];
unsigned char bbframe[BBFRAME_LENGTH];

unsigned char buffer[IP_PAYLOAD_LENGTH + GSE_MAX_HEADER_LENGTH + GSE_MAX_TRAILER_LENGTH];

uint8_t label[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static double
_unix_time(void)
{
	struct timeval timev;

	gettimeofday(&timev, NULL);
	return (double)timev.tv_sec + (((double)timev.tv_usec) / 1000000);
}

int main(void)
{
	gse_encap_t *encap_context;
	gse_vfrag_t *in_vfrag, *out_vfrag;
	gse_status_t status;
	int is_failure = 1;

	int size;
	size_t vfrag_length;
	unsigned char *gse_packet;
	int nb_fragment = 0;

	long long iter;

	uint8_t end_indicator;
	bool is_end;

	double clock_start, total_tics;

	// Defining payload
	memset(ip_payload, 0x42, IP_PAYLOAD_LENGTH);

	// Initialize encap context
	status = gse_encap_init(QOS_NR, FIFO_SIZE, &encap_context);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to initialize encapsulation library: %s\n",
		        gse_get_status(status));
		goto error;
	}

	// Initialize input vfrag
	status = gse_allocate_vfrag(&in_vfrag, 1);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to create input vfrag: %s\n",
				gse_get_status(status));
		goto free_context;
	}

	// Initialize output vfrag
	status = gse_allocate_vfrag(&out_vfrag, 0);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to create output vfrag: %s\n",
				gse_get_status(status));
		goto free_in_vfrag;
	}

	/* sync disk to avoid io during test */
	sync();
	sync();
	sync();

	/* warm up the cpu with some spinning */
	size = time(NULL);
	for (;;) {
		if ((time(NULL) - size) > 2) break;
	}

	size = BBFRAME_LENGTH;

	clock_start = _unix_time();
	for (iter = 0 ; iter < NB_ITER ; ++iter)
	{
		//printf("Iter #%d\n", iter);
		// Initialize input buffer for vfrag
		bzero(buffer, IP_PAYLOAD_LENGTH + GSE_MAX_HEADER_LENGTH + GSE_MAX_TRAILER_LENGTH);
		memcpy(buffer + GSE_MAX_HEADER_LENGTH, ip_payload, IP_PAYLOAD_LENGTH);


		// Feed IP payload to GSE compressor
		status = gse_affect_buf_vfrag(in_vfrag, buffer, GSE_MAX_HEADER_LENGTH, GSE_MAX_TRAILER_LENGTH, IP_PAYLOAD_LENGTH);
		if (status != GSE_STATUS_OK)
		{
			fprintf(stderr, "Fail to copy data into input vfrag: %s\n",
			        gse_get_status(status));
			// in_vfrag is automatically freed in case of error
			goto free_out_vfrag;
		}

		// Put PDU into encap context
		// One copy: label value
		status = gse_encap_receive_pdu(in_vfrag, encap_context, label,
		                               GSE_LT_NO_LABEL, PROTOCOL_TYPE, QOS_VALUE);
		if (status != GSE_STATUS_OK)
		{
			fprintf(stderr, "Fail to receive PDU: %s\n",
			        gse_get_status(status));
			// in_vfrag is automatically freed in case of error
			goto free_out_vfrag;
		}

		// Fill BBFrames until no more encapsulated PDU
		do
		{
			// Get GSE packet
			status = gse_encap_get_packet_no_alloc(&out_vfrag, encap_context, MIN(size, GSE_MAX_PACKET_LENGTH), QOS_VALUE);
			if (status != GSE_STATUS_OK)
			{
				fprintf(stderr, "Fail to retrieve GSE packet: %s\n",
				        gse_get_status(status));
				goto free_out_vfrag;
			}

			vfrag_length = gse_get_vfrag_length(out_vfrag);

			// Get pointer on packet start
			gse_packet = gse_get_vfrag_start(out_vfrag);

			// One copy here
			memcpy(bbframe + BBFRAME_LENGTH - size, gse_packet, vfrag_length);

			size -= vfrag_length;
			if (size <= GSE_MIN_PACKET_LENGTH)
				// BBFrame full, start new one
				size = BBFRAME_LENGTH;

			// Test if packet contains 'E' bit
			status = gse_get_end_indicator(gse_packet, &end_indicator);
			if (status != GSE_STATUS_OK)
			{
				fprintf(stderr, "Fail to retrieve GSE end indicator: %s\n",
				        gse_get_status(status));
				goto free_out_vfrag;
			}

			// Is packet complete, or is it first fragment ?
			// (nb: only at most 2 fragments per packet)
			is_end = ((end_indicator & 0x01) == 0x01);
			if (!is_end)
				nb_fragment++;

			// Free vfrag before next call to gse_encap_get_packet() per
			// libgse requirement
			gse_free_vfrag_no_alloc(&out_vfrag, 1, 0);

		} while (is_end != true);
	}
	total_tics = _unix_time() - clock_start;

	printf("NB iter: %e\n", NB_ITER);
	printf("Nb fragment: %d\n", nb_fragment);
	printf("Tics: %e seconds\n", total_tics);
	printf("Tics / loop: %e seconds\n", (total_tics / NB_ITER));
	printf("PPS %.8f\n", (double)NB_ITER / total_tics);

	/* everything went fine */
	is_failure = 0;

free_out_vfrag:
	status = gse_free_vfrag_no_alloc(&out_vfrag, 0, 1);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to free out_vfrag: %s\n",
		        gse_get_status(status));
	}
free_in_vfrag:
	status = gse_free_vfrag_no_alloc(&in_vfrag, 0, 0);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to free in_vfrag: %s\n",
		        gse_get_status(status));
	}
free_context:
	// Release context
	gse_encap_release(encap_context);
error:
	return is_failure;
}
