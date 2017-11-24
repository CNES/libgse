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
 * @file     eval_gse_trunk.c
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

uint8_t label[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

int main(void)
{
	gse_encap_t *encap_context;
	gse_vfrag_t *in_vfrag, *out_vfrag;
	gse_status_t status;

	int size;
	size_t vfrag_length;
	unsigned char *gse_packet;
	int nb_fragment = 0;

	long long iter;

	uint8_t end_indicator;
	bool is_end;

	clock_t clock_start, total_tics;

	// Zero-ing payload
	bzero(ip_payload, IP_PAYLOAD_LENGTH);

	// Initialize encap context
	status = gse_encap_init(QOS_NR, FIFO_SIZE, &encap_context);
	if (status != GSE_STATUS_OK)
	{
		fprintf(stderr, "Fail to initialize encapsulation library: %s\n",
		        gse_get_status(status));
		return 1;
	}

	size = BBFRAME_LENGTH;
	clock_start = clock();
	for (iter = 0 ; iter < NB_ITER ; ++iter)
	{
		//printf("Iter #%d\n", iter);

		// Initialize input vfrag
		// It currently cannot be done outside of the loop,
		// since there is no other way to "reset" a vfrag,
		// and calling gse_free_vfrag() release the allocated memory...
		// One vfrag-allocation here:
		//  - One for the vfrag structure
		//  - One for the vbuf structure
		//  - One for the vbuf buffer
		status = gse_create_vfrag(&in_vfrag,
								  GSE_MAX_PDU_LENGTH,
								  GSE_MAX_HEADER_LENGTH,
								  GSE_MAX_TRAILER_LENGTH);
		if (status != GSE_STATUS_OK)
		{
			fprintf(stderr, "Fail to create input vfrag: %s\n",
					gse_get_status(status));
			return 1;
		}

		// Feed IP payload to GSE compressor
		// One copy here
		status = gse_copy_data(in_vfrag, ip_payload, IP_PAYLOAD_LENGTH);
		if (status != GSE_STATUS_OK)
		{
			fprintf(stderr, "Fail to copy data into input vfrag: %s\n",
			        gse_get_status(status));
			// in_vfrag is automatically freed in case of error
			goto free_context;
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
			goto free_context;
		}

		// Fill BBFrames until no more encapsulated PDU
		do
		{
			// Get GSE packet
			// One allocation here (out_vfrag)
			// One copy (for extensions, even if there is none (memcpy(size=0))
			// One free here (in_vfrag if PDU is complete)
			status = gse_encap_get_packet(&out_vfrag, encap_context, MIN(size, GSE_MAX_PACKET_LENGTH), QOS_VALUE);
			if (status != GSE_STATUS_OK)
			{
				fprintf(stderr, "Fail to retrieve GSE packet: %s\n",
				        gse_get_status(status));
				goto free_context;
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
				goto free_context;
			}

			// Is packet complete, or is it first fragment ?
			// (nb: only at most 2 fragments per packet)
			is_end = ((end_indicator & 0x01) == 0x01);
			if (!is_end)
				nb_fragment++;

			// Free vfrag before next call to gse_encap_get_packet() per
			// libgse requirement
			// One free here if packet is not fragmented
			gse_free_vfrag(&out_vfrag);

		} while (is_end != true);
	}
	total_tics = clock() - clock_start;

	printf("NB iter: %e\n", NB_ITER);
	printf("Nb fragment: %d\n", nb_fragment);
	printf("Tics: %d - %e seconds\n", (int)total_tics, ((double)total_tics) / CLOCKS_PER_SEC);
	printf("Tics / loop: %f - %e seconds\n", ((double)total_tics / NB_ITER), (((double)total_tics)/NB_ITER)/CLOCKS_PER_SEC);

free_context:
	// Release context
	gse_encap_release(encap_context);

	return status;
}
