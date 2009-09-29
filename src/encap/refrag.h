/****************************************************************************/
/**
 *   @file          refrag.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: REFRAGMENTATION
 *
 *   @brief         GSE reencapsulation
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_REFRAG_H
#define GSE_REFRAG_H

#include <stdint.h>

#include "virtual_buffer.h"

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Refragment a GSE packet packet1 in 2 new GSE packets (packet[1, 2])
 *
 *  @param   packet1       The GSE packet to refragment and the first new GSE packet
 *  @param   packet2       OUT: The second new GSE packet
 *  @param   head offset   The offset to apply at the beginning of the created
 *                         fragment (packet2)
 *  @param   trail offset  The offset to apply at the end of the created fragment
 *  @param   qos           The QoS associated to the wanted GSE packet
 *  @param   max_length    Maximum length of the first new GSE packet
 *
 *  @return  status code
 */
status_t gse_refrag_packet(vfrag_t *packet1, vfrag_t **packet2,
                           size_t head_offset, size_t trail_offset,
                           uint8_t qos, size_t max_length);
/* For the first new GSE packet, header offset will depend on offsets applied
 * on packet1 creation with get_packet function. */
#endif
