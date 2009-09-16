/****************************************************************************/
/**
 *   @file          gse_refrag.h
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

#include "gse_common.h"
#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Refragment a GSE packet packet1 in 2 new GSE packets (packet[1, 2])
 *
 *  @param   packet1     The GSE packet to refragment and the first new GSE packet
 *  @param   packet2     The second new GSE packet
 *  @param   qos         The QoS associated to the wanted GSE packet
 *  @param   max_length  Maximum length of the first new GSE packet
 *
 *  @return  status code
 */
status_t gse_refrag_packet(vfrag_t *packet1, vfrag_t **packet2,
                           uint8_t qos, size_t max_length);

#endif
