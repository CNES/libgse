/****************************************************************************/
/**
 *   @file          encap.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION CONTEXT
 *
 *   @brief         GSE encapsulation public functions definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_ENCAP_H
#define GSE_ENCAP_H

#include <stdint.h>

#include "virtual_buffer.h"

struct gse_encap_s;
typedef struct gse_encap_s gse_encap_t;


/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/* Encapsulation initialization and release functions */

/**
 *  @brief   Initialize the encapsulation structure
 *
 *  The function return the encapsulation structure which is a fifo table
 *
 *  @param   qos_nbr        number of qos values
 *  @param   fifo_size      size of FIFOs
 *  @param   encap          OUT: Encapsulation structure
 *                          (table of FIFOs associated to a QoS value)
 *  @return  status code
 */
status_t gse_encap_init(uint8_t qos_nbr, size_t fifo_size,
                        gse_encap_t **encap);

/**
 *  @brief   Release the encapsulation structure
 *
 *  @param   encap   Encapsulation structure
 *  @return  status code
 */
status_t gse_encap_release(gse_encap_t *encap);

/**
 *  @brief   Set the offset applied on each GSE packet (for usage with copy only)
 *
 *  @param   encap         Encapsulation structure
 *  @param   head_offset   Offset applied on the beginning of each GSE packet
 *  @param   trail_offset  Offset applied on the end of each GSE packet
 *  @return  status code
 */
status_t gse_encap_set_offsets(gse_encap_t *encap,
                               size_t head_offset, size_t trail_offset);

/* Encapsulation functions */

/**
 *  @brief   Receive a PDU which is stored in a virtual buffer
 *
 *  @param   pdu            The PDU to encapsulate
 *  @param   encap          The encapsulation context structure
 *  @param   label          The packet label
 *  @param   label_type     The label type field value
 *                          only '00' is implemented
 *  @param   protocol       The PDU protocol
 *  @param   qos            The QoS value of the PDU
 *  @return  status code
 */
status_t gse_encap_receive_pdu(vfrag_t *pdu, gse_encap_t *encap,
                               uint8_t label[6], uint8_t label_type,
                               uint16_t protocol, uint8_t qos);

/**
 *  @brief   Get a packet from the encapsulation context structure
 *
 *  @param   packet        OUT: The GSE packet
 *  @param   encap         The encapsulation context structure
 *  @param   length        Desired length for the packet
 *  @param   qos           QoS of the packet
 *  @return  status code
 */
status_t gse_encap_get_packet(vfrag_t **packet, gse_encap_t *encap,
                              size_t length, uint8_t qos);

/**
 *  @brief   Get a packet from the encapsulation context structure
 *
 *  This function does not use zero copy strategy
 *
 *  @param   packet        OUT: The GSE packet
 *  @param   encap         The encapsulation context structure related
 *  @param   length        Desired length for the packet
 *  @param   qos           QoS of the packet
 *  @return  status code
 */
status_t gse_encap_get_packet_copy(vfrag_t **packet, gse_encap_t *encap,
                                   size_t length, uint8_t qos);

#endif
