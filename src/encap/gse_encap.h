/****************************************************************************/
/**
 *   @file          gse_encap.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION CONTEXT
 *
 *   @brief         Encapsulation structure definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_ENCAP_H
#define GSE_ENCAP_H

#include "gse_common.h"
#include "gse_fifo.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/**Encapsulation structure*/
typedef struct
{
  fifo_t *fifo;          /**< Table of FIFOs */
  size_t head_offset;    /**< Offset applied on the beginning of each copied
                              GSE packet
                              (default: FRAG_ID_LENGTH + TOTAL_LENGTH_LENGTH) */
  size_t trail_offset;   /**< Offset applied on the end of each copied
                              GSE packet (default: 0) */
  uint8_t qos_nbr;       /**< Number of QoS values */
} gse_encap_t;

/* If library is used with zero copy, the header and trailer offsets are not used.
 * However, with zero copy, there is at least the specified header offset minus
 * the maximum header length before the GSE packets. Thus, a header offset can
 * be used if a correct offset is specified when the fragment is created.
 * Trailer offset usage on GSE packets is not possible with zero-copy else, 
 * data could be overwritten. */

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

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

/**
 *  @brief   Get the QoS number
 *
 *  @param   encap   Encapsulation structure
 *  @return  QoS number on success, -1 on failure
 */
uint8_t gse_encap_get_qos_nbr(gse_encap_t *const encap);

#endif
