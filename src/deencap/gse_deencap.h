/****************************************************************************/
/**
 *   @file          gse_deencap.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: DEENCAPSULATION CONTEXT
 *
 *   @brief         De-encapsulation context and structure definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_DEENCAP_H
#define GSE_DEENCAP_H

#include "gse_common.h"
#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Deencapsulation context */
typedef struct
{
  vfrag_t *vfrag;            /**< Virtual buffer containing the PDU fragments */
  uint8_t label_type;        /**< Label type field value */
  uint16_t total_length;     /**< Total length field value */
  uint16_t protocol_type;    /**< Protocol type field value */
  gse_label_t label;         /**< Label field value */
  unsigned int bbframe_nbr;  /**< Number of BBFram since the reception of first
                                  fragment */
} gse_deencap_ctx_t;

/** Deencapsulation structure */
typedef struct
{
  gse_deencap_ctx_t *deencap_ctx; /**< Table of deencapsulation contexts */
  size_t head_offset;             /**< Offset applied on the beginning of the
                                       returned PDU (default: 0) */
  size_t trail_offset;            /**< Offset applied on the end of the
                                       returned PDU (default: 0) */
  uint8_t qos_nbr;                /**< Size of the deencapsulation context table,
                                       number of potential Frag ID */
} gse_deencap_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Initialize the deencapsulation structure
 *
 *  The function return the deencapsulation structure which is a table of
 *  deencapsulation contexts
 *
 *  @param   qos_nbr   Number of qos values
 *  @param   deencap   Structure of de-encapsulation contexts
 *  @return  status code
 */
status_t gse_deencap_init(uint8_t qos_nbr, gse_deencap_t **deencap);

/**
 *  @brief   Release the encapsulation structure
 *
 *  @param   deencap   Structure of de-encapsulation contexts
 *  @return  status code
 */
status_t gse_deencap_release(gse_deencap_t *deencap);

/**
 *  @brief   Set the offset applied on all the received PDU
 *
 *  @param   deencap       Structure of de-encapsulation contexts
 *  @param   head_offset   Offset applied on the beginning of the PDU
 *  @param   trail_offset  Offset applied on the end of the PDU
 */
void gse_deencap_set_offsets(gse_deencap_t *deencap,
                             size_t head_offset, size_t trail_offset);

/**
 *  @brief   Get the QoS number for deencapsulation context
 *
 *  @param   deencap   Structure of deencapsulation contexts
 *  @return  QoS number
 */
uint8_t gse_deencap_get_qos_nbr(gse_deencap_t *const deencap);

#endif
