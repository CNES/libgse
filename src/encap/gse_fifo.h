/****************************************************************************/
/**
 *   @file          gse_fifo.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: FIFO
 *
 *   @brief         Encapsulation FIFO
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_FIFO_H
#define GSE_FIFO_H

#include "gse_common.h"
#include "gse_encap_ctx.h"
#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** FIFO structure */
typedef struct
{
  gse_encap_ctx_t *value;   /**< The table of elements (ie. the FIFO) */
  unsigned int first;       /**< First element of the FIFO */
  unsigned int last;        /**< Last element of the FIFO */
  size_t size;              /**< Size of the fifo */
  unsigned int elt_nbr;     /**< Number of elements in the FIFO */
} fifo_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Initialize a FIFO
 *
 *  @param   fifo  The FIFO to initialize
 *  @param   size  The size of the fifo
 *  @return  status code
 */
status_t gse_init_fifo(fifo_t *fifo, size_t size);

/**
 *  @brief   Release a FIFO
 *
 *  @param   fifo  The FIFO that will be released
 *  @return  status code
 */
status_t gse_release_fifo(fifo_t *fifo);

/**
 *  @brief   Remove an element from the fifo
 *
 *  @param   fifo  The FIFO
 *  @return  status code
 */
status_t gse_pop_fifo(fifo_t *fifo);

/**
 *  @brief   Add an element in the FIFO
 *
 *  The function return the new element but does not fill it
 *
 *  @param   fifo      The FIFO
 *  @param   context   The element to add in the FIFO
 *  @return  status code
 */
status_t gse_push_fifo(fifo_t *fifo, gse_encap_ctx_t **context);

/**
 *  @brief   Get the first element of the FIFO without removing it
 *
 *  @param   fifo     The FIFO
 *  @param   context  The element to get in the FIFO
 *  @return  The fifo size
 */
status_t gse_get_elt(fifo_t *fifo, gse_encap_ctx_t **context);

/**
 *  @brief   Get the number of elements in the FIFO
 *
 *  @param   fifo   The FIFO
 *  @return  The fifo size
 */
int gse_get_elt_nbr_fifo(fifo_t *const fifo);

#endif
