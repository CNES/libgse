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
#include <pthread.h>

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** FIFO structure */
typedef struct
{
  gse_encap_ctx_t *value;   /**< The table of elements (ie. the FIFO) */
  size_t size;              /**< Size of the fifo */
  unsigned int first;       /**< First element of the FIFO */
  unsigned int last;        /**< Last element of the FIFO */
  unsigned int elt_nbr;     /**< Number of elements in the FIFO */
  pthread_mutex_t mutex;    /**< Mutex on the context for multithreading support */
} fifo_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/* All these functions protect the access to the FIFO with a mutex except
 * push_fifo which need to be protected outside to take into account the
 * element filling, get_elt_nbr and init_fifo */

/**
 *  @brief   Initialize a FIFO
 *
 *  @param   fifo  The FIFO to initialize
 *  @param   size  The size of the FIFO
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
 *  @brief   Tell the FIFO to add an element
 *
 *  The function return the new element but does not fill it
 *
 *  @param   fifo      The FIFO
 *  @param   context   OUT: The element added in the FIFO
 *  @return  status code
 */
status_t gse_push_fifo(fifo_t *fifo, gse_encap_ctx_t **context);

/**
 *  @brief   Get the first element of the FIFO without removing it
 *
 *  @param   fifo     The FIFO
 *  @param   context  OUT: The element to get in the FIFO
 *  @return  status code
 */
status_t gse_get_fifo_elt(fifo_t *fifo, gse_encap_ctx_t **context);

/**
 *  @brief   Get the number of elements in the FIFO
 *
 *  @param   fifo   The FIFO
 *  @return  the FIFO size on success
 */
int gse_get_fifo_elt_nbr(fifo_t *const fifo);

#endif
