/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2016 TAS
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

/****************************************************************************/
/**
 *   @file          fifo.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
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

#include <pthread.h>

#include "encap_ctx.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** FIFO of GSE encapsulation contexts */
typedef struct
{
  gse_encap_ctx_t *values;  /**< The table of elements (ie. the FIFO) */
  size_t size;              /**< Size of the fifo */
  unsigned int first;       /**< Index of the first element of the FIFO */
  unsigned int last;        /**< Index of the last element of the FIFO */
  unsigned int elt_nbr;     /**< Number of elements in the FIFO */
  pthread_mutex_t mutex;    /**< Mutex on the context for multithreading support */
} fifo_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/* All these functions protect the access to the FIFO with a mutex.
 * The library is designed for a unique access when reading in a specific FIFO,
 * thus, when an element is got by a thread it is not protected afterwards */

/**
 *  @brief   Initialize a FIFO
 *
 *  @param   fifo  The FIFO to initialize
 *  @param   size  The size of the FIFO
 *
 *  @return
 *                 - success/informative code among:
 *                   - \ref GSE_STATUS_OK
 *                 - warning/error code among:
 *                   - \ref GSE_STATUS_FIFO_SIZE_NULL
 *                   - \ref GSE_STATUS_MALLOC_FAILED
 *                   - \ref GSE_STATUS_PTHREAD_MUTEX
 */
gse_status_t gse_init_fifo(fifo_t *fifo, size_t size);

/**
 *  @brief   Release a FIFO
 *
 *  @param   fifo  The FIFO that will be released
 *
 *  @return
 *                 - success/informative code among:
 *                   - \ref GSE_STATUS_OK
 *                 - warning/error code among:
 *                   - \ref GSE_STATUS_PTHREAD_MUTEX
 *                   - \ref GSE_STATUS_NULL_PTR
 *                   - \ref GSE_STATUS_FRAG_NBR
 */
gse_status_t gse_release_fifo(fifo_t *fifo);

/**
 *  @brief   Remove an element from the fifo
 *
 *  The FIFO is protected by a mutex when the element is removed
 *
 *  @param   fifo  The FIFO
 *
 *  @return
 *                 - success/informative code among:
 *                   - \ref GSE_STATUS_OK
 *                 - warning/error code among:
 *                   - \ref GSE_STATUS_PTHREAD_MUTEX
 *                   - \ref GSE_STATUS_FIFO_EMPTY
 */
gse_status_t gse_pop_fifo(fifo_t *fifo);

/**
 *  @brief   Tell the FIFO to add an element and to fill it
 *
 *  The FIFO is protected by a mutex when it is pushed but the new element is
 *  not protected afterwards. Thus, for correct library usage, only one thread
 *  should be allowed to read per FIFO.
 *
 *  @param   fifo      The FIFO
 *  @param   context   OUT: The element added in the FIFO
 *  @param   ctx_elts  Context used to transmit parameters to the FIFO
 *
 *  @return
 *                     - success/informative code among:
 *                       - \ref GSE_STATUS_OK
 *                     - warning/error code among:
 *                       - \ref GSE_STATUS_PTHREAD_MUTEX
 *                       - \ref GSE_STATUS_FIFO_FULL
 */
gse_status_t gse_push_fifo(fifo_t *fifo, gse_encap_ctx_t **context,
                           gse_encap_ctx_t ctx_elts);

/**
 *  @brief   Get the first element of the FIFO without removing it
 *
 *  The FIFO is protected by a mutex when getting the element but the element is
 *  not protected afterwards. Thus, for correct library usage, only one thread
 *  should be allowed to read per FIFO.
 *
 *  @param   fifo     The FIFO
 *  @param   context  OUT: The element to get in the FIFO
 *
 *  @return
 *                    - success/informative code among:
 *                      - \ref GSE_STATUS_OK
 *                    - warning/error code among:
 *                      - \ref GSE_STATUS_PTHREAD_MUTEX
 *                      - \ref GSE_STATUS_FIFO_EMPTY
 */
gse_status_t gse_get_fifo_elt(fifo_t *fifo, gse_encap_ctx_t **context);

/**
 *  @brief   Get the number of elements in the FIFO
 *
 *  The FIFO is protected by a mutex when getting the elements number.
 *
 *  @param   fifo   The FIFO
 *
 *  @return         The number of elements in the FIFO on success,
 *                  -1 on failure
 */
int gse_get_fifo_elt_nbr(fifo_t *const fifo);

#endif
