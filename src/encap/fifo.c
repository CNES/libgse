/****************************************************************************/
/**
 *   @file          fifo.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: FIFO
 *
 *   @brief         FIFO for GSE encapsulation context
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "fifo.h"

#include <stdlib.h>
#include <assert.h>


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

gse_status_t gse_init_fifo(fifo_t *fifo, size_t size)
{
  gse_status_t status = GSE_STATUS_OK;

  assert(fifo != NULL);

  if(size == 0)
  {
    status = GSE_STATUS_FIFO_SIZE_NULL;
    goto error;
  }
  /* Each FIFO value is an encapsulation context */
  fifo->values = calloc(size, sizeof(gse_encap_ctx_t));
  if(fifo->values == NULL)
  {
    status = GSE_STATUS_MALLOC_FAILED;
    goto error;
  }
  /* Initialize the FIFO */
  fifo->size = size;
  fifo->first = 0;
  /* When the first element is created fifo->last become 0 */
  fifo->last = size - 1;
  fifo->elt_nbr = 0;
  /* Initialize the mutex on the FIFO */
  if(pthread_mutex_init(&fifo->mutex, NULL) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error;
  }

error:
  return status;
}

gse_status_t gse_release_fifo(fifo_t *fifo)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_status_t stat_mem = GSE_STATUS_OK;

  unsigned int i;

  assert(fifo != NULL);

  if(pthread_mutex_lock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error;
  }

  /* Free fragments in each encapsulation context */
  for(i = fifo->first;
      i != (fifo->last + 1) % fifo->size;
      i = (i + 1) % fifo->size)
  {
    status = gse_free_vfrag(fifo->values[i].vfrag);
    if(status != GSE_STATUS_OK)
    {
      stat_mem = status;
    }
  }

  free(fifo->values);

  if(pthread_mutex_unlock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error;
  }

  /* Destroy the mutex on the FIFO */
  if(pthread_mutex_destroy(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error;
  }

  return stat_mem;
error:
  return status;
}

gse_status_t gse_pop_fifo(fifo_t *fifo)
{
  gse_status_t status = GSE_STATUS_OK;

  assert(fifo != NULL);

  if(pthread_mutex_lock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error_mutex;
  }

  if(fifo->elt_nbr <= 0)
  {
    status = GSE_STATUS_FIFO_EMPTY;
    goto unlock;
  }
  fifo->first = (fifo->first + 1) % fifo->size;
  fifo->elt_nbr--;

unlock:
  if(pthread_mutex_unlock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
  }
error_mutex:
  return status;
}

gse_status_t gse_push_fifo(fifo_t *fifo, gse_encap_ctx_t **context,
                           gse_encap_ctx_t ctx_elts)
{
  gse_status_t status = GSE_STATUS_OK;

  assert(fifo != NULL);
  assert(context != NULL);

  if(pthread_mutex_lock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error_mutex;
  }

  if(fifo->elt_nbr >= fifo->size)
  {
    status = GSE_STATUS_FIFO_FULL;
    goto unlock;
  }
  fifo->last = (fifo->last + 1) % fifo->size;
  fifo->elt_nbr++;

  /* Return the context address */
  *context = &(fifo->values[fifo->last]);
  /* Copy elements in the context */
  **context = ctx_elts;

unlock:
  if(pthread_mutex_unlock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
  }
error_mutex:
  return status;
}

gse_status_t gse_get_fifo_elt(fifo_t *fifo, gse_encap_ctx_t **context)
{
  gse_status_t status = GSE_STATUS_OK;

  assert(fifo != NULL);
  assert(context != NULL);

  if(pthread_mutex_lock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto error_mutex;
  }

  if(fifo->elt_nbr == 0)
  {
    status = GSE_STATUS_FIFO_EMPTY;
    goto unlock;
  }
  *context = &(fifo->values[fifo->first]);

unlock:
  if(pthread_mutex_unlock(&fifo->mutex) != 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
  }
error_mutex:
  return status;
}

int gse_get_fifo_elt_nbr(fifo_t *const fifo)
{
  int nbr;

  assert(fifo != NULL);

  if(pthread_mutex_lock(&fifo->mutex) != 0)
  {
    goto error;
  }
  nbr = fifo->elt_nbr;
  if(pthread_mutex_unlock(&fifo->mutex) != 0)
  {
    goto error;
  }

  return nbr;
error:
  return -1;
}

