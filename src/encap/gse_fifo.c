/****************************************************************************/
/**
 *   @file          gse_fifo.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: FIFO
 *
 *   @brief         FIFO for GSE encapsulation context
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_fifo.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_init_fifo(fifo_t *fifo, size_t size)
{
  status_t status = STATUS_OK;

  assert(fifo != NULL);

  if(size == 0)
  {
    status = ERR_FIFO_SIZE_NULL;
    goto error;
  }
  //Each FIFO value is an encapsulation context
  fifo->value = malloc(sizeof(gse_encap_ctx_t) * size);
  if(fifo->value == NULL)
  {
    fifo = NULL;
    status = ERR_MALLOC_FAILED;
    goto error;
  }
  //Initialize the FIFO
  fifo->size = size;
  fifo->first = 0;
  //When the first element is created fifo->last become 0
  fifo->last = size - 1;
  fifo->elt_nbr = 0;

error:
  return status;
}

status_t gse_release_fifo(fifo_t *fifo)
{
  status_t status = STATUS_OK;
  status_t stat_mem = STATUS_OK;

  unsigned int i = 0;
  unsigned int j = fifo->first;

  assert(fifo != NULL);

  //Free fragments in each encapsulation context
  while(i < fifo->elt_nbr)
  {
    status = gse_free_vfrag(fifo->value[j].vfrag);
    if(status != STATUS_OK)
    {
      stat_mem = status;
    }
    j = (j + 1) % fifo->size;
    i++;
  }

  free(fifo->value);

  return stat_mem;
}

status_t gse_pop_fifo(fifo_t *fifo)
{
  status_t status = STATUS_OK;

  assert(fifo != NULL);

  if(fifo->elt_nbr <= 0)
  {
    status = FIFO_EMPTY;
    goto error;
  }
  fifo->first = (fifo->first + 1) % fifo->size;
  fifo->elt_nbr--;

error:
  return status;
}

status_t gse_push_fifo(fifo_t *fifo, gse_encap_ctx_t **context)
{
  status_t status = STATUS_OK;

  assert(fifo != NULL);

  if(fifo->elt_nbr >= fifo->size)
  {
    status = FIFO_FULL;
    goto error;
  }
  fifo->last = (fifo->last + 1) % fifo->size;
  fifo->elt_nbr++;
  //Return the context address
  *context = &(fifo->value[fifo->last]);

error:
  return status;
}

status_t gse_get_elt(fifo_t *fifo, gse_encap_ctx_t **context)
{
  status_t status = STATUS_OK;

  assert(fifo != NULL);

  if(fifo->elt_nbr == 0)
  {
    status = FIFO_EMPTY;
    goto error;
  }
  *context = &(fifo->value[fifo->first]);

error:
  return status;
}

int gse_get_elt_nbr_fifo(fifo_t *const fifo)
{
  return fifo->elt_nbr;
}

