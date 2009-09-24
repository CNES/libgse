/****************************************************************************/
/**
 *   @file          gse_virtual_buffer.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: VIRTUAL BUFFER
 *
 *   @brief         Prototypes of elements used by the virtual buffer
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_VIRTUAL_BUFFER_H
#define GSE_VIRTUAL_BUFFER_H

#include "gse_common.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Virtual buffer */
typedef struct
{
  unsigned char* start; /**< Point on the beginning of the virtual buffer */
  unsigned char* end;   /**< Point on the end of the virtual buffer */
  size_t length;        /**< Length of the virtual buffer */
  int vfrag_count;      /**< Number of virtual fragments
                             This value should not be greater than 2 */
} vbuf_t;

/** Virtual fragment: contain a part of a virtual buffer */
typedef struct
{
  vbuf_t *vbuf;         /**< The virtual buffer to which the fragment belongs */
  unsigned char* start; /**< Point on the beginning of the virtual fragment */
  unsigned char* end;   /**< Point on the end of the virtual fragment */
  size_t length;        /**< length of the virtual fragment */
} vfrag_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Create an empty virtual fragment
 *
 *  The length of the virtual buffer containing the fragment will be
 *  max_length + head_offset + trail_offset
 *
 *  @param   vfrag         OUT: The virtual fragment
 *  @param   max_length    The maximum length of the fragment
 *  @param   head_offset   The offset applied before the fragment
 *  @param   trail_offset  The offset applied after the fragment
 *  @return  status code
 */
status_t gse_create_vfrag(vfrag_t **vfrag, size_t max_length,
                          size_t head_offset, size_t trail_offset);

/**
 *  @brief   Create a virtual fragment containing data
 *
 *  @param   vfrag        OUT: The virtual fragment
 *  @param   max_length   The maximum length of the fragment
 *  @param   head_offset  The offset applied before the fragment
 *  @param   trail_offset The offset applied after the fragment
 *  @param   data         The data to write in the virtual fragment
 *  @param   data_length  The length of the data
 *  @return  status code
 */
status_t gse_create_vfrag_with_data(vfrag_t **vfrag, size_t max_length,
                                    size_t head_offset, size_t trail_offset,
                                    unsigned char const *data,
                                    size_t data_length);
/* For a GSE encapsulation usage, the header offset should at least be the
 * maximum header length and the trailer offset should at least be the CRC length */

/**
 *  @brief   Copy data in a virtual fragment
 *
 *  @param   vfrag       The virtual fragment
 *  @param   data        The data to write in the virtual fragment
 *  @param   data_length The length of the data
 *  @return  status code
 */
status_t gse_copy_data(vfrag_t *vfrag, unsigned char const* data,
                       size_t data_lenth);

/**
 *  @brief   Free a virtual fragment
 *
 *  The value is added to the pointer
 *
 *  @param   vfrag         The virtual fragment that will be destoyed
 *  @return  status code
 */
status_t gse_free_vfrag(vfrag_t *vfrag);

/**
 *  @brief   Create a virtual fragment from an existing one
 *
 *  @param   vfrag        The duplicated virtual fragment
 *  @param   father       The virtual fragment which will be duplicated
 *  @param   length       The length of the duplicated virtual fragment
 *  @return  status code
 */
status_t gse_duplicate_vfrag(vfrag_t **vfrag, vfrag_t *father, size_t length);

/**
 *  @brief   Shift the virtual fragment
 *
 *  @param   vfrag        The virtual fragment
 *  @param   start_shift  The shift value to apply on the beginning of the
 *                        fragment
 *  @param   end_shift    The shift value to apply on the end of the fragment
 *  @return  status code
 */
status_t gse_shift_vfrag(vfrag_t *vfrag, size_t start_shift, size_t end_shift);

/**
 *  @brief   Reset a virtual fragment to its created state
 *
 *  @param   vfrag         The virtual fragment
 *  @param   length        The length of the fragment
 *  @param   head_offset   The offset applied before the fragment
 *  @param   trail_offset  The offset applied after the fragment
 *  @return  status code
 */
status_t gse_reset_vfrag(vfrag_t *vfrag, size_t *length,
                         size_t head_offset, size_t trail_offset);

/**
 *  @brief   Get the pointer on the beginning of a virtual fragment
 *
 *  @param   vfrag  Virtual fragment
 *  @return  pointer on the start of virtual fragment on sucess, NULL on failure
 */
unsigned char *gse_get_vfrag_start(vfrag_t *vfrag);

/**
 *  @brief   Get the length of a virtual fragment
 *
 *  @param   vfrag  Virtual fragment
 *  @return  length of the virtual fragment on success, -1 on failure
 */
size_t gse_get_vfrag_length(vfrag_t *vfrag);

/**
 *  @brief   Set the length of a virtual fragment
 *
 *  @param   vfrag  Virtual fragment
 *  @return  status
 */
status_t gse_set_vfrag_length(vfrag_t *vfrag, size_t length);

/**
 *  @brief   Get the number of fragments in a virtual buffer related to a
 *           virtual fragment
 *
 *  @param   vfrag The virtual fragment depending on the virtual buffer
 *  @return  Number of fragments on success, -1 on failure
 */
int gse_get_vfrag_nbr(vfrag_t *vfrag);

#endif
