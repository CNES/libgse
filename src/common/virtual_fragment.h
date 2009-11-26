/****************************************************************************/
/**
 *   @file          virtual_fragment.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: VIRTUAL FRAGMENT
 *
 *   @brief         Prototypes of elements used by the virtual fragment
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef VIRTUAL_FRAGMENT_H
#define VIRTUAL_FRAGMENT_H

#include <string.h>

#include "status.h"

/**
 * @defgroup gse_virtual_fragment GSE virtual fragment API
 */

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Virtual buffer */
typedef struct
{
  unsigned char *start; /**< Point on the beginning of the virtual buffer */
  unsigned char *end;   /**< Point on the end of the virtual buffer */
  size_t length;        /**< Length of the virtual buffer (in bytes)*/
  unsigned int vfrag_count; /**< Number of virtual fragments
                                 This value should not be greater than 2 */
} gse_vbuf_t;

/** Virtual fragment: represent a subpart of a virtual buffer */
typedef struct
{
  gse_vbuf_t *vbuf;     /**< The virtual buffer to which the fragment belongs */
  unsigned char *start; /**< Point on the beginning of the virtual fragment */
  unsigned char *end;   /**< Point on the end of the virtual fragment */
  size_t length;        /**< length of the virtual fragment (in bytes)*/
} gse_vfrag_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Create an empty virtual fragment
 *
 *  The length of the virtual buffer containing the fragment will be
 *  max_length + head_offset + trail_offset.\n
 *  All length are expressed in bytes.\n
 *  For a GSE encapsulation usage, the header offset should at least be the
 *  maximum header length and the trailer offset should at least be the CRC
 *  length.\n
 *
 *  @param   vfrag         OUT: The virtual fragment on success,
 *                              NULL on error
 *  @param   max_length    The maximum length of the fragment
 *  @param   head_offset   The offset applied before the fragment
 *  @param   trail_offset  The offset applied after the fragment
 *
 *  @return
 *                         - success/informative code among:
 *                           - \ref GSE_STATUS_OK
 *                         - warning/error code among:
 *                           - \ref GSE_STATUS_NULL_PTR
 *                           - \ref GSE_STATUS_BUFF_LENGTH_NULL
 *                           - \ref GSE_STATUS_MALLOC_FAILED
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_create_vfrag(gse_vfrag_t **vfrag, size_t max_length,
                              size_t head_offset, size_t trail_offset);

/**
 *  @brief   Create a virtual fragment containing data
 *
 *  The length of the virtual buffer containing the fragment will be
 *  max_length + head_offset + trail_offset.\n
 *  All length are expressed in bytes.\n
 *  For a GSE encapsulation usage, the header offset should at least be the
 *  maximum header length and the trailer offset should at least be the CRC
 *  length.\n
 *
 *  @param   vfrag        OUT: The virtual fragment on success,
 *                             NULL on error
 *  @param   max_length   The maximum length of the fragment
 *  @param   head_offset  The offset applied before the fragment
 *  @param   trail_offset The offset applied after the fragment
 *  @param   data         The data to write in the virtual fragment
 *  @param   data_length  The length of the data
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_BUFF_LENGTH_NULL
 *                          - \ref GSE_STATUS_MALLOC_FAILED
 *                          - \ref GSE_STATUS_MULTIPLE_VBUF_ACCESS
 *                          - \ref GSE_STATUS_DATA_TOO_LONG
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_create_vfrag_with_data(gse_vfrag_t **vfrag, size_t max_length,
                                        size_t head_offset, size_t trail_offset,
                                        unsigned char const *data,
                                        size_t data_length);

/**
 *  @brief   Copy data in a virtual fragment
 *
 *  In case of warning or error, the virtual fragment is unchanged.
 *
 *  @param   vfrag       The virtual fragment
 *  @param   data        The data to write in the virtual fragment
 *  @param   data_length The length of the data (in bytes)
 *
 *  @return
 *                       - success/informative code among:
 *                         - \ref GSE_STATUS_OK
 *                       - warning/error code among:
 *                         - \ref GSE_STATUS_NULL_PTR
 *                         - \ref GSE_STATUS_MULTIPLE_VBUF_ACCESS
 *                         - \ref GSE_STATUS_DATA_TOO_LONG
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_copy_data(gse_vfrag_t *vfrag, unsigned char const* data,
                           size_t data_length);

/**
 *  @brief   Free a virtual fragment
 *
 *  @param   vfrag         IN: The virtual fragment that will be destroyed
 *                         OUT: NULL
 *
 *  @return
 *                         - success/informative code among:
 *                           - \ref GSE_STATUS_OK
 *                         - warning/error code among:
 *                           - \ref GSE_STATUS_NULL_PTR
 *                           - \ref GSE_STATUS_FRAG_NBR
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_free_vfrag(gse_vfrag_t **vfrag);

/**
 *  @brief   Create a virtual fragment from an existing one
 *
 *  In case of warning or error, the virtual fragment is unchanged.
 *  @warning If the father length is smaller than the wanted length, the length
 *           of the duplicated fragment will be the father length.
 *
 *  @param   vfrag        The duplicated virtual fragment
 *  @param   father       The virtual fragment which will be duplicated
 *  @param   length       The length of the duplicated virtual fragment (in bytes)
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_EMPTY_FRAG
 *                          - \ref GSE_STATUS_FRAG_NBR
 *                          - \ref GSE_STATUS_MALLOC_FAILED
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_duplicate_vfrag(gse_vfrag_t **vfrag, gse_vfrag_t *father, size_t length);

/**
 *  @brief   Shift the virtual fragment
 *
 *  All length are expressed in bytes.
 *  In case of warning or error, the virtual fragment is unchanged.
 *
 *  @param   vfrag        The virtual fragment
 *  @param   start_shift  The shift value to apply on the beginning of the
 *                        fragment
 *  @param   end_shift    The shift value to apply on the end of the fragment
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_PTR_OUTSIDE_BUFF
 *                          - \ref GSE_STATUS_FRAG_PTRS
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_shift_vfrag(gse_vfrag_t *vfrag, int start_shift, int end_shift);

/**
 *  @brief   Reset a virtual fragment to its created state
 *
 *  All length are expressed in bytes.
 *  In case of warning or error, the virtual fragment is unchanged.
 *
 *  @param   vfrag         The virtual fragment
 *  @param   length        OUT: The length of the fragment (can eventually be 0)
 *  @param   head_offset   The offset applied before the fragment
 *  @param   trail_offset  The offset applied after the fragment
 *
 *  @return                success/informative code among:
 *                           - \ref GSE_STATUS_OK
 *                         warning/error code among:
 *                           - \ref GSE_STATUS_NULL_PTR
 *                           - \ref GSE_STATUS_OFFSET_TOO_HIGH
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_reset_vfrag(gse_vfrag_t *vfrag, size_t *length,
                             size_t head_offset, size_t trail_offset);

/**
 *  @brief   Get the pointer on the beginning of a virtual fragment
 *
 *  In case of warning or error, the virtual fragment is unchanged.
 *
 *  @param   vfrag  Virtual fragment
 *
 *  @return         A pointer on the start of the virtual fragment on success,
 *                  NULL on failure
 *
 *  @ingroup gse_virtual_fragment
 */
unsigned char *gse_get_vfrag_start(gse_vfrag_t *vfrag);

/**
 *  @brief   Get the length of a virtual fragment (in bytes)
 *
 *  Check if vfrag is not NULL before using this function.
 *
 *  @param   vfrag  Virtual fragment
 *
 *  @return         The length of the virtual fragment
 *
 *  @ingroup gse_virtual_fragment
 */
size_t gse_get_vfrag_length(gse_vfrag_t *vfrag);

/**
 *  @brief   Set the length of a virtual fragment (in bytes)
 *
 *  In case of warning or error, the virtual fragment is unchanged.
 *
 *  @param   vfrag  The virtual fragment
 *  @param   length The length of the data that were put in the fragment
 *
 *  @return
 *                  - success/informative code among:
 *                    - \ref GSE_STATUS_OK
 *                  - warning/error code among:
 *                    - \ref GSE_STATUS_NULL_PTR
 *                    - \ref GSE_STATUS_PTR_OUTSIDE_BUFF
 *
 *  @ingroup gse_virtual_fragment
 */
gse_status_t gse_set_vfrag_length(gse_vfrag_t *vfrag, size_t length);

#endif
