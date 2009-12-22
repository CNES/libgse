/****************************************************************************/
/**
 *   @file          test_vfrag.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Virtual fragment management tests
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

/****************************************************************************
 *
 *   INCLUDES
 *
 *****************************************************************************/

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdint.h>

/* GSE includes */
#include "virtual_fragment.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

/** Length of data to write in the virtual fragment */
#define DATA_LENGTH 64
/** Length of the virtual fragment */
#define VFRAG_LENGTH 64
/** Length of the duplicated virtual fragment */
#define DUP_LENGTH 32
/** Length of the created virtual fragment */
#define CREATED_LENGTH 16

/* DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_vfrag(int verbose);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Main function for the GSE virtual buffer test program
 *
 * @param argc  the number of program arguments
 * @param argv  the program arguments
 * @return      the unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
  int res = 1;
  int verbose = 0;

  if(argc > 2 || argc < 1)
  {
    printf("USAGE : test_vfrag [verbose]\n");
  }
  else
  {
    if(argc == 2)
    {
      if(!strcmp(argv[1], "verbose"))
      {
        verbose = 1;
      }
      else
      {
        printf("USAGE : test_vfrag_robust [verbose]\n");
        goto quit;
      }
    }
    res = test_vfrag(verbose);
  }

quit:
  return res;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Test the virtual buffer creation, duplication and release
 *
 * @param   verbose  Print debug if verbose is 1
 * @return  0 on sucess, 1 on failure
 */
static int test_vfrag(int verbose)
{
  int is_failure = 1;
  unsigned char *data;
  unsigned char *zero;
  gse_vfrag_t *vfrag;
  gse_vfrag_t *dup_vfrag;
  gse_vfrag_t *created_vfrag;
  size_t length;
  gse_status_t status;
  unsigned int i;


  data = malloc(sizeof(unsigned char) * DATA_LENGTH);
  if(data == NULL)
  {
    DEBUG(verbose, "Malloc failed for data\n");
    goto quit;
  }
  zero = malloc(sizeof(unsigned char) * DATA_LENGTH);
  if(zero == NULL)
  {
    DEBUG(verbose, "Malloc failed for zero\n");
    goto free_data;
  }

  DEBUG(verbose, "The original data are '");

  /* Create data */
  for(i = 0 ; i < DATA_LENGTH ; i++)
  {
    data[i] = i;
    DEBUG(verbose, "%x", data[i]);
  }
  DEBUG(verbose, "'.\n");

  /******************************* TEST_FUNC_1 *******************************/

  /* Create a fragment and print informations */
  status = gse_create_vfrag_with_data(&vfrag, VFRAG_LENGTH, 0, 0, data,
                                      DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when creating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  /* Avoid the loop is verbose is deactivated */
  if(verbose)
  {
    DEBUG(verbose, "\nThe fragment data are '");
    for(i = 0 ; i < vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");
  }

  DEBUG(verbose, "\tIts size is %d, the virtual buffer size is %d\n"
        "\tIts start address is %p, the virtual buffer start address is %p\n"
        "\tIts end address is %p, the virtual buffer end address is %p\n"
        "\tNumber of fragments is %d\n",
         vfrag->length, vfrag->vbuf->length,
         vfrag->start, vfrag->vbuf->start,
         vfrag->end, vfrag->vbuf->end,
         vfrag->vbuf->vfrag_count);
  
  /* Check the different values and the data*/
  if(vfrag->length != VFRAG_LENGTH ||
     vfrag->vbuf->length != VFRAG_LENGTH ||
     vfrag->start != vfrag->vbuf->start ||
     vfrag->vbuf->vfrag_count != 1 ||
     memcmp(vfrag->start, data, vfrag->length))
  {
    DEBUG(verbose, "ERROR: Data are incorrect or this list contains incorrect value\n");
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /******************************* TEST_FUNC_2 *******************************/

  /* Duplicate a fragment and print informations */
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "A duplicated fragment is created...\n"
                 "The duplicated fragment data are '");
  for(i = 0 ; i < dup_vfrag->length ; i++)
  {
    DEBUG(verbose, "%x", dup_vfrag->start[i]);
  }
  DEBUG(verbose, "'.\n");

  DEBUG(verbose, "\tIts size is %d, the virtual buffer size is %d\n"
         "\tIts start address is %p, the virtual buffer start address is %p\n"
         "\tIts end address is %p, the virtual buffer end address is %p\n"
         "\tNumber of fragments is %d\n"
         "\nThe initial virtual fragment start address is now %p\n"
         "and its length %d\n",
          dup_vfrag->length, dup_vfrag->vbuf->length,
          dup_vfrag->start, dup_vfrag->vbuf->start,
          dup_vfrag->end, dup_vfrag->vbuf->end,
          dup_vfrag->vbuf->vfrag_count,
          vfrag->start,
          vfrag->length);

  if(verbose)
  {
    DEBUG(verbose, "Its data are now '");
    for(i = 0 ; i < vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");
  }

  /* Check the different values and the data*/
  if(dup_vfrag->length != DUP_LENGTH ||
     dup_vfrag->vbuf->length != VFRAG_LENGTH ||
     dup_vfrag->start != vfrag->start ||
     dup_vfrag->vbuf->vfrag_count != 2 ||
     vfrag->start != vfrag->vbuf->start ||
     vfrag->length != VFRAG_LENGTH ||
     memcmp(dup_vfrag->start, data, dup_vfrag->length) ||
     memcmp(vfrag->start, data, vfrag->length))
  {
    DEBUG(verbose, "ERROR: Data are incorrect or this list contains incorrect value\n");
    goto failure;
  }

  /* free duplicated fragment */
  status = gse_free_vfrag(&dup_vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying duplicated fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe  duplicated fragment is destroyed, number of fragments is %d\n",
         vfrag->vbuf->vfrag_count);

  if(vfrag->vbuf->vfrag_count != 1)
  {
    DEBUG(verbose, "ERROR: incorrect number of fragment value\n");
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /******************************* TEST_FUNC_3 *******************************/

  DEBUG(verbose, "Reset virtual fragment:\n'");

  status = gse_reset_vfrag(vfrag, &length, 0, 0);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when resetting fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "Its length is %d:\n'", length);
  if(vfrag->length != VFRAG_LENGTH)
  {
    DEBUG(verbose, "ERROR: incorrect length value\n");
    goto failure;
  }

  DEBUG(verbose, "New data are written into the virtual fragment:\n'");

  /* Create new data */
  for(i = 0 ; i < DATA_LENGTH ; i++)
  {
    data[i] = DATA_LENGTH - i;
    DEBUG(verbose, "%x", data[i]);
  }
  DEBUG(verbose, "'.\nThe data are copied in the virtual fragment...\n");

  /* Copy the data and print informations */
  status = gse_copy_data(vfrag, data, DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when copying data in fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "\nThe virtual fragment data are now '");
  for(i = 0 ; i < vfrag->length ; i++)
  {
    DEBUG(verbose, "%x", vfrag->start[i]);
  }
  DEBUG(verbose, "'.\n");
  if(memcmp(vfrag->start, data, DATA_LENGTH))
  {
    DEBUG(verbose, "ERROR: incorrect number of fragment value\n");
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /******************************* TEST_FUNC_4 *******************************/

  /* Create a fragment from virtual fragment data */
  status = gse_create_vfrag_with_data(&created_vfrag, CREATED_LENGTH, 10, 10,
                                      vfrag->start, CREATED_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when Creating fragment from the first one (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  if(verbose)
  {
    DEBUG(verbose, "Create a new fragment with a part of the virtual fragment...\n"
          "Header and trailer offsets are set to 10\n"
          "The created fragment data are '");
    for(i = 0 ; i < created_vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", created_vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");

    DEBUG(verbose, "\tIts size is %d, the virtual buffer size is %d\n"
           "\tIts start address is %p, the virtual buffer start address is %p\n"
           "\tIts end address is %p, the virtual buffer end address is %p\n"
           "\tNumber of fragments in this buffer is %d\n"
           "\nThe duplicated virtual fragment start address is %p, its end address is %p\n"
           "and its length %d\n",
           created_vfrag->length, created_vfrag->vbuf->length,
           created_vfrag->start, created_vfrag->vbuf->start,
           created_vfrag->end, created_vfrag->vbuf->end,
           created_vfrag->vbuf->vfrag_count,
           vfrag->start,
           vfrag->end,
           vfrag->length);

    DEBUG(verbose, "Its data are still '");
    for(i = 0 ; i < vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");
  }

  /* Check the different values and the data*/
  if(created_vfrag->length != CREATED_LENGTH ||
     created_vfrag->vbuf->length != CREATED_LENGTH + 10 + 10 ||
     created_vfrag->start != created_vfrag->vbuf->start + 10 ||
     created_vfrag->vbuf->vfrag_count != 1 ||
     vfrag->start != vfrag->vbuf->start ||
     vfrag->length != DATA_LENGTH ||
     memcmp(created_vfrag->start, vfrag->start, created_vfrag->length) ||
     memcmp(vfrag->start, data, vfrag->length))
  {
    DEBUG(verbose, "ERROR: Data are incorrect or this list contains incorrect value\n");
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /* Fill the virtual fragment with 0 and check the data in the created vfrag */
  status = gse_reset_vfrag(vfrag, &length, 0, 0);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when copying data in the virtual fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  if(verbose)
  {
    DEBUG(verbose, "The virtual fragment is filled with '0':\n"
           "Its data are now '");
    for(i = 0 ; i < length ; i++)
    {
      zero[i] = 0x0;
    }
  }

  status = gse_copy_data(vfrag, zero, DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when copying data in the virtual fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  if(verbose)
  {
    for(i = 0 ; i < DATA_LENGTH ; i++)
    {
      DEBUG(verbose, "%x", vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");

    DEBUG(verbose, "Created vfrag data are still '");
    for(i = 0 ; i < created_vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", created_vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");
  }

  if(memcmp(created_vfrag->start, data, created_vfrag->length ||
     memcmp(vfrag->start, zero, vfrag->length)))
  {
    DEBUG(verbose, "ERROR: Data are incorrect\n");
    goto failure;
  }

  /******************************* TEST_FUNC_5 *******************************/

  DEBUG(verbose, "\n***********************************************************\n\n");

  /* Duplicate a fragment and print informations */
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  if(verbose)
  {
    DEBUG(verbose, "A new duplicated fragment is created...\n"
           "The duplicated fragment data are '");
    for(i = 0 ; i < dup_vfrag->length ; i++)
    {
      DEBUG(verbose, "%x", dup_vfrag->start[i]);
    }
    DEBUG(verbose, "'.\n");
  }
  if(memcmp(dup_vfrag->start, zero, dup_vfrag->length))
  {
    DEBUG(verbose, "ERROR: Data are incorrect\n");
    goto failure;
  }

  /* free the virtual fragment */
  status = gse_free_vfrag(&vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the virtual fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe virtual fragment is destroyed, buffer is not destroyed because"
         " number of fragment is %d\n", dup_vfrag->vbuf->vfrag_count);
  if(dup_vfrag->vbuf->vfrag_count != 1)
  {
    DEBUG(verbose, "ERROR: Number of fragment is incorrect\n");
    goto failure;
  }

  /* free the duplicated fragment */
  status = gse_free_vfrag(&dup_vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the duplicated fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe duplicated fragment and the buffer are destroyed\n");

  /* free the created fragment */
  status = gse_free_vfrag(&created_vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the created fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "The created buffer is destroyed !\n");

  is_failure = 0;

failure:
  free(zero);
free_data:
  free(data);
quit:
  return is_failure;
}

