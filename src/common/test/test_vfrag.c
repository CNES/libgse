/****************************************************************************/
/**
 * @file    test_vfrag.c
 * @brief   Virtual fragment management tests
 * @author  Didier Barvaux / Viveris Technologies
 */
/****************************************************************************/

/****************************************************************************
 *
 *   INCLUDES
 *
 *****************************************************************************/

/* system includes */
#include <gse_common.h>

/* GSE includes */
#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

#define DATA_LENGTH 64
#define VFRAG_LENGTH 64
#define DUP_LENGTH 32
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
 * @return      the unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
  int res = 1;

  if(argc > 2)
  {
    printf("USAGE : test_vfrag_robust [verbose]\n");
    goto quit;
  }
  if(argc == 1)
  {
    res = test_vfrag(0);
    goto quit;
  }
  if(argc == 2)
  {
    if(!strcmp(argv[1], "verbose"))
    {
      res = test_vfrag(1);
      goto quit;
    }
  }
  printf("USAGE : test_vfrag_robust [verbose]\n");

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
 * @return  0 on sucess, 1 on failure
 */
static int test_vfrag(int verbose)
{
  int is_failure = 1;
  unsigned char *data = NULL;
  vfrag_t *vfrag;
  vfrag_t *dup_vfrag;
  vfrag_t *created_vfrag;
  size_t length;
  int status = 0;
  unsigned int i;


  data = malloc(sizeof(unsigned char) * DATA_LENGTH);
  DEBUG(verbose, "The original data are '");

  // Create data
  for(i = 0 ; i < DATA_LENGTH ; i++)
  {
    data[i] = i;
    DEBUG(verbose, "%x", data[i]);
  }
  DEBUG(verbose, "'.\n");

  /********************************TEST_FUNC_1********************************/

  // Create a fragment and print informations
  status = gse_create_vfrag_with_data(&vfrag, VFRAG_LENGTH, 0, 0, data,
                                      DATA_LENGTH);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when creating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "\nThe fragment data are '");
  for(i = 0 ; i < vfrag->length ; i++)
  {
    DEBUG(verbose, "%x", vfrag->start[i]);
  }
  DEBUG(verbose, "'.\n");


  DEBUG(verbose, "\tIts size is %d, the virtual buffer size is %d\n"
         "\tIts start address is %p, the virtual buffer start address is %p\n"
         "\tIts end address is %p, the virtual buffer end address is %p\n"
         "\tNumber of fragments is %d\n",
          vfrag->length, vfrag->vbuf->length,
          vfrag->start, vfrag->vbuf->start,
          vfrag->end, vfrag->vbuf->end,
          vfrag->vbuf->vfrag_count);

  DEBUG(verbose, "\n***********************************************************\n\n");

  /********************************TEST_FUNC_2********************************/

  // Duplicate a fragment and print informations
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status > 0)
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

  DEBUG(verbose, "Its data are now '");
  for(i = 0 ; i < vfrag->length ; i++)
  {
    DEBUG(verbose, "%x", vfrag->start[i]);
  }
  DEBUG(verbose, "'.\n");

  // free duplicated fragment
  status = gse_free_vfrag(dup_vfrag);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when destroying duplicated fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe  duplicated fragment is destroyed, number of fragments is %d\n",
         vfrag->vbuf->vfrag_count);

  DEBUG(verbose, "\n***********************************************************\n\n");

  /********************************TEST_FUNC_3********************************/

  DEBUG(verbose, "Reset virtual fragment:\n'");

  status = gse_reset_vfrag(vfrag, &length, 0, 0);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when resetting fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "Its length is %d:\n'", length);
  
  DEBUG(verbose, "New data are written into the virtual fragment:\n'");

  // Create new data
  for(i = 0 ; i < DATA_LENGTH ; i++)
  {
    data[i] = DATA_LENGTH - i;
    DEBUG(verbose, "%x", data[i]);
  }
  DEBUG(verbose, "'.\nThe data are copied in the virtual fragment...\n");

  // Copy the data and print informations
  status = gse_copy_data(vfrag, data, DATA_LENGTH);
  if(status > 0)
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

  DEBUG(verbose, "\n***********************************************************\n\n");

  /********************************TEST_FUNC_4********************************/

  //Create a fragment from virtual fragment data
  status = gse_create_vfrag_with_data(&created_vfrag, CREATED_LENGTH, 10, 10,
                                      vfrag->start, CREATED_LENGTH);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when Creating fragment from the first one (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "Create a new fragment with a part of the virtual fragment...\n"
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

  DEBUG(verbose, "\n***********************************************************\n\n");

  //Fill the virtual fragment with 0 and check the data in the created vfrag
  status = gse_reset_vfrag(vfrag, &length, 0, 0);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when copying data in the virtual fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "The virtual fragment is filled with '0':\n"
         "Its data are now '");
  for(i = 0 ; i < length ; i++)
  {
    data[i] = 0x0;
  }
  status = gse_copy_data(vfrag, data, DATA_LENGTH);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when copying data in the virtual fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

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

  /********************************TEST_FUNC_5********************************/

  DEBUG(verbose, "\n***********************************************************\n\n");

  // Duplicate a fragment and print informations
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "A new duplicated fragment is created...\n"
         "The duplicated fragment data are '");
  for(i = 0 ; i < dup_vfrag->length ; i++)
  {
    DEBUG(verbose, "%x", dup_vfrag->start[i]);
  }
  DEBUG(verbose, "'.\n");

  // free the virtual fragment
  status = gse_free_vfrag(vfrag);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when destroying the virtual fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe virtual fragment is destroyed, buffer is not destroyed because"
         " number of fragment is %d\n", dup_vfrag->vbuf->vfrag_count);

  // free the duplicated fragment
  status = gse_free_vfrag(dup_vfrag);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when destroying the duplicated fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe duplicated fragment and the buffer are destroyed\n");

  // free the created fragment
  status = gse_free_vfrag(created_vfrag);
  if(status > 0)
  {
    DEBUG(verbose, "Error %#.4x when destroying the created fragment (%s)\n",
          status, gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "The created buffer is destroyed !\n");

  free(data);
  is_failure = 0;

failure:
  if(is_failure != 0)
    free(data);
  return is_failure;
}

