#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "memory_debugger.h"

#ifdef DEBUG_MEMORY

// extern int errno;
int print_list_now = 0;
void *last_ptr_registered = NULL;

static MEMORYALLOCATIONINFO *info = NULL;
static int32_t numInfoStructs = 0;
static int32_t currentInfoStruct = 0;
static int32_t maxAllocated = 0;
static int32_t currentAllocated = 0;
static int dirty = 0;
static int keepTrack = 1;

static int blocksRegistered = 0;
char globalComment[256] = "";


/*
*	This keeps track of how much memory the memory tracking machinery uses.
*/
static int32_t trackingOverhead = 0;


static int32_t findInfoStruct (void *p);
static int32_t findInfoStructIn (void *p, MEMORYALLOCATIONINFO * m, int size);

static int compareAddresses (const void *b1, const void *b2);
static int compareWhenAllocated (const void *b1, const void *b2);
static void sortStructures (void);
static void sortStructuresByOrder (void);

static int trackStack[100];
static int trackStackIndex = 0;

int
setMemoryTracking (int track)
{
  keepTrack = track;
  return (0);
}
int
getMemoryTracking ()
{
  return (keepTrack);
}
static int printMemoryAllocationInfo (MEMORYALLOCATIONINFO * s);

int
pushMemoryTrackingStack ()
{
  if (trackStackIndex >= 100) {
    fprintf (stderr, "TRACK STACK OVERFLOW!\n");
    exit (1);
  }
  trackStack[trackStackIndex++] = getMemoryTracking ();
  return (0);
}

int
pushMemoryTracking (int newState)
{
  pushMemoryTrackingStack ();
  setMemoryTracking (newState);
  return (0);
}

int
popMemoryTracking ()
{
  if (trackStackIndex <= 0) {
    fprintf (stderr, "TRACK STACK UNDERFLOW!\n");
    exit (1);
  }
  setMemoryTracking (trackStack[--trackStackIndex]);
  return (0);
}

static int memoryStatusStack[20];
static int memoryStatusIndex = 0;
static int currentMemoryStatus = MS_SHOULD_BE_FREED;

static void *gBase = NULL;
static int gNum = -1;

void *
myBsearch (const void *key,
	   const void *base,
	   size_t nel,
	   size_t elemSize,
	   int (*compar) (const void *p1, const void *p2),
	   void **keyIsBefore)
{
  void *newBase = NULL;
  size_t newNel = 0;
  void *mid;
/*
 */
  if (nel == 0) {
    gBase = NULL;
    *keyIsBefore = NULL;
    return (NULL);
  }
/*
 */
  if (gBase == NULL) {
    if (compar (key, base) == 0) {
      *keyIsBefore = ((char *) base + elemSize);
      return ((void *) base);
    }
    if (compar (key, (char *) base + (nel - 1) * elemSize) == 0) {
      *keyIsBefore = NULL;
      return (void *) (((char *) base + (nel - 1) * elemSize));
    }
    gBase = (void *) base;
    gNum = nel;
  }
/*
 */
  if (nel == 1) {
    void *retVal;
    if (compar (key, base) < 0) {
      *keyIsBefore = (void *) base;
      retVal = NULL;
    } else {
      if (((char *) base + elemSize) < (char *) gBase + (gNum *
							 elemSize)) {
	*keyIsBefore = (char *) base + elemSize;
      } else {
	*keyIsBefore = NULL;
      }
      if (compar (key, base) == 0) {
	retVal = (void *) base;
      } else {
	retVal = NULL;
      }
    }
    gBase = NULL;
    return (retVal);
  }
  mid = &(((char *) base)[(nel / 2) * elemSize]);
//      printf("(base,nel,mid) = (%ld, %d, %ld)\n", base, nel, mid);
  if (compar (key, mid) < 0) {
    /*
     *    key < mid.  Base stays the same and numElements
     *      is halved.
     */
    newBase = (void *) base;
    newNel = nel / 2;
  } else if (compar (key, mid) > 0) {
    newBase = mid;
    newNel = nel - (nel / 2);
  } else {
    /*
     *    Mid is it.
     */
    if (mid > gBase) {
      *keyIsBefore = (char *) mid + elemSize;
      gBase = NULL;
      return (mid);
    }
  }
  return (myBsearch (key, newBase, newNel, elemSize, compar, keyIsBefore));
}

int
pushMemoryStatus (int newStatus)
{
  int retVal = currentMemoryStatus;
  assertGoodMemoryStatus (newStatus);
  if (memoryStatusIndex >= 20) {
    fprintf (stderr, "memory status stack overflow.\n");
    exit (1);
  }
  memoryStatusStack[memoryStatusIndex++] = currentMemoryStatus;
  currentMemoryStatus = newStatus;
  return (retVal);
}

int
popMemoryStatus ()
{
  int retval;
  if (memoryStatusIndex >= 20) {
    fprintf (stderr, "memory status stack underflow.\n");
    exit (1);
  }
  retval = currentMemoryStatus;
  currentMemoryStatus = memoryStatusStack[--memoryStatusIndex];
  return (retval);
}

int
assertGoodMemoryStatus (int status)
{
  switch (status) {
  case MS_SHOULD_BE_FREED:
  case MS_SHOULD_NOT_BE_FREED:
    break;
  default:
    fprintf (stderr, "Bad status %d to assertGoodMemoryStatus", status);
    exit (1);
    break;
  }
  return (0);
}

/*
*	Set the status field of a particular entry.  This should be one of
*	[MS_SHOULD_BE_FREED | MS_SHOULD_NOT_BE_FREED]
*
*	Returns 0 if the status parameter is ok, otherwise prints an error
*	and exits.
*/
int
setStatus (void *p, int status)
{
  int32_t i;
  if (!keepTrack || (p == NULL))
    return (0);
  i = findInfoStruct (p);
  if (i < 0) {
    fprintf (stderr, "Problem in setStatus\n");
    exit (1);
  }
  assertGoodMemoryStatus (status);
  info[i].status = status;
  return (0);
}

static int
compareAddresses (const void *v1, const void *v2)
{
  MEMORYALLOCATIONINFO *p1 = (MEMORYALLOCATIONINFO *) v1;
  MEMORYALLOCATIONINFO *p2 = (MEMORYALLOCATIONINFO *) v2;
  return ((int) ((char *) p1->buffer - (char *) p2->buffer));
}

static int
compareWhenAllocated (const void *v1, const void *v2)
{
  MEMORYALLOCATIONINFO *p1 = (MEMORYALLOCATIONINFO *) v1;
  MEMORYALLOCATIONINFO *p2 = (MEMORYALLOCATIONINFO *) v2;
  return (p1->whichTime - p2->whichTime);
}

static void
sortStructuresByOrder ()
{
  qsort (info, currentInfoStruct, (unsigned int) sizeof
	 (MEMORYALLOCATIONINFO), compareWhenAllocated);
  dirty = 1;
}

static void
sortStructures ()
{
  qsort (info, currentInfoStruct, (unsigned int) sizeof
	 (MEMORYALLOCATIONINFO), compareAddresses);
  dirty = 0;
}

void *
myMemmove (void *dest, const void *source, size_t size, char *file, int line)
{
  static int theSize = 0;
  static void *temp = NULL;
  if (size > 0) {
    if ((source == NULL) || (dest == NULL)) {
      fprintf (stderr, "MEMMOVE to/from NULL pointer [%s/%d].\n", file, line);
      assert (0);
    }
  }
#if HAVE_MEMMOVE
  return ((void *) memmove (dest, source, size));
#else
  if (size > theSize) {
    while (theSize < size)
      theSize += 1000;
    temp = realloc (temp, theSize);
  }
  memcpy (temp, source, size);
  return (memcpy (dest, temp, size));
#endif
}

/*
*
*/
int
registerBlock (void *p, size_t b, char *file, int line)
{
  if (!keepTrack)
    return (0);
  blocksRegistered++;
  if (p == NULL && b > 0) {
    fprintf (stderr, "WARNING: registering a NULL block of size >0.\n");
  }
  // printf("Registering block %p (%s) (%d) call(%d)\n",
	//	p,
	//	file,
	//	line,
	//	blocksRegistered);
  //fflush(stdout);
  /* If this block is already registered, return 1. */
  if (findInfoStruct (p) >= 0)
    return (1);
  /*
   *  Make sure we have space for the new information.
   *    Use real malloc and realloc here because we don't want to call ourselves!
   */
  if (currentInfoStruct >= numInfoStructs) {
    numInfoStructs += 1000;
    if (info == NULL) {
      info = (MEMORYALLOCATIONINFO *) malloc (numInfoStructs * sizeof (MEMORYALLOCATIONINFO));
    } else {
      info = (MEMORYALLOCATIONINFO *) realloc (info, numInfoStructs *
					       sizeof (MEMORYALLOCATIONINFO));
    }
    trackingOverhead = numInfoStructs * sizeof (MEMORYALLOCATIONINFO);
    if (info == NULL) {
      fprintf (stderr, "Can't reallocate info pointer.\n");
      exit (1);
    }
  }
/*
 *
 */
  currentAllocated += b;
  if (currentAllocated > maxAllocated)
    maxAllocated = currentAllocated;
  {
    /*
     *    Move the current structures as necessary to make room for the new one.
     */
    MEMORYALLOCATIONINFO key;
    MEMORYALLOCATIONINFO *isBefore;
    key.buffer = p;
    myBsearch (&key,
	       info,
	       currentInfoStruct,
	       sizeof (MEMORYALLOCATIONINFO),
	       compareAddresses,
	       (void **) &isBefore);
    if (isBefore == NULL) {
      /* */
      isBefore = &info[currentInfoStruct];
    } else {
      int numToMove = currentInfoStruct - (isBefore - info);
      MEMMOVE (isBefore + 1, isBefore, numToMove * sizeof (MEMORYALLOCATIONINFO));
    }
    /*
     */
    isBefore->buffer = p;
    strncpy (isBefore->file, file, (size_t) MAXMEMFNAME);
    (isBefore->file)[MAXMEMFNAME - 1] = '\0';
    if ( strlen(globalComment)>0 ) {
      strncpy (isBefore->gComment, globalComment, (size_t) 256);
      (isBefore->gComment)[256 - 1] = '\0';
    }
    isBefore->line = line;
    isBefore->size = b;
    isBefore->whichTime = blocksRegistered;
    isBefore->status = currentMemoryStatus;
    currentInfoStruct++;
    last_ptr_registered = p;
    return (0);
  }
}

void
updateBlockInfo (void *p, char *file, int line)
{
  int i;
  i = findInfoStruct (p);
  if (i >= 0) {
    strcpy (info[i].file, file);
    info[i].line = line;
    if ( strlen(globalComment)>0 ) {
      strncpy (info [i].gComment, globalComment, (size_t) 256);
      info [i].gComment[256 - 1] = '\0';
    }
  }
}

void
updateLastBlockInfo (char *file, int line)
{
  int i;
  void *p = last_ptr_registered;

  if (!p)
     return;

  i = findInfoStruct (p);
  if (i >= 0) {
    strcpy (info[i].file, file);
    info[i].line = line;
    if ( strlen(globalComment)>0 ) {
      strncpy (info [i].gComment, globalComment, (size_t) 256);
      (info [i].gComment)[256 - 1] = '\0';
    }
  }
}


int
memory_checkpoint (MEMORYALLOCATIONINFO ** theInfo)
{
  *theInfo = (MEMORYALLOCATIONINFO *) malloc (currentInfoStruct * sizeof (MEMORYALLOCATIONINFO));
  MEMMOVE (*theInfo, info, currentInfoStruct * sizeof (MEMORYALLOCATIONINFO));
  return (currentInfoStruct);
}

int
newSince (MEMORYALLOCATIONINFO * theInfo, int num)
{
  int i;
  printf ("There are currently a total of %ld buffers tracked (%d)\n",
	  currentInfoStruct, sizeof (MEMORYALLOCATIONINFO));
  for (i = 0; i < currentInfoStruct; i++) {
    if (findInfoStructIn (info[i].buffer, theInfo, num) < 0) {
      printMemoryAllocationInfo (&info[i]);
    }
  }
  return (0);
}

int
unregisterBlock (void *p, char *file, int line)
{
  static int timesCalled = 0;
  int32_t i;
  timesCalled++;
  if (p == NULL)
    return (0);
  if (!keepTrack)
    return (0);
  i = findInfoStruct (p);
  //printf("Unregistering block %p (%s) (%d) call(%d)\n",
	//	p,
	//	file,
	//	line,
	//	timesCalled);
  if (i < 0) {
    fprintf (stderr,
	     "Trying to free something we didn't allocate from [%s/%d] at %p call(%d)\n",
	     file, line, p, timesCalled);
    fflush (stdout);
    fflush (stderr);
    logMemoryInfo ();
    exit (1);
  }
//printf("Unregistering block %p (%s) (%d) call(%d)\n", p, file, line, timesCalled);
//fflush(stdout);
  currentAllocated -= info[i].size;
//      logEvent(LOGMEMORYPRINT, "myFree freeing %ld bytes from [%s/%ld] at %0X.\n",
//              info[i].size, info[i].file, info[i].line, p);
  currentInfoStruct--;
/*
 */
  {
    int numToMove = currentInfoStruct - i;
    MEMMOVE (&info[i], &info[i + 1], numToMove * sizeof (MEMORYALLOCATIONINFO));
    return (0);
  }
}

int
purgeMemoryTracking ()
{
  currentInfoStruct = 0;
  dirty = 0;
  return (0);
}

int
memory_check (void *p, char *file, int line)
{
  if (!keepTrack)
    return (0);
  if (findInfoStruct (p) >= 0) {
    return (1);
  } else {
    fprintf (stderr, "Check failed on pointer %p file: %s line: %d\n",
	     p, file, line);
    return (0);
  }
}

/*
** myMalloc(size, file, line) allocates and returns a pointer to size
** bytes and logs the allocation in a memory allocation structure.
** This routine should never be called directly, only through the
** macro MALLOC().
*/
void *
myMalloc (size_t b, char *file, int line)
{
  void *tmp;
  tmp = (void *) malloc (b);
  if (tmp == NULL) {
    fprintf (stderr, "Out of memory {%s, %d} tried to allocate %d.\n",
	     file, line, b);
    logMemoryInfo ();
    exit (1);
  }
  if (keepTrack) {
//              logEvent(LOGMEMORYPRINT, "myMalloc allocating %ld bytes [%s/%ld] 0x%08lX.\n", b,
//                                               file, line, tmp);
    registerBlock (tmp, b, file, line);
  }
  return (tmp);
}

void *
myRealloc (void *p, size_t b, char *file, int line)
{
  void *retVal = NULL;
  if (b == 0)
    return (NULL);
  if (p == NULL) {
    retVal = myMalloc (b, file, line);
  } else {
    retVal = realloc (p, b);
    if (keepTrack) {
//                      logEvent(LOGMEMORYPRINT, "myRealloc {%s, %d} reallocating pointer %08lX to %08lX.\n",
//                              file, line, p, retVal);
    }
  }
  if ((p != NULL) && (keepTrack)) {
    unregisterBlock (p, file, line);
    registerBlock (retVal, b, file, line);
  }
#ifdef sun4
  if (retVal == NULL) {
    switch (errno) {
    case EINVAL:
      sprintf (reason, "incorrect value.");
      break;
    case ENOMEM:
      sprintf (reason, "out of memory.");
      break;
    default:
      sprintf (reason, "unknown reason.");
      break;
    }
    fprintf (stderr, "Out of memory in realloc because: %s", reason);
  }
#endif
  return (retVal);
}

/*
** Free memory allocated earlier and log the transaction.
*/
void
myFree (void *p, char *file, int line)
{
  if (!keepTrack) {
    free (p);
    return;
  }
  if (p == NULL)
    return;
  unregisterBlock (p, file, line);
  free (p);
}

static int32_t
findInfoStructIn (void *p, MEMORYALLOCATIONINFO * m, int size)
{
  MEMORYALLOCATIONINFO *result;
  MEMORYALLOCATIONINFO key;
  key.buffer = p;
#if 0
  int32_t i;
  for (i = 0; i < size; i++) {
    if (m[i].buffer == p) {
      return (i);
    }
  }
#else
  if (dirty) {
    sortStructures ();
  }
  if (m == NULL) {
    return (-1);
  }
  result = (MEMORYALLOCATIONINFO *) bsearch (&key, m, size, sizeof
					     (MEMORYALLOCATIONINFO), compareAddresses);
  if (result == NULL) {
    return (-1);
  } else {
    return (result - m);
  }
#endif
  return (-1);
}

static int32_t
findInfoStruct (void *p)
{
  int32_t i;
  i = findInfoStructIn (p, info, currentInfoStruct);
  return (i);
}

static int32_t
findInfoStruct2 (void *p)
{
  int32_t i;
  if (dirty)
    sortStructures ();
  for (i = 0; (i < currentInfoStruct) && (p >= info[i].buffer); i++) {
    if (info[i].buffer == p) {
      return (i);
    }
  }
  return (-i);
}

/*
**
*/
int
inAllocatedSpace (void *p)
{
  int32_t where;
  where = findInfoStruct2 (p);
  if (where > 0)
    return (1);
  if (where < 0)
    where = (-where) - 1;
  if (((char *) p >= (char *) info[where].buffer)
      && ((char *) p < (char *) info[where].buffer + info[where].size))
    return (1);
  return (0);
}

int
memoryUsed (size_t * currentUsed, size_t * maxUsed, size_t * overhead)
{
  *currentUsed = currentAllocated;
  *maxUsed = maxAllocated;
  *overhead = trackingOverhead;
  assert (currentAllocated <= maxAllocated);
  return (1);
}

/*
** Print information about the memory allocation logged.  This is
** a diagnostic.  It's an int so that I have a shot at calling it
** from within the debugger.
*/
int
logMemoryInfo ()
{
  int32_t i;
  int32_t totalAllocated = 0;
//      sortStructuresByOrder();
  printf ("long = %d  void* = %d\n", sizeof (int32_t), sizeof (void *));
  printf ("%d blocks were registered.\n", blocksRegistered);
  printf ("There are %ld allocation structures.\n", currentInfoStruct);
  for (i = 0; i < currentInfoStruct; i++) {
    printf ("%4ld  ", i);
    printMemoryAllocationInfo (&info[i]);
    totalAllocated += info[i].size;
  }
  printf ("Maximum memory usage: %ld\n", maxAllocated);
  printf ("A total of %ld bytes are currently allocated.\n", totalAllocated);
  return (0);
}

static int
printMemoryAllocationInfo (MEMORYALLOCATIONINFO * s)
{
#define LOGFORMAT	"o[%ld] f[%s] l[%ld] c[%s] s[%ld] b[0x%08lx] %s\n"
  printf (LOGFORMAT,
	  s->whichTime,
	  s->file,
	  s->line,
	  s->gComment,
	  (int32_t) s->size,
	  (int32_t) s->buffer,
	  (s->status == MS_SHOULD_BE_FREED) ? "Should be Freed" :
	  "OK to be left");
  return (0);
}


#endif // DEBUG_MEMORY




