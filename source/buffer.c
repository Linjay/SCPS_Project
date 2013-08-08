/********************************************************
 * 
 *                             NOTICE
 *  
 * "This software was produced for the U.S. Government under
 * Contract No's. DAAB07-97-C-E601, F19628-94-C-0001,
 * NAS5-32607, and JPL contract 752939 and is subject 
 * to the Rights in Noncommercial Computer Software and 
 * Noncommercial Computer Software Documentation Clause 
 * at (DFARS) 252.227-7014 (JUN 95), and the Rights in 
 * Technical Data and Computer Software Clause at (DFARS) 
 * 252.227-7013 (OCT 88) with Alternate II (APR 93),  
 * FAR 52.227-14 Rights in Data General, and Article GP-51,
 * Rights in Data - General, respectively.
 *
 *        (c) 1999 The MITRE Corporation
 *
 * MITRE PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO 
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY, 
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT. 
 * IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, 
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR 
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you 
 * indemnify and hold harmless MITRE, its Board of 
 * Trustees, officers, agents and employees, from any and 
 * all liability or damages to third parties, including 
 * attorneys' fees, court costs, and other related costs 
 * and expenses, arising our of your use of the Product 
 * irrespective of the cause of said liability, except 
 * for liability arising from claims of US patent 
 * infringements.
 *
 * The export from the United States or the subsequent 
 * reexport of this software is subject to compliance 
 * with United States export control and munitions 
 * control restrictions.  You agree that in the event you 
 * seek to export this software you assume full 
 * responsibility for obtaining all necessary export 
 * licenses and approvals and for assuring compliance 
 * with applicable reexport restrictions.
 *
 ********************************************************/

#include <string.h>
#include <stdlib.h>
extern void free (void *ptr);
extern void *malloc (size_t size);
//extern void *memset (void *s, int c, size_t n);
extern int printf (const char *format, /* args */ ...);

#include "buffer.h"
#include "tp_debug.h"

#include "scpstp.h"

#ifdef DEBUG_SNACK_OLD
extern FILE *trimFile;
#endif /* DEBUG_SNACK_OLD */

#ifndef SEQ_GT
#define SEQ_GT(a,b)    ((int)((a)-(b)) > 0)
#endif /* SEQ_GT */
#ifndef SET_LT
#define SEQ_LT(a,b)    ((int)((a)-(b)) < 0)
#endif /* SEQ_LT */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: buffer.c,v $ -- $Revision: 1.31 $\n";
#endif

extern void fix_tp_header (void *, struct mbuff *);

extern uint32_t tp_now;

int cluster_check = 1;
struct _sys_memory sys_memory =
{
  TOTAL_SYSTEM_BUFFERS,		/* Total buffer space */
  0,				/* Amount of space now in use */
  0,				/* Amount of buffers now in use */
  0,				/* Amount of clusters now in use */
  0,				/* Amount of clusters promised */
  0,				/* Number of clusters actually malloc'd */
  {				/* fblist initialization */
    TOTAL_SYSTEM_BUFFERS,	/* Upper bound on fblist size */
    0,				/* Instantaneous size of fblist */
    0,				/* Number of elements currently enqueued */
    TOTAL_SYSTEM_BUFFERS,	/* Maximum ever allowed to be enqueued */
    0,				/* Biggest size we've seen so far */
    0,				/* Corresponds to data size */
    0,				/* Biggest # elements we've seen so far */
    0,
    NULL,			/* Pointer to first buffer in fblist chain */
    NULL,			/* Pointer to last buffer in fblist chain */
    NULL,			/* Pointer to fblist snd_una */
    NULL,			/* Pointer to fblist send */
    NULL,			/* Pointer to holes */
    NULL},			/* Pointer to parent */
  {				/* fclist initialization */
    (TOTAL_SYSTEM_BUFFERS / SMCLBYTES + 2),	/* Max size of fclist */
    0,				/* Instantaneous size of fclist */
    0,				/* Biggest size we've seen so far */
    0,				/* Out_Seq_size... Not really useful... */
    0,				/* Number of elements in fclist */
    (TOTAL_SYSTEM_BUFFERS / SMCLBYTES + 2),	/* Big number, keep all give */
    0,				/* Biggest number of elements we've seen */
    0,				/* fclist bytes beyond write-head */
    0,				/* Run-length - not applicable here */
    NULL,			/* Pointer to last buffer in fclist chain */
    NULL,			/* Pointer to last cluster in fclist chain */
    NULL,			/* fclist read_head */
    NULL,			/* fclist write_head */
    0,				/* fclist write_off */
    0,				/* fclist read_off */
    NULL			/* Pointer to first record boundary */
  },
  /* free _hole_element list */
  NULL
};

struct _clust_mem_map clust_mem_map;

/*
 * Adds 'buf' to the end of the linked list 'q'. (Intended to be used for
 * both retransmission buffers and the flist.) Returns 0 and leaves 'q'
 * unchanged if 'q' already contains the maximum number of elements.
 * Otherwise, enqueues 'buf' and returns the number of elements in 'q' after
 * modification.
 */

int cluster_id = -1;
int
enq_mbuff (struct mbuff *buf, struct _buffer *q)
{
  if (q == NULL)
    {
      abort ();
    }

  if (q->b_size == q->max_size)
    return (0);

  if (buf == NULL)
    {
      return (0);
    }

 if ((q->last) && 
     (((tp_Header *) (q->last->m_pktdat))->flags & tp_FlagFIN) &&
     (((tp_Header *) (buf->m_pktdat))->flags & tp_FlagFIN)) {
	return ((q->b_size));
  }

if ( (q->start == q->last) && (q->start == NULL) )
    {
      q->start = q->last = buf;
      /* Next line doesn't exist in version b */
      buf->m_prev = buf->m_next = NULL;
      q->data_size  = q->b_size = 0;
    }
  else
    {
      q->last->m_next = buf;
      buf->m_prev = q->last;
      buf->m_next = NULL;
      q->last = buf;
    }
  buf->parent = q;
  q->data_size += buf->m_plen;
  return (++(q->b_size));
}

/*
 * Returns 0 and leaves 'q' unchanged if 'q' is empty. Otherwise, dequeues
 * the first element in 'q' and returns a pointer to it.
 */
struct mbuff *
deq_mbuff (struct _buffer *q)
{
  struct mbuff *temp;

  if (q->b_size == 0)
    return ((struct mbuff *) NULL);

  if (q->start == NULL)
    {
      /* Bummer, we've got a problem! */
      q->start = q->last = NULL;
      q->b_size = 0;
      return ((struct mbuff *) NULL);
    }
  temp = q->start;
  temp->m_prev = (struct mbuff *) NULL;
  q->start = q->start->m_next;

  if (q->start)
    {
      q->start->m_prev = (struct mbuff *) NULL;
    }
  else
    {
      q->last = (struct mbuff *) NULL;
    }

  q->b_size--;
  q->data_size -= temp->m_plen;
  temp->parent = NULL;
  /* This needs to be nulled out too.  --KS. */
  temp->m_next = NULL;

  return (temp);
}

/*
 * Walks down a chain of mbuffs and frees the mbuffs and attached clusters.
 * Used for flushing send and receive buffers.
 * 
 * Note: This code currently assumes a packet contains a single packet. To fix
 * this, we need to make all other mbuff linkages based upon m_nextpkt and
 * m_prevpkt, instead of m_next & m_prev, AND we need to add a sub-loop in
 * here to walk through the m_next chain for a header mbuff and free that up,
 * prior to going on to the next mbuff-header.
 * 
 */
void
kill_bchain (struct mbuff *buff_head)
{

  /* In case we're pruning a chain from the middle */
  if ((buff_head) && (buff_head->m_prev))
    buff_head->m_prev->m_next = NULL;

  while (buff_head)
    {
      if (buff_head->m_next)
	{
	  buff_head = buff_head->m_next;
	  free_mbuff (buff_head->m_prev);
	  /* We would free-up a sub-chain here - see above */
	}
      else
	{
	  free_mbuff (buff_head);
	  buff_head = NULL;
	}
    }
}

/*
 * Adds 'cluster' to the end of the linked list 'q'. (Intended to be used for
 * cluster chains) Returns 0 and leaves 'q' unchanged if 'q' already contains
 * the maximum number of elements.  Otherwise, enqueues 'buf' and returns the
 * number of elements in 'q' after modification.
 */
int
enq_mclus (struct mbcluster *cluster, struct _cl_chain *q)
{
  if ((q->num_elements == q->max_elements) || (!(cluster)))
    {
      return (0);
    }

  if (q->num_elements == 0)
    {
      q->start = cluster;
      cluster->c_prev = NULL;
    }
  else
    {
      q->last->c_next = cluster;
      cluster->c_prev = q->last;
    }
  cluster->c_next = NULL;
  cluster->parent = q;
  q->last = cluster;
  if ((++(q->num_elements)) > q->biggest_elements)
    {
      q->biggest_elements = q->num_elements;
    }
  return (q->num_elements);
}

/*
 * Frees 'cluster' by attempting to place it onto the global fclist. If
 * fclist is full (contains max_size elements), 'cluster' is deallocated.
 */
void
free_mclus (struct mbcluster *cluster)
{
  if (cluster)
    {
      if (--(cluster->c_count) == 0)
	{
	  if (cluster->parent)
	    {
	          cluster->parent->num_elements--;

	      if (cluster->parent->start == cluster)
		{
		  cluster = deq_mclus (cluster->parent);
		}
	      else
		{
		  abort ();
		}
	    }
	  else
	    {
	    }
	  /* Clean it out! */
	  /* memset (cluster, 0, sizeof (struct mbcluster)); */

          if (cluster) {
            sys_memory.clust_in_use--;
            clust_mem_map.clust_list [cluster->cluster_id].used = 0;
/*            unregisterBlock (cluster, __FILE__, __LINE__);          */
          } else {
/*		printf ("Tried to Free a cluster and could not find it\n"); */
          }

	  if ( (cluster)  && (!(enq_mclus (cluster, &(sys_memory.fclist)))))
	    {
              sys_memory.clust_in_use--;
              clust_mem_map.clust_list [cluster->cluster_id].used = -1;
	      free ((char *) cluster);
	      sys_memory.clust_created--;
	    }
            cluster = NULL;
	} else {

        }

    } else {
	cluster = NULL;
    }

}

/*
 * Frees 'buf' by attempting to place it onto the global flist. If the flist
 * is full (contains max_size elements), 'buf' is deallocated. This code now
 * should properly handle freeing of mbuffs that have data spanning two or
 * more clusters.
 * 
 * This routine seems to work REALLY hard, let's make sure that none of its
 * efforts are duplicated anywhere else...
 */
void
free_mbuff (struct mbuff *buf)
{
  int size;
  int clust_count = 0;
  struct mbcluster *next_cluster, *temp_cluster;

  if (!buf)
    {
      return;
    }

  /* If this mbuff has a cluster associated with it, free it first */
  if (buf->m_flags & M_EXT)
    {

      /*
       * This is slightly complicated, since we might have multiple
       * clusters chained to this mbuffer. We can determine this
       * from the offset into the first cluster and the overall
       * data length.
       */

      size = buf->m_ext.offset + buf->m_ext.len;

      if (size > SMCLBYTES)
	{
	  /* Need to lop off multiple clusters... */
	  /*
	   * Overhang = length - (SMCLBYTES - offset) which is
	   * == length + offset - SMCLBYTES == size - SMCLBYTES,
	   * the number of clusters is found by dividing by
	   * SMCLBYTES and adding 1 (integer arithmetic)
	   * cluster-count = (size - SMCLBYTES)/SMCLBYTES + 1
	   * Simplifying, we get:
	   *       clust_count = (size / SMCLBYTES)
	   * If SMCLBYTES is an even multiple of size,
	   * we will try and free one more cluster than we've
	   * actually allocated to the mbuff, prompting an 
	   * error. To fix this, if the remainder of 
	   * (size % SMCLBYTES) == 0, we decrement clust_count. 
	   */

	  clust_count = 0;
	  clust_count = (size / SMCLBYTES);
	  if (!(size % SMCLBYTES))
	    clust_count--;

	  /*
	   * Free the first one, and step through the chain
	   * after it
	   */

	  next_cluster = ((struct mbcluster *) buf->m_ext.ext_buf)->c_next;

	  free_mclus ((struct mbcluster *) buf->m_ext.ext_buf);
	  for (clust_count = clust_count; clust_count > 0; clust_count--)
	    {
	      if (next_cluster)
		{
		  if (next_cluster->c_next)
		    {
		      /*
		       * Not guaranteed to have a
		       * back pointer!
		       */
		      temp_cluster = next_cluster;
		      temp_cluster->mbuffs--;
		      next_cluster = next_cluster->c_next;
		      free_mclus (temp_cluster);
                      temp_cluster = NULL;
		    }
		  else
		    {
		      next_cluster->mbuffs--;
		      free_mclus (next_cluster);
		      next_cluster = NULL;
		    }
		}
	    }
	}
      else if (size)
	{
	  free_mclus ((struct mbcluster *) buf->m_ext.ext_buf);
	}
    }
  /* memset (buf, 0, (sizeof (struct mbuff) - MHLEN)); */
/* bzero (buf, sizeof (struct mbuff)); *//* Clear it out. */
  buf->m_seq = 17;		/* A prime number that shouldn't occur often */
  buf->m_ext.len = 20000000;	/* Bigger than the biggest window we expect to see. */
  memset ((buf->m_pktdat), 0, MHLEN);   /* We must clear this data */

  {
    if (!(enq_mbuff (buf, &(sys_memory.fblist)))) {
      sys_memory.mbuff_created--;	/* Durst - 7/29/1999 */
      free ((char *) buf);
    }
    sys_memory.mbuff_in_use--;
  }
}

/*
 * Allocates an mbuff by attempting to remove one from the front of the
 * global flist. If the flist is empty, and we haven't already exceeded the
 * maximum buffer space available, a new mbuff is malloc'd. Note: This
 * routine currently assumes that buffer space is assigned in fixed sized
 * chunks, so if there is buffer space available, at worst, another malloc
 * will fill available buffer space, not exceed it.
 * 
 * This routine seems to work REALLY hard, let's make sure none of it's efforts
 * are duplicated elsewhere. Make sure that this routine isn't too
 * involved...
 */
struct mbuff *
alloc_mbuff (int type)
{
  struct mbuff *temp;

  if (sys_memory.fblist.b_size == 0)
    {
      if (sys_memory.mbuff_created < MAX_MBUFFS)
	{
	  if (!(temp = (struct mbuff *) malloc (sizeof (struct mbuff)))) {
	      return ((struct mbuff *) NULL);
          }

	  if (!(temp->m_data = (char *) malloc (MBLEN * sizeof (char))))
	    {
	      free ((char *) temp);
	      syslog (LOG_ERR, "Gateway: Failed to alloc_mbuff 1\n");
	      return ((struct mbuff *) NULL);
	    }

	  sys_memory.mbuff_in_use++;
	  sys_memory.mbuff_created++;

	  /* clear it out */

	  memset (temp, 0, (sizeof (struct mbuff) - MHLEN));
	  temp->m_type = type;

	  if (type == MT_HEADER)
	    temp->m_flags &= M_PKTHDR;
	  if (temp->m_flags)
	    printf("Well, that's a surprise!  alloc_mbuff, temp->m_flags = %u, M_PKTHDR = %u\n", 
		temp->m_flags, M_PKTHDR);
	  return (temp);
	}
      syslog (LOG_ERR, "Gateway: Failed to alloc_mbuff 2\n");
      return ((struct mbuff *) NULL);
    }

  temp = deq_mbuff (&(sys_memory.fblist));
  if (!temp) {
	return ((struct mbuff *) NULL);
  }

  sys_memory.mbuff_in_use++;
  memset (temp, 0, (sizeof (struct mbuff) - MHLEN));
  temp->m_type = type;
  temp->m_next = temp->m_prev = NULL;

  if (type == MT_HEADER)
    temp->m_flags &= M_PKTHDR;
  if (temp->m_flags)
    printf("Well, that's another surprise!  alloc_mbuff, temp->m_flags = %u, M_PKTHDR = %u\n", 
		temp->m_flags, M_PKTHDR);

  return (temp);
}

/*
 * Remove a cluster from the head of the chain. Clean up the dangling c_next
 * and c_prev fields while we're at it.
 */
struct mbcluster *
deq_mclus (struct _cl_chain *q)
{
  struct mbcluster *temp;

#ifdef DEBUG_MEMORY
  if (q == NULL)
    {
      printf ("WARNING: Who's trying to deq_mclus from a NULL cluster?\n");
    }
  if (q->num_elements > 0 && q->start == NULL)
    {
      printf
	("deq_mclus: cluster(%p) has num_elements=%d but start is NULL\n",
	 q, q->num_elements);
      fflush (stdout);
      q->num_elements = 0;
      return (NULL);
    }
#endif /* DEBUG_MEMORY */

  if (q->num_elements == 0)
    {
      return ((struct mbcluster *) NULL);
    }

  temp = q->start;
  temp->c_prev = (struct mbcluster *) NULL;
  temp->parent = NULL; 

  q->start = q->start->c_next;

  if (q->start)
    {
      q->start->c_prev = (struct mbcluster *) NULL;
    }
  else
    {
      q->last = NULL;
    }
  q->num_elements--;
  temp->de_queued = 1;
  return (temp);
}

/*
 * Allocates an mcluster by attempting to remove one from the front of the
 * global fclist. If the fclist is empty, and we haven't already exceeded the
 * maximum cluster space available, a new mbcluster is malloc'd. Note: This
 * routine currently does NO checking for allocation boundaries. We'll need
 * to incorporate some global bounds for application buffer space and abide
 * by them. To do that model on alloc_mbuff() above.
 */

struct mbcluster *
alloc_mbclus (int reserve_pool)
{
  struct mbcluster *temp;
  int tmp_clust_id;

  if (((!cluster_check) && (sys_memory.clust_in_use  + 5  <
            sys_memory.fclist.max_size))) { 
  } else {
      if ((reserve_pool) &&(sys_memory.clust_in_use  + 20  >
            sys_memory.fclist.max_size)) {
#ifdef MEMORY_DEBUG
	  printf ("In alloc_mbclus %d %d\n", sys_memory.clust_in_use, sys_memory.fclist.max_size);
#endif /* MEMORY_DEBUG */
	  return (NULL);
      }

  }

  if (sys_memory.fclist.num_elements == 0)
    {
      if (sys_memory.clust_created < sys_memory.fclist.max_size)
	{
	  if (!(temp = (struct mbcluster *) malloc (sizeof (struct mbcluster))))

	    {
	      syslog (LOG_ERR, "Gateway: Failed to alloc_mbclus 1\n");
	      return ((struct mbcluster *) NULL);
	    }
	  memset (temp, 0, sizeof (struct mbcluster));
	  cluster_id++;
	  temp ->cluster_id = cluster_id;
	  sys_memory.clust_created++;
	  sys_memory.clust_in_use++;
/*          registerBlock (temp, 10, __FILE__,  __LINE__); */
          clust_mem_map.clust_list [cluster_id].used = 1;
          clust_mem_map.clust_list [cluster_id].clust = temp;
          clust_mem_map.clust_list [cluster_id].where = 0;
	  return (temp);
	}
      else
	{
#ifdef MEMORY_DEBUG
	  printf ("In alloc_mbclus %d %d\n", sys_memory.clust_in_use, sys_memory.fclist.max_size);
#endif /* MEMORY_DEBUG */
	  return (NULL);
	}
    }
  else /* There is at least one element on the free cluster list. */
    {
      if (sys_memory.fclist.start == NULL)
	{
	  printf("Thought there were elements on the free list but there are none!\n");
	}
      temp = deq_mclus (&(sys_memory.fclist));
      if (!temp) {
         printf ("%s %d 1 tried to dequeue a clust off the free list, but non was there \n", __FILE__, __LINE__);
	 sys_memory.fclist.num_elements = 0x0;
	 sys_memory.fclist.start = 0x0;
	 sys_memory.fclist.last = 0x0;
      } else {
          tmp_clust_id = temp ->cluster_id;
          memset (temp, 0, sizeof (struct mbcluster));
          temp ->cluster_id = tmp_clust_id;
          sys_memory.clust_in_use++;
          clust_mem_map.clust_list [temp ->cluster_id].used = 1;
          clust_mem_map.clust_list [temp ->cluster_id].where = 0;
/*          registerBlock (temp, 10, __FILE__,  __LINE__); */
          return (temp);
      }
    }
    return NULL;
}

struct _hole_element *
alloc_hole_element (void)
{

  struct _hole_element *temp = 0x0;

  if (sys_memory.hole_list)
    {
      temp = sys_memory.hole_list;
      sys_memory.hole_list = sys_memory.hole_list->next;
      temp->next = 0x0;

      if (sys_memory.hole_list)
	sys_memory.hole_list->prev = 0x0;
    }
  else if
      ((temp = (struct _hole_element *) malloc (sizeof (struct
							_hole_element))))
    {
      memset (temp, 0, sizeof (struct _hole_element));
    }

  if (temp)
    temp->prev = temp->next = 0x0;

  return (temp);
}

void
free_hole_element (struct _hole_element *hole)
{
  hole->prev = 0x0;

  memset (hole, 0x0, sizeof (struct _hole_element));

  if (sys_memory.hole_list)
    {
      sys_memory.hole_list->prev = hole;
      hole->next = sys_memory.hole_list;
    }
  else
    hole->next = 0x0;

  sys_memory.hole_list = hole;
}

/* 
 * Insert a hole into an ordered list of holes. 
 * Return value is the new head of the hole list.
 * Implementation assumes that holes next overlap 
 */

struct _hole_element *
insert_hole (struct _hole_element *list,
	     struct _hole_element *hole, uint32_t tp_now1,
             uint32_t snack_delay)
{
  struct _hole_element *previous_hole = 0x0;
  struct _hole_element *next_hole = 0x0;

/*  Possible cases:
 *  Case 1:  Disjoint holes
 *  Case 2:  Hole identical to another hole in list
 *  Case 3:  Old hole contains new hole (full containment)
 *  Case 4:  New hole contains old hole (full containment)
 *  Case 5:  New hole extends beyond old hole (with overlap)
 *  Case 6:  New hole precedes old hole (with overlap)
 *  Case 7:  New hole bridges gap(s) between multiple old holes
 */
#ifdef DEBUG_SNACK_OLD
  fprintf (trimFile, "     Before hole is reconciled:  \n");
  printHoleChain (list);
#endif /* DEBUG_SNACK_OLD */
  if (list)
    {
      next_hole = list;

      /*  Here's the deal:
       *    We first locate the appropriate point in the list based on
       *    the new hole's starting sequence number.  This test is 
       *    buzzes through holes while the starting sequence number of
       *    the new hole is GREATER than the ending sequence number of
       *    the existing hole.  (Note that this allows adjacency of holes
       *    with no space between them, which is OK -- meaning that we don't
       *    upchuck when we encounter it.)
       *  
       *    OK, once we pop out of that while loop, we lash the new hole
       *    into the list at that point, then clean up the trash we might
       *    create.
       *    
       *    The trash might include all of them cases above.
       */

      /* Step 1:  find the point in the list to lash this guy in */
      while ((next_hole) &&
	     SEQ_GT (hole->hole_start_seq, next_hole->hole_end_seq))
	{
	  previous_hole = next_hole;
	  next_hole = next_hole->next;
	}

#ifdef DEBUG_SNACK_OLD
      fprintf (trimFile, "     Finished insert_hole step 1. \n");
      fprintf (trimFile,
	       "     list(%p), hole(%p), next_hole(%p), previous_hole(%p)\n",
	       list, hole, next_hole, previous_hole);
      fprintf (trimFile, "     hole:  start_seq(%u), end_seq(%u)\n",
	       hole->hole_start_seq, hole->hole_end_seq);
      fprintf (trimFile, "     next_hole:  start_seq(%u), end_seq(%u)\n",
	       next_hole ? next_hole->hole_start_seq : 0,
	       next_hole ? next_hole->hole_end_seq : 0);
      fprintf (trimFile, "     previous_hole:  start_seq(%u), end_seq(%u)\n",
	       previous_hole ? previous_hole->hole_start_seq : 0,
	       previous_hole ? previous_hole->hole_end_seq : 0);
#endif /* DEBUG_SNACK_OLD */

      /* Step 1.5:  If we start in the middle of an existing hole, we
       *  1) throw away the new hole if it's completely covered by the
       *     existing hole, or
       *  2) Extend the start of the new hole backwards to the beginning
       *     of the existing hole and allow the code below to handle
       *     the possible need to extend the tail of our new hole.
       */
      if (next_hole && (SEQ_GEQ (hole->hole_start_seq, next_hole->hole_start_seq)))
	{
	  /* We overlap with the existing hole - check for complete overlap */
	  if (SEQ_GEQ (next_hole->hole_end_seq, hole->hole_end_seq))
	    {
	      /* Existing hole completely covers us, punt */
	      remove_hole (NULL, hole);		/* Not lashed in yet, just get rid of it */
#ifdef DEBUG_SNACK_OLD
	      fprintf (trimFile, "     After existing hole subsumed:  \n");
	      printHoleChain (list);
#endif /* DEBUG_SNACK_OLD */
	      return (list);	/* Sorry */
	    }
	  hole->length += hole->hole_start_seq - next_hole->hole_start_seq;
	  hole->hole_start_seq = next_hole->hole_start_seq;
	  hole->hole_start = next_hole->hole_start;
	  hole->next_to_send = next_hole->next_to_send;		/* ??? */
	}
#ifdef DEBUG_SNACK_OLD
      fprintf (trimFile, "     Finished insert_hole step 1.5 \n");
      fprintf (trimFile,
	       "     list(%p), hole(%p), next_hole(%p), previous_hole(%p)\n",
	       list, hole, next_hole, previous_hole);
      fprintf (trimFile, "     hole:  start_seq(%u), end_seq(%u)\n",
	       hole->hole_start_seq, hole->hole_end_seq);
      fprintf (trimFile, "     next_hole:  start_seq(%u), end_seq(%u)\n",
	       next_hole ? next_hole->hole_start_seq : 0,
	       next_hole ? next_hole->hole_end_seq : 0);
      fprintf (trimFile, "     previous_hole:  start_seq(%u), end_seq(%u)\n",
	       previous_hole ? previous_hole->hole_start_seq : 0,
	       previous_hole ? previous_hole->hole_end_seq : 0);
#endif /* DEBUG_SNACK_OLD */

      /* Step 2:  Lash this guy in after previous and before next 
       *   In a stroke of good luck, if the guy goes at the beginning
       *   of the list, previous_hole happens to be NULL at the end of
       *   the while loop and next_hole is "list".  If the new guy goes
       *   at the END of the list, next_hole is NULL, and previous_hole
       *   points to the last hole in the list.  Planning?  I think not!
       */
      if (previous_hole)
	previous_hole->next = hole;
      else
	list = hole;
      if (next_hole)
	next_hole->prev = hole;
      hole->next = next_hole;
      hole->prev = previous_hole;

#ifdef DEBUG_SNACK_OLD
      fprintf (trimFile, "     Finished insert_hole step 2 \n");
      fprintf (trimFile,
	       "     list(%p), hole(%p), next_hole(%p), previous_hole(%p)\n",
	       list, hole, next_hole, previous_hole);
      fprintf (trimFile,
	       "     hole:  start_seq(%u), end_seq(%u), next(%p) prev(%p)\n",
	       hole->hole_start_seq, hole->hole_end_seq,
	       hole->next, hole->prev);
      fprintf (trimFile,
	       "     next_hole:  start_seq(%u), end_seq(%u), next(%p), prev(%p)\n",
	       next_hole ? next_hole->hole_start_seq : 0,
	       next_hole ? next_hole->hole_end_seq : 0,
	       next_hole ? next_hole->next : 0,
	       next_hole ? next_hole->prev : 0);

      fprintf (trimFile,
	       "     previous_hole:  start_seq(%u), end_seq(%u), next(%p), prev(%p)\n",
	       previous_hole ? previous_hole->hole_start_seq : 0,
	       previous_hole ? previous_hole->hole_end_seq : 0,
	       previous_hole ? previous_hole->next : 0,
	       previous_hole ? previous_hole->prev : 0);
#endif /* DEBUG_SNACK_OLD */

      /* Step 3:  Clean up the mess we just made.  There are two possibilities
       *   for the new guy's end_seq:  
       *      1)  It ends between two holes (which may mean before the next element
       *          in the list or beyond the last element in the list)
       *      2)  It ends in the middle of an existing hole.
       *
       *   (If it abuts an existing hole, we treat it as case 1, above.)
       *   For case 1, we remove any holes that our new guy completely subsumes.
       *   For case 2, we do that, too, plus we adjust the ending point for our
       *   new hole to match that of the hole in the midst of which we end.
       *   (With apologies to all English speakers everywhere.)
       */
      while (next_hole && (SEQ_GEQ (hole->hole_end_seq, next_hole->hole_end_seq)))
	{
	  hole->next = next_hole->next;
	  if (next_hole->next)
	    next_hole->next->prev = hole;
	  list = remove_hole (list, next_hole); /* PDF added list = 7/30/1999 */
	  next_hole = hole->next;
	}

      if (next_hole && (SEQ_GT (hole->hole_end_seq, next_hole->hole_start_seq)))
	{
	  /* Need to fix the hole end seq number, the length, and the pointer to 
	   * the ending mbuffer.
	   */
	  hole->hole_end_seq = next_hole->hole_end_seq;
	  hole->length = hole->hole_end_seq - hole->hole_start_seq;
	  hole->hole_end = next_hole->hole_end;
	  hole->next = next_hole->next;
	  if (next_hole->next)
	    next_hole->next->prev = hole;
	  list = remove_hole (list, next_hole); /* PDF added list = 7/30/1999 */
	}


#ifdef DEBUG_SNACK_OLD
      fprintf (trimFile, "     Finished insert_hole step 3 \n");
      fprintf (trimFile,
	       "     list(%p), hole(%p), next_hole(%p), previous_hole(%p)\n",
	       list, hole, hole->next, hole->prev);
      fprintf (trimFile, "     hole:  start_seq(%u), end_seq(%u)\n",
	       hole->hole_start_seq, hole->hole_end_seq);
      fprintf (trimFile,
	       "     next_hole:  start_seq(%u), end_seq(%u), next(%p), prev(%p)\n",
	       hole->next ? hole->next->hole_start_seq : 0,
	       hole->next ? hole->next->hole_end_seq : 0,
	       hole->next ? hole->next->next : 0,
	       hole->next ? hole->next->prev : 0);

      fprintf (trimFile,
	       "     previous_hole:  start_seq(%u), end_seq(%u), next(%p), prev(%p)\n",
	       hole->prev ? hole->prev->hole_start_seq : 0,
	       hole->prev ? hole->prev->hole_end_seq : 0,
	       hole->prev ? hole->prev->next : 0,
	       hole->prev ? hole->prev->prev : 0);
#endif /* DEBUG_SNACK_OLD */
    }
  else
    {
      list = hole;
      hole->next = NULL;
      hole->prev = NULL;
    }

  if (snack_delay == 0) {
     hole->Embargo_Time = 0;
  } else {
     hole->Embargo_Time = snack_delay + tp_now;
  }

  hole->next_to_send = hole->hole_start;
#ifdef DEBUG_SNACK_OLD
  fprintf (trimFile, "     After hole reconciled:\n");
  printHoleChain (list);
#endif /* DEBUG_SNACK_OLD */
  return (list);
}


struct _hole_element *
add_hole (struct _hole_element *list, struct mbuff *hole_start,
	  uint32_t len, uint32_t tp_now1, uint32_t seq_num, uint32_t seqsent,
          uint32_t snack_delay)
{
  struct _hole_element *hole, *temp = 0x0;
#ifdef DEBUG_SNACK_OLD
  if (trimFile == NULL)
    trimFileOpen ();
  fprintf (trimFile, "%s add_hole list(%p), hole_start(%u), len(%u) seqsent(%u)\n",
	   stringNow (), list, ((unsigned) ((hole_start) ? hole_start->m_seq
					    : 0)), (unsigned) len, (unsigned) seqsent);
#endif /* DEBUG_SNACK_OLD */

  if (!(hole_start))
    return (list);

  tp_now1 = tp_now;

  hole = alloc_hole_element ();
  hole->hole_start = hole_start;
  if (len)
    {
      /*
       * This is on the sending side of things;
       * Find the last mbuff
       */

      /*
       * Make sure we trim the hole to seqsent.
       */
      if ( SEQ_GT(hole_start->m_seq+len, seqsent) ) {
        len = seqsent-hole_start->m_seq;
#ifdef DEBUG_HOLE
	printf("Trimming hole to (%lu:%lu) [%lu]\n",
		hole_start->m_seq, hole_start->m_seq+len, len);
#endif
      }

      hole->length = len;
      hole->hole_start_seq = hole_start->m_seq;
      hole->hole_end_seq = hole_start->m_seq + len;
      hole->next_to_send = hole->hole_start;
      hole->hole_end = hole_start;
      len -= hole->hole_end->m_ext.len;
      while ((((int) len) > 0) && (hole->hole_end->m_next))
	{
	  hole->hole_end = hole->hole_end->m_next;
	  len -= hole->hole_end->m_ext.len;
	}
      if (((int) len) > 0)
	hole->length -= len;

#ifdef DEBUG_SNACK_OLD
      fprintf (trimFile,
	       "     Added hole of length %d, start_seq, end_seq, length (%u, %u, %u)\n",
	       (int) len, hole->hole_start_seq, hole->hole_end_seq,
	       (unsigned) hole->length);
#endif /* DEBUG_SNACK_OLD */
    }
  else
    {
      /* This is a new hole on the receiving end of things */
      /* Find the hole's starting point... */
      if ((temp = list))
	{
	  while ((temp) && (temp->next) &&
		 (hole_start->m_seq > temp->data_end_seq))
	    temp = temp->next;

	  seq_num = temp->data_end_seq + 1;
	  temp = temp->next;
	}

      hole->hole_end = hole_start;
      hole->hole_start_seq = seq_num;
      hole->hole_end_seq = hole->hole_start->m_seq;
      hole->length = hole->hole_end_seq - hole->hole_start_seq;
      hole->data_length = hole_start->m_ext.len;
      hole->data_start_seq = hole_start->m_seq;
      hole->data_end_seq = hole_start->m_seq + hole->data_length;

      if (temp)
	{
	  temp->hole_start_seq = hole->data_end_seq + 1;
	  temp->length = temp->hole_end_seq - temp->hole_start_seq;
  	  if (snack_delay == 0) {
	       temp->Embargo_Time = 0;
	    } else {
	       temp->Embargo_Time = snack_delay + tp_now;
	    }
	}
    }

  if (snack_delay == 0) {
     hole->Embargo_Time = 0;
  } else {
     hole->Embargo_Time = snack_delay + tp_now;
  }

  if (hole->length)
    temp = insert_hole (list, hole, tp_now1, snack_delay);
  else
    temp = list;
  VERIFY_HOLE (temp);
  return (temp);
}

struct _hole_element *
remove_hole (struct _hole_element *list, struct _hole_element *hole)
{
  if (!(list) || (!(hole)))
    {
      if (hole)
	free_hole_element (hole);
      return (0x0);
    }

  if (hole->prev)
    {
      hole->prev->next = hole->next;
      if (hole->next)
	hole->next->prev = hole->prev;
    }

  else if (hole == list)
    {
      if (hole->next)
	hole->next->prev = 0x0;
      list = hole->next;
    }
  free_hole_element (hole);
  return (list);
}

/* Remove 0 or more holes below seqnum - this doesn't free the
   storage, since it's freed by mb_trim */
struct _hole_element *
trim_hole (struct _hole_element *list, uint32_t seqnum)
{
  if ((list) && SEQ_GT (seqnum, list->hole_start_seq))
    {				/* for debugging only */
      while ((list) && SEQ_GEQ (seqnum, list->hole_end_seq))
	list = remove_hole (list, list); /* PDF added list = 7/30/1999 */

      if ((list) && SEQ_GT (seqnum, list->hole_start_seq))
	{
	  list->length = list->hole_end_seq - seqnum;
	  list->hole_start_seq = seqnum;
	  while ((list->hole_start != list->hole_end) &&
		 SEQ_LT (list->hole_start->m_seq + list->hole_start->m_ext.len,
			 seqnum))
	    list->hole_start = list->hole_start->m_next;
	}
    }				/* if (list) */
  return (list);
}


/* Search a list for a hole *containing* seqnum */
struct _hole_element *
find_hole (struct _hole_element *list, uint32_t seqnum)
{
  struct _hole_element *hole = 0x0;

  if (!(list))
    return (0x0);

  hole = list;
  while ((hole) && (SEQ_LT (hole->hole_start_seq, seqnum)))
    hole = hole->next;

  if ((hole) && (SEQ_GT (seqnum, hole->hole_end_seq)))
    hole = 0x0;

  return (hole);
}


/*
 * Attaches an existing cluster to an existing mbuff, and sets the begining
 * of the data to point to an appropriate offset into the cluster.
 * 
 * Data may span across contiguous clusters, the mbuffer will point to the
 * starting cluster, but all the memory routines will handle it properly,
 * including reference count operations.
 * 
 * Note: Because of the "Swiss-Army-Knife" nature of this routine, the value of
 * the len field has different meanings... I hate this and wish I could find
 * a more acceptable way of handling things, but code size and runtime
 * footprint is my overwhelming driver at this point - Sorry.
 * 
 * The following two fields always have the following meaning: mbuff        *m:
 * Pointer to the target mbuff. mbcluster *clust: Pointer to the STARTING
 * cluster of the data to be attached (the data may span more one cluster).
 * The usage rules for the following fields are as follows: Normal Operations
 * (Attaching chunks of buffer-space of size 'len' to mbuffer 'm'): int
 * offset:  An absolute offset from the begining of clust. Generally, this is
 * set to the value of chain->read_off int  len:     The length of the data
 * to be attached, if there is not enough data available in the cluster
 * chain, the call to mcput() will fail. int force = 0: Setting the value of
 * force = 0 indicates normal operations. Push/End-Of-Record Operations
 * (Forcing segmentation of data regardless of whether or not it is of
 * maximum-segment size). This type of operation will attach attach up to len
 * bytes of data to the mbuff m, bounded by the amount of valid data
 * remaining in the cluster. It will return the length of data attached.
 * maximum sized seqments and 0 or 1 "small segments" int offset:   An
 * absolute offset from the begining of clust. Generally, this is set to the
 * value of chain->read_off... int len:      The maximum length of the data
 * to be attached. Generally, this is set to the maximum allowable segment
 * size as in Normal Operations. int  force = 1: Setting the value of force =
 * 1 indicates the routine should operate in Push/End-Of-Record Operations
 * mode... Out-Of-Sequence Operations (Attaching non-contiguous data to
 * mbuffers for assignment to the out-of-sequence queue). This mode of
 * operation is identical to Normal Operations, but it doesn't do any "bounds
 * checking" on whether or not the request can be satisfied. It assumes that
 * the requested size is valid as int32_t as it does not exceed the overall
 * length of the cluster chain. int offset:  This offset is NOT an absolute
 * value, but rather a relative offset from clust->tail. There is rationale
 * for doing it this way - trust me... :) int len:     The length of data to
 * be attached, if this exceeds the amount space currently allocated to the
 * chain, it will fail. This is the  only check that is made! int force = 2:
 * Setting the value of force = 3 Indicates that the routine should operate
 * in Out-of-Sequence Operations mode...
 * ======================================================================
 * This routine was more or less rewritten 7.21.95 by Travis in the spirit of
 * "Urban Renewal"
 */

int
mcput (struct mbuff *m, struct mbcluster *clust, int offset, int len, int force)
{
  struct mbcluster *temp_clust, *temp_write_head;
  int temp_len, temp_write_off, difference;

  if (!(clust))
    {
      return (-1);		/* Illegal as the day is long! */
    }
  /* Setup the temporary cluster anchor and offsets */
  if (force == 3)
    {
      temp_clust = clust;
      temp_write_off = clust->parent->write_off;

      difference = offset;

      /*
       * Redundant code with that in cb_cpdatin - make it so later
       * (ie, function call)
       */

      /*
       * As we run through the buffer, we face three possibilities
       * for each iteration: 1. The remaining offset is more than a
       * cluster-size away from the current offset - In this case
       * we just move to the same position in the next cluster. 2.
       * The remaining offset is within the current cluster - In
       * this case, we just advance the write_offset to the correct
       * position and will terminate the loop at the next test. 3.
       * The remaining offset is less than a cluster-size away, but
       * crosses over a cluster boundary - To minimize code, we
       * allow case #2 to finish the positioning in the next
       * iteration of the loop. Here, we decrement the remaining
       * offset by the  amount left in this cluster, advance to the
       * next cluster and set the write_offset to be zero (the
       * start of the new cluster).
       */
      while ((difference) && (temp_clust))
	{
	  if (difference >= SMCLBYTES)
	    {
	      /* 
	       * Difference is greater than a cluster
	       * size in length, jump to same offset
	       * in next cluster.
	       */
	      difference -= SMCLBYTES;
	      temp_clust = temp_clust->c_next;
	    }
	  else if (difference < (SMCLBYTES - temp_write_off))
	    {
	      /* End is in this cluster */
	      temp_write_off += difference;
	      difference = 0;
	    }
	  else
	    {
	      /* 
	       * Difference is less than SMCLBYTES, but 
	       * spans a cluster boundary.
	       */
	      difference -= (SMCLBYTES - temp_write_off);
	      temp_write_off = 0;
	      temp_clust = temp_clust->c_next;
	    }
	}
      if (!(temp_clust))
	{
	  return (-1);		/* There is a BIG PROBLEM! */
	}
    }
  else
    {
      /* Short-circuit further processing if we can */
      if ((clust->parent->size == 0) ||
	  ((clust->parent->size < len) && (!force)))
	return (0);		/* We can't satisfy the request. */
      temp_clust = clust;
      temp_write_head = clust;
      temp_write_off = offset;
    }

  /*
   * Determine how much data we have available to attach to the
   * mbuffer. Compare it to the max the caller can handle, and take the
   * lesser value.
   */

  if (force == 3)
    {
      /* 
       * I used to trim the request to fit whatever was there...
       * I don't do this now - If your playing in the Out_of_Sequence
       * queue, I think it proper to be precise about what you are doing!
       */
      if ((offset + len) > (temp_clust->parent->bytes_beyond +
			    temp_clust->parent->size +
			    (SMCLBYTES - temp_clust->parent->write_off)))
	{
	  return (-1);
	}
    }
  else if (((force == 1) || (force == 2)) && (temp_clust->parent->size < len))
    len = temp_clust->parent->size;
 
  temp_len = len;
  /* First, Attach the initial cluster to the mbuff passed to us */

  m->m_ext.ext_buf = (caddr_t) temp_clust;
  m->m_ext.offset = (temp_write_off % SMCLBYTES);
  m->m_ext.len = len;
  m->m_flags |= M_EXT;
  m->m_ext.ext_size = SMCLBYTES;
  m->m_plen = len;
  temp_clust->c_count++;
  temp_clust->mbuffs++;

  /*
   * Next, update the cluster reference counts. If we bridge clusters,
   * this loop should update the reference counts accordingly
   */

  if (force != 3)
    {
      temp_len -= (SMCLBYTES - temp_write_off);
      while ((temp_clust) && (temp_len > 0))
	{
	  /* Need to go onto the next cluster */
	  temp_clust = temp_clust->c_next;
	  if (temp_clust)
	    {
	      temp_clust->c_count++;
	      temp_clust->mbuffs++;
	      offset = 0;
	    }
	  else
	    temp_len = 0;
	  temp_len -= SMCLBYTES;
	}
      return (len);
    }
  else
    {
      temp_len -= (SMCLBYTES - temp_write_off);
      while (temp_len > 0)
	{
	  /* Need to go onto the next cluster */
	  temp_clust = temp_clust->c_next;
	  if (temp_clust)
	    {
	      temp_clust->c_count++;
	      temp_clust->mbuffs++;
	      temp_len -= SMCLBYTES;
	    }
	  else
	    {
	      /* This is as far as we can go */
	      return (len);
	    }
	}
      return (len);
    }
}

/* Create new function to do non-destructive reads from a cluster */

int
clust_copy (struct mbcluster *cluster, caddr_t cp, int togo, int offset)
{
  int amount, ln_read;

  amount = ln_read = 0;

  /* Jump to the offset in the data to be read */

  while ((offset >= SMCLBYTES) && (cluster))
    {
      offset -= SMCLBYTES;
      cluster = cluster->c_next;
    }

  if (!(cluster))
    return (0);			/* We're hosed ! */

  /* Now, start copying data out until we're done */

  while ((togo > 0) && cluster)
    {
      if (togo >= (SMCLBYTES - offset))
	amount = SMCLBYTES - offset;
      else
	amount = togo;

      memcpy (cp, (cluster->c_data + offset), amount);
      ln_read += amount;
      cp += amount;
      togo -= amount;
      offset += amount;

      if (offset == SMCLBYTES)
	{
	  offset = 0;
	  cluster = cluster->c_next;
	}
    }

  return (ln_read);

}

/*
 * The logical way to handle this is to increase the size of the cluster
 * chain to the size required by len + offset (where offset is ALWAYS
 * relative to the current write_off position for the owning chain. Assign
 * any new clusters to the bytes beyond count. This value will be decremented
 * when we advance the write_head pointer for non-out-of-sequence operations.
 */

int
cb_cpdatin (struct _cl_chain *chain, caddr_t dp,
	    int len, int offset, int maxseg)
{
  int difference, written, size, temp_write_off;
  int temp = 0;
  struct mbcluster *temp_write_head;

  written = 0;

  if (chain->write_head == NULL)
    {

      /* Are we at the end of a chain, or on a fresh chain? */

      if (chain->start == NULL)
	{
	  if (!(grow_chain (chain, 1)))
	    {
	      return (-1);
	      /*
	       * If this failed, we really need to indicate an
	       * error #
	       */
	    }

	  chain->read_head = chain->write_head = chain->start;

	  /* Do reference counting thing */

	  chain->write_head->c_count = 1;
	  chain->read_off = chain->write_off = 0;
	}
      else
	{
	  /*
	   * We've got a read-head (chain-start), so, we just need to
	   * append a new cluster to chain for write-head.
	   */
	  if (!(grow_chain (chain, 1)))
	    {
	      return (-1);
	      /*
	       * If this failed, we really need to indicate an
	       * error #
	       */
	    }

	  chain->write_head = chain->last;

	  chain->write_off = 0;

	  if ((chain->read_off == SMCLBYTES) &&
	      (chain->read_head->c_next))
	    {
	      chain->read_off = 0;

	      chain->read_head = chain->read_head->c_next;

	      if (chain->start == chain->read_head->c_prev)
		trim_chain (chain);
	    }
	}
    }


  /* Now we've got a head cluster, lets start writing into it. */

  /* 
   * First, check to see if we're going to need more cluster space 
   * This is going to have to take into account the alignment overhead
   * of multiple segments when maxseg is odd. It will add 1-byte per
   * max-segsize.
   */

  if (maxseg)
    temp = (len / maxseg) + 1;

  while (((SMCLBYTES - chain->write_off) + chain->bytes_beyond)
	 < (offset + len + temp))
    {
      if (!((chain->num_elements < chain->max_elements) &&
	    (grow_chain (chain, 1))))
	{
	  return (-1);
	}
    }

  /*
   * Use different handles for the chain->write_head and
   * chain->write_off; Note, any operations we do that modify the
   * contents of temp_write_head ALSO modify the contents of
   * chain->write_head, so be careful!
   */

  temp_write_head = chain->write_head;
  temp_write_off = chain->write_off;

  /*
   * Now, we need to advance out position in the buffer to correspond
   * with the desired offset. We can short-circuit this for none
   * out-of-sequence operations which should be much more common.
   */

  if (offset)
    {
      difference = offset;
      /*
       * As we run through the buffer, we face three possibilities
       * for each iteration: 1. The remaining offset is more than a
       * cluster-size away from the current offset - In this case
       * we just move to the same position in the next cluster. 2.
       * The remaining offset is within the current cluster - In
       * this case, we just advance the write_offset to the correct
       * position and will terminate the loop at the next test. 3.
       * The remaining offset is less than a cluster-size away, but
       * crosses over a cluster boundary - To minimize code, we
       * allow case #2 to finish the positioning in the next
       * iteration of the loop. Here, we decrement the remaining
       * offset by the  amount left in this cluster, advance to the
       * next cluster and set the write_offset to be zero (the
       * start of the new cluster).
       */
      while (difference)
	{
	  if (difference >= SMCLBYTES)
	    {
	      difference -= SMCLBYTES;
	      temp_write_head = temp_write_head->c_next;
	    }
	  else if (difference < (SMCLBYTES - temp_write_off))
	    {
	      temp_write_off += difference;
	      difference = 0;
	    }
	  else
	    {
	      difference -= (SMCLBYTES - temp_write_off);
	      temp_write_off = 0;
	      temp_write_head = temp_write_head->c_next;
	    }
	}
    }

  /*
   * Now, the writing begins... Since we've prepositioned the
   * temp_write_head and temp_write_off,  all we need to is start
   * writing from there. If (offset == 0), then this will be the
   * current write_head's tail. We update the chain's write_off,
   * write_head and write_head->tail ONLY if the offset passed into the
   * routine is zero (signaling a regular sequential buffer write).
   */

  while ((len > 0) && (temp_write_head))
    {
      /*
       * If this fails because (chain->write_head == NULL) we
       * screwed-up
       */
      if (len > (SMCLBYTES - temp_write_off))
	size = SMCLBYTES - temp_write_off;
      else
	size = len;

      if ((maxseg) && (size > (maxseg - chain->run_length)))
	size = maxseg - chain->run_length;

      memcpy ((void *) (temp_write_head->c_data + temp_write_off),
	      dp, size);
      len -= size;
      dp += size;
      temp_write_off += size;

      if ((maxseg) && ((chain->run_length += size) == maxseg))
	{
	  chain->run_length = 0;
	  if (temp_write_off & 1)
	    temp_write_off++;
	}

      /* Update where the last byte of data is in the cluster */
      if (!offset)
	temp_write_head->tail += size;	/* Should be the same as
					 * write_off */
      written += size;

      if (temp_write_off >= SMCLBYTES)
	{
	  temp_write_head = temp_write_head->c_next;
	  temp_write_off = 0;

	  if (temp_write_head == NULL)
	    {
	      if ((chain->num_elements < chain->max_elements) &&
		  (grow_chain (chain, 1)))
		{
		  temp_write_head = chain->last;
		}
	    }

	  if ((!offset) && (chain->bytes_beyond))
	    chain->bytes_beyond -= SMCLBYTES;
	}
    }

  /*
   * The writing is finished, now update the chain if we are doing a
   * sequential write operation
   */

  if (!offset)
    {
      chain->write_head = temp_write_head;
      chain->write_off = temp_write_off;
      chain->size += written;
      if (chain->size > chain->biggest)
	chain->biggest = chain->size;
    }
  else if (offset)
    {
      chain->Out_Seq_size += written;
    }
  return (written);
}

/*
 * This routine copies data out of a cluster chain. 
 * It's primary (only?) use is by tp_Read().
 */

int
cb_cpdatout (struct _cl_chain *chain, caddr_t dp, unsigned int len)
{
  int size, to_read;
  static int timesCalled = 0;
  struct mbcluster *mbcluster = NULL;

  if ((chain->read_head == chain->write_head) &&
      (chain->read_off == chain->write_off)) {
    /* Nothing to read in the buffer... */
    return (0);
}

  timesCalled++;
  if (timesCalled == 24)
    {
      timesCalled = 24;
    }
  to_read = len;
  if (to_read > chain->size)
    {
      to_read = chain->size;
      len = chain->size;
    }

  while ((to_read > 0) && (chain->size > 0))
    {
      if ((to_read > (SMCLBYTES - chain->read_off)) &&
	  (SMCLBYTES != chain->read_off))
	{
	  size = SMCLBYTES - chain->read_off;
	}
      else
	{
	  size = to_read;
	}

      memcpy (dp, (chain->read_head->c_data + chain->read_off), size);
      dp += size;
      read_align (chain, size, 0);
      chain->size -= size;
      to_read -= size;

      if ((chain->read_off >= SMCLBYTES) && (chain->read_head->c_next))
	{
	  /* Move on to the next cluster */
	  chain->read_head = chain->read_head->c_next;
	  chain->read_off -= SMCLBYTES;
	  /* This should always be true, but... */
	  if (chain->start == chain->read_head->c_prev)
	    {
	      mbcluster = deq_mclus (chain);
	    }
	  else
	    {
	      printf ("Uh oh...\n");
	    }
	  /* Free it regardless */
	  free_mclus (mbcluster);

	  chain->read_off = 0;
	}
    }
  return (len);
}

/* Initialize structures of type _buffer */
struct _buffer *
buff_init (uint32_t max_size, void *parent)
{
  struct _buffer *buffer = (struct _buffer *) malloc (sizeof (struct _buffer));

  if (!buffer)
    {
      printf ("Buffer init failed\n");
      return (0x0);
    }

  buffer->max_size = (int32_t) max_size;
  buffer->b_size = 0;
  buffer->num_elements = 0;
  buffer->max_elements = (int32_t) max_size;
  buffer->biggest = 0;
  buffer->data_size = 0;
  buffer->biggest_elements = 0;
  buffer->flags = 0;
  buffer->start = buffer->last = NULL;
  buffer->snd_una = buffer->send = NULL;
  buffer->holes = NULL;
  buffer->parent = parent;
  return (buffer);
}

/* Initialize structures of type _cl_chain */
struct _cl_chain *
chain_init (uint32_t max_size)
{
  struct mbcluster *temp_clust;
  struct _cl_chain *chain;
  chain = (struct _cl_chain *) malloc (sizeof (struct _cl_chain));

  if (!chain)
    {
      syslog (LOG_ERR, "Gateway: Failed in chain init 1\n");
      return (0);
    }

  chain->max_size = (int32_t) max_size;
  chain->size = 0;
  chain->biggest = 0;
  chain->Out_Seq_size = 0;
  chain->num_elements = 0;
  chain->max_elements = (max_size / SMCLBYTES) + 2;
  chain->biggest_elements = 0;
  chain->bytes_beyond = 0;
  chain->run_length = 0;
  if ((temp_clust = alloc_mbclus (1)))
    {
      enq_mclus (temp_clust, chain);
      chain->read_head = chain->write_head = chain->start;
      /* Handle the reference counting */

      chain->write_head->c_count = 1;

      chain->read_off = chain->write_off = 0;
      chain->RB = NULL;
    } else {
      /* 
       * If we can't get the temporary cluster, free the chain and bail.
       */
      free(chain);
      chain = 0x0;
    }

  if (chain == 0)
    {
      syslog (LOG_ERR, "Gateway: Failed in chain init 3\n");
    }
  return (chain);
}

#define SEQ_LEQ(a,b)   ((int)((a)-(b)) <= 0)

/*
 * Free from the head of the buffer chain until we've freed up to limit
 * octets of associated data
 */
uint32_t
mb_trim (struct _buffer *buffer, uint32_t limit, uint32_t *tsp, uint32_t *rxm)
{
  struct mbuff *temp;
  uint32_t timestamp = 0;
  uint32_t ts1 = 0;
  uint32_t rexmits = 0;
  struct _hole_element *hole;
  struct mbcluster *mbcluster;

  int isLimit = 0;

#ifdef DEBUG_SNACK_OLD
  if (trimFile == NULL)
    trimFileOpen ();
#endif /* DEBUG_SNACK_OLD */

  if (buffer->snd_una)
    ts1 = buffer->snd_una->m_ts;

  /* 
   * We want to make sure any holes queued between 
   * (buffer->snd_una->m_seq and buffer->snd_una->m_seq + limit)
   */
  /* Now, make sure we don't have any dangling holes */

  if (buffer->holes)
    {

      // For debugging
      if ((limit == buffer->holes->hole_start_seq) || (limit ==
						       buffer->holes->hole_end_seq))
	{
	  isLimit = 1;
	}

      if (SEQ_GEQ (limit, buffer->holes->hole_start_seq))
	{
#ifdef DEBUG_SNACK_OLD
	  fprintf (trimFile,
		   "%s hole being acknowleged limit(%u) start(%u) end(%u) %c\n",
		   stringNow (),
		   (unsigned) limit, buffer->holes->hole_start_seq,
		   buffer->holes->hole_end_seq,
		   isLimit ? '*' : ' ');
	  fflush (trimFile);
#endif /* DEBUG_SNACK_OLD */
	}
      while ((buffer->holes) && SEQ_GEQ (limit, buffer->holes->hole_end_seq
					 - 1))
	{
#ifdef DEBUG_SNACK_OLD
	  fprintf (trimFile,
		   "      entire hole being acknowleged (before) limit(%u) start(%u) end(%u) %c\n",
		   (unsigned) limit, buffer->holes->hole_start_seq,
		   buffer->holes->hole_end_seq,
		   isLimit ? '*' : ' ');
#endif /* DEBUG_SNACK_OLD */
	  hole = buffer->holes;
	  buffer->holes = remove_hole (buffer->holes, hole);
	}
      /* Limit is the last byte of *data* that has been received (i.e., acknum - 1).  
       * The first byte of the hole following limit (limit+1) is the thing we're looking 
       * for here.  I think.
       */
      if ((hole = buffer->holes) &&
	  (SEQ_GEQ (limit, hole->hole_start_seq)) &&
	  (SEQ_LT (limit, hole->hole_end_seq - 1)))
	{
#ifdef DEBUG_SNACK_OLD
	  fprintf (trimFile,
		   "      partial hole being acknowleged limit(%u) start(%u) end(%u) %c\n",
		   (unsigned) limit, buffer->holes->hole_start_seq,
		   buffer->holes->hole_end_seq,
		   isLimit ? '*' : ' ');
	  if (hole->hole_start->m_next)
	    {
	      fprintf (trimFile,
		       "      first hole mbuff(%p) m_seq(%lu), len (%u), next(%p) m_seq(%lu), len (%u)\n",
		       hole->hole_start, hole->hole_start->m_seq, hole->hole_start->m_ext.len,
		       hole->hole_start->m_next,
		       hole->hole_start->m_next->m_seq, hole->hole_start->m_next->m_ext.len);
	    }
#endif /* DEBUG_SNACK_OLD */

	  /* trim off any full mbuffers that can be removed */
	  while ((((int) (hole->length)) > 0) &&
		 (SEQ_GEQ (limit + 1, hole->hole_start->m_seq + hole->hole_start->m_ext.len)))
	    {
	      hole->length -= hole->hole_start->m_ext.len;
	      /*
	       * If we're dragging hole->hole_start forward we have to
	       * be sure that hole->next_to_send is dragged forward
	       * as well.
	       */
	      if (hole->next_to_send == hole->hole_start)
		{
		  hole->next_to_send = hole->hole_start->m_next;
		}
	      hole->hole_start = hole->hole_start->m_next;
	      if (hole->hole_start)
		{
		  hole->hole_start_seq = hole->hole_start->m_seq;
		}
	      else
		{
		  hole->length = 0;
		}
#ifdef DEBUG_SNACK_OLD
	      fprintf (trimFile,
		       "      trimmed an mbuff from hole: new start(%u) end(%u) new length(%u) %c\n",
		       buffer->holes->hole_start_seq,
		       buffer->holes->hole_end_seq,
		       (unsigned) hole->length,
		       isLimit ? '*' : ' ');
#endif /* DEBUG_SNACK_OLD */
	    }

	  /* Now account for the possibility that the acknum may move hole_start_seq to the
	   * middle of an mbuffer (unfortunate, but possible).
	   */
	  if (SEQ_LT (hole->hole_start_seq, limit + 1))
	    {
	      hole->hole_start_seq = limit + 1;
	      hole->length = hole->hole_end_seq - hole->hole_start_seq;
#ifdef DEBUG_SNACK_OLD
	      fprintf (trimFile,
		       "    trim hole_start_seq and hole (hole_end_seq unchanged) (%u, %u) len=%u\n",
		       buffer->holes->hole_start_seq,
		       buffer->holes->hole_end_seq,
		       (unsigned) hole->length);
#endif /* DEBUG_SNACK_OLD */
	    }

	  if ( (hole->next_to_send) && (SEQ_LT (hole->next_to_send->m_seq, hole->hole_start->m_seq)) )
	    {
	      hole->next_to_send = hole->hole_start;
#ifdef DEBUG_SNACK_OLD
	      fprintf (trimFile, "     dragged next_to_send forward\n");
#endif /* DEBUG_SNACK_OLD */
	    }

	  if (((int) (hole->length)) <= 0)
	    {
#ifdef DEBUG_SNACK_OLD
	      fprintf (trimFile,
		       "      removing hole: start(%u) end(%u) length(%u) %c\n",
		       buffer->holes->hole_start_seq,
		       buffer->holes->hole_end_seq, (unsigned) hole->length,
		       isLimit ? '*' : ' ');
#endif /* DEBUG_SNACK_OLD */
	      buffer->holes = remove_hole (buffer->holes, hole);
	    }
	}
    }

  while ((buffer->snd_una) &&
	 (((buffer->snd_una->m_plen == 0) &&
	   SEQ_LEQ (buffer->snd_una->m_seq, limit)) ||
	  ((buffer->snd_una->m_plen != 0) &&
	   SEQ_LEQ ((buffer->snd_una->m_seq + buffer->snd_una->m_plen - 1),
		    limit))))
    {
      /* Check for boundary conditions! */
      timestamp = buffer->snd_una->m_ts;
      rexmits += buffer->snd_una->m_rx;

      if (buffer->snd_una->m_next)
	{
	  /* Free the buffer! */

	  if (buffer->last == buffer->snd_una)
	    buffer->last = NULL;

	  /* Decrement the instantaneous buffer size */

	  temp = deq_mbuff (buffer);
	  /* buffer->data_size -= temp->m_ext.len; */
	  buffer->snd_una = buffer->start;
	  temp->m_next = 0x0;
	  if (temp->m_flags & M_RUNT)
	    {
	      buffer->flags &= ~M_RUNT;
	      temp->m_flags &= ~M_RUNT;
	    }
	  free_mbuff (temp);
	}
      else
	{
	  /* This was the last buffer in the chain */
	  /* Decrement the instantaneous buffer size */

	  buffer->b_size--;
	  buffer->data_size -= buffer->snd_una->m_ext.len;
	  if (buffer->snd_una->m_flags & M_RUNT)
	    {
	      buffer->flags &= ~M_RUNT;
	      buffer->snd_una->m_flags &= ~M_RUNT;
	    }

	  free_mbuff (buffer->snd_una);
	  buffer->snd_una = buffer->start = buffer->last = NULL;
	}

      if (buffer->snd_una == buffer->send)
	buffer->snd_una = NULL;
    }

  /* Check to see if we are acknowledging just *part* of an mbuff's data */
  if ((buffer->snd_una) && (SEQ_GEQ (limit, buffer->snd_una->m_seq)))
    {
/*              printf("%s mb_trim got ack for part of an mbuff's data\n", stringNow(
));
 *                      fflush(stdout);
 */
      limit = limit - buffer->snd_una->m_seq + 1;
      buffer->snd_una->m_plen -= limit;
      buffer->snd_una->m_ext.len -= limit;
      buffer->snd_una->m_seq += limit;
      buffer->snd_una->m_ext.offset += limit;
      while (buffer->snd_una->m_ext.offset >= SMCLBYTES)
	{
	  buffer->snd_una->m_ext.offset -= SMCLBYTES;
	  mbcluster = (struct mbcluster *) buffer->snd_una->m_ext.ext_buf;
	  buffer->snd_una->m_ext.ext_buf = (caddr_t) mbcluster->c_next;
	  free_mclus (mbcluster);
	}

      /* Now we need to fix the prebuilt header(s) in the mbuff */

      fix_tp_header (((struct tp_socket *) buffer->parent),
		     buffer->snd_una);

      /* If this mbuffer is also at the start of a hole, we need
         to deal with that too... :o(  */
    }

  if (tsp)
    *tsp = ts1;
  if (rexmits)
    {
      if (rxm)
	*rxm = rexmits;
    }
#ifdef DEBUG_SNACK_OLD
  fflush (trimFile);
#endif /* DEBUG_SNACK_OLD */

#ifdef MFX_SND_UNA_HOLE
  /*
   * If we've moved acknum forward and there's a hole at the new value,
   * send the packet now (he'll get send multiple times).
   */
  if (buffer->holes)
    {
      buffer->holes->Embargo_Time = 0;
      buffer->holes->next_to_send = buffer->holes->hole_start;
    }
#endif /* MFX_SND_UNA_HOLE */

  return (timestamp);
}



/*
 * Free from the head of the buffer chain until we've freed upto limit octets
 * of associated data This one is receive_buffer centric...
 */
void
mb_rtrim (struct _buffer *buffer, uint32_t limit)
{
  struct mbuff *temp;
  struct mbcluster *mbcluster;

  /*
   * This is going to be slightly complicated, as we might be only
   * partially draining data associated with an mbuff, when this
   * happens, we need to update its m_seq field and NOT delete it.
   */

  /*
   * Boundary is the place we STOP pulling the elements off the queue 
   * Limit is 1 past the last octet we want to have read 
   */
  if (!(buffer->start))
    return;

  for (;;)
    {
      if ((limit > 0) && (limit >= buffer->start->m_plen))
	{

	  /*
	   * (limit == 0) is NOT really a bug, as BETS can  
	   * cause mb_rtrim to be called with a limit of 0 
	   */
	  /* Dequeue and free the buffer */

	  limit -= buffer->start->m_plen;
	  temp = deq_mbuff (buffer);
	  temp->m_next = 0x0;
	  free_mbuff (temp);

	  /* escape if we are out of mbuffs */

	  if (!(buffer->start))
	    {
	      BUG_HUNT (G_SOCK);
	      return;
	    }
	}
      else
	/*
	 * We're going to stop somewhere in the middle of
	 * this mbuff
	 */
	{
	  buffer->start->m_plen -= limit;
	  buffer->start->m_ext.len -= limit;
	  buffer->start->m_seq += limit;
	  buffer->start->m_ext.offset += limit;
	  while (buffer->start->m_ext.offset >= SMCLBYTES)
	    {
	      buffer->start->m_ext.offset -= SMCLBYTES;
	      mbcluster = (struct mbcluster *) buffer->start->m_ext.ext_buf;
	      buffer->start->m_ext.ext_buf = (caddr_t) mbcluster->c_next;
	      free_mclus (mbcluster);
	    }
	  BUG_HUNT (G_SOCK);
	  return;
	}
    }
}

/*
 * This routine will insert an mbuff into an existing mbuff-chain prior to an
 * indicated mbuff. If the indicated mbuff is NULL, the new mbuff will be
 * enqueued into the buffer.
 * 
 * Providing a NULL entry for *before will cause the new mbuff to be added to
 * the end of the list (creating a new list if required)
 */
int
mb_insert (struct _buffer *buffer, struct mbuff *before, struct mbuff *new)
{
  if (!before)
    return (enq_mbuff (new, buffer));	/* "New" list, reuse
					 * enq_mbuff code */
  else
    {
      if (buffer->b_size == buffer->max_size)
	return (0);
      if (before->parent != buffer)
	return (-1);		/* Set an errno for buffer, element
				 * mismatch! */
      new->m_next = before;
      new->m_prev = before->m_prev;
      if (before->m_prev)
	before->m_prev->m_next = new;
      before->m_prev = new;
      new->parent = buffer;
      new->parent->data_size += new->m_plen;
if (buffer ==  &(sys_memory.fblist)) {
printf ("in mb_insert in incrementing the freelist\n");
}
      return (++(buffer->b_size));
    }
}

/* This routine will merge two (or more) mbuffs into a single mbuff. */

int
mb_merge (struct mbuff *first, struct mbuff *second)
{
  int overslop;			/* The amount of data not in both first and second */

  /*
   * Don't trust that the call was made with first 
   * and second properly passed in!
   */

  if ((!(first && second)) || (first->m_seq > second->m_seq))
    return (-1);		/* Define an errno -  for use at
				 * "pseudo-kernel level" */

  /* 
   * Now for the great loop, starting from the "left" (first), attempt to
   * coalesce the first chunk of contiguous data. The loop ends when
   * we run out of mbuffs or they've got a gap between them.
   */

  for (; ((second) && (SEQ_GEQ ((first->m_seq + first->m_plen),
				second->m_seq)));)
    {

      /* 
       * Speed things up in the case where we are 
       * coalescing two buffers already in the Out_Seq queue.
       */

      if ((first->m_next == second) && (second->m_prev == first))
	{
	  /* 
	   * Simple, just grow first into second, and adopt the 
	   * second->m_next link. 
	   */

	  /* 
	   * if second's length is zero, odds are it's the FIN, 
	   * just leave quietly - we don't want any trouble 
	   */

	  if (second->m_plen == 0) {
		return(1);
	  }

	  overslop = (first->m_seq + first->m_plen) - second->m_seq;
	  if (overslop < 0)
	    overslop = 0;

	  first->m_plen += (second->m_plen - overslop);
	  first->m_ext.len += (second->m_plen - overslop);
	  first->parent->data_size -= overslop;
	  if ((first->m_next = second->m_next))
	    second->m_next->m_prev = first;

	  /* Check for a cluster usage overlap of the adjoining 
	   * segments; If the two segments have the same starting
	   * cluster, knock down the c_count of that cluster by one.
	   * We test for this case by checking second->m_ext.ext_offset
	   * If it is non-zero, then the first segment has SOME data
	   * in the same cluster as second's start, so we declare
	   * an overlap.
	   *
	   * Note: This much simpler overlap detection is credited to
	   * the eagle-eyes of Greg Miller. Many thanks to putting 
	   * many hours of debugging to use.
	   */

	  if (second->m_ext.offset)
	    {
	      ((struct mbcluster *) (second)->m_ext.ext_buf)->c_count--;
	    }

	  second->m_plen = 0;
	  second->m_ext.len = 0;
	  second->m_ext.ext_buf = NULL;

	  /* Subtract off second since we're freeing it */
	  first->parent->b_size--;
	  if (first->parent->last == second)
	    first->parent->last = first;
	  goto Free_It;
	}

      /* 
       * Calculate the overslop, We assume that second has the "bigger"
       * sequence number. We need to consider the special case where
       * first->m_seq == second->m_seq, we deal with this case first:
       */

      if (first->m_seq == second->m_seq)
	{
	  if (first->m_plen >= second->m_plen)
	    {
	      /* Second is completely within first */
	      if (!(first->parent))
		{
		  if (!(second->parent))
		    {
		      printf ("Busted! Going to die horribly now...\n");
		      printf ("wait for core dump use it for debugging\n");
		    }

		  first->parent = second->parent;

		  /* Copy the links */
		  if ((first->m_prev = second->m_prev))
		    first->m_prev->m_next = first;

		  if ((first->m_next = second->m_next))
		    first->m_next->m_prev = first;
		}

	      overslop = first->m_plen - second->m_plen;
	      first->parent->data_size += overslop;

	      if (first->parent->last == second)
		first->parent->last = first;
	      goto Free_It;
	    }

	  else
	    overslop = second->m_plen - first->m_plen;
	}
      else
	{
	  /*
	   * More general case: 
	   *    Second starts after First. 
	   *         o If second ends within first (including ending
	   *           at the same octet, there is nothing more to  
	   *           do here, other than dispose of second.
	   *           (If we wish to keep the "fresher" header, we 
	   *           need to do that here)
	   *         o Otherwise, second ends after first, and the
	   *           overlap is calculated to be the difference 
	   *           between second's ending sequence number and 
	   *           first's ending sequence number.
	   */

	  if (SEQ_GEQ ((first->m_seq + first->m_plen),
		       (second->m_seq + second->m_plen)))
	    {
	      if ((second->m_plen == 0) && (second->parent) &&
		  (second->m_next == NULL) &&
		  (second->parent->last == second))
		{
		  /* Special case here: Second happens to
		   * *look-like* an already enqueued FIN, so
		   * I will assume it is (I don't want to
		   * bother with cracking the transport
		   * header). In this case, I will simply
		   * insert the first guy in front of second.
		   * Leave quietly afterwards...
		   */

		  first->m_next = second;
		  first->m_prev = second->m_prev;
 		  if (first->m_prev) {
		  	first->m_prev->m_next = first;
                  }
		  second->m_prev = first;
		  first->parent = second->parent;
		  first->parent->b_size++;
		  first->parent->data_size += first->m_plen;
		  /* Leave now - you are done. */
		  return (1);
		}

	      /* 
	       * Second is completely within first,
	       * dump second and return 
	       */

	      if (second->m_plen <= 0)
		{
		  second->m_ext.ext_buf = NULL;
		  second->m_ext.len = 0;

                  if (!(first->parent))
                    {
                      if (!(second->parent))
                        printf ("Busted! Going to die now...\n");
                    }
 
                  /* Copy the links */
                  if ((first->m_prev = second->m_prev))
                    first->m_prev->m_next = first;
                  if ((first->m_next = second->m_next))
                    first->m_next->m_prev = first;
                  first->parent = second->parent;
 
 
                  if (first->parent->last == second) {
                    first->parent->last = second;
                    first->parent->last = first;
                  }

                  goto Free_It;
                }

	      if (!(first->parent))
		{
		  if (!(second->parent))
		    printf ("Busted! Going to die now...\n");

		  first->parent = second->parent;

		  /* Copy the links */
		  if ((first->m_prev = second->m_prev))
		    first->m_prev->m_next = first;
		  if ((first->m_next = second->m_next))
		    first->m_next->m_prev = first;
		}

	      overslop = first->m_plen - second->m_plen;
	      first->parent->data_size += overslop;
	      if (first->parent->last == second)
		first->parent->last = first;
	      goto Free_It;
	    }

	  else
	    {
	      overslop = (second->m_seq + second->m_plen) -
		(first->m_seq + first->m_plen);
	    }
	}

      if (overslop < 0)		/* Error! */
	{
	  second->m_plen = 0;
	  second->m_ext.len = 0;
	  second->m_ext.ext_buf = NULL;
	  if ( (first->parent) && (first->parent->last == second) )
	    first->parent->last = second;
	  goto Free_It;		/* We should never get here! */
	}

      /* Grow the first segment to include the second */

      first->m_ext.len += overslop;
      first->m_plen += overslop;

      /* 
       * Now, let's make sure we can safely free the second: 
       * Make sure we don't free the new stuff;
       * If we've got the case where they don't overlap clusters,
       * make sure we don't lose the new cluster!
       */

      second->m_ext.len -= overslop;
      second->m_plen -= overslop;

      /* Now, make sure that first has a parent */

      if (!(first->parent))
	{
	  if (!(second->parent))
	    {
	      printf ("The merge routine broken. Neither has a parent!\n");
	      return (-1);
//	      exit (1);
	    }
	  else
	    {
	      first->parent = second->parent;
	      /* 
	       * The overslop is ALREADY in the parent buffer, it
	       * has ALREADY been added into first->m_plen, so DON'T
	       * count it twice!
	       */
	      first->parent->data_size += (first->m_plen - overslop);
	    }
	}
      else
	first->parent->data_size += overslop;

      /* Now, keep any existing links */

      /* If first is the newbie, adopt second's previous link */
      if ((!(first->m_prev)) && (second->m_prev))
	{
	  first->m_prev = second->m_prev;
	  first->m_prev->m_next = first;
	  second->m_prev = NULL;
	}

      /* If second has a next link, we adopt it regardless */
      if (second->m_next)
	{
	  first->m_next = second->m_next;
	  first->m_next->m_prev = first;
	  second->m_next = NULL;
	}

      if (first->parent->last == second)
	first->parent->last = first;
      if (first->parent->start == second)
	first->parent->start = first;

    if (((tp_Header *) (second->m_pktdat))->flags & tp_FlagFIN) {
             ((tp_Header *) (first->m_pktdat))->flags |= tp_FlagFIN;
    }

    Free_It:
      /*
       * Freeing second should get rid of any 
       * duplicate cluster accounting 
       */
      free_mbuff (second);

      /* 
       * Now, we go to the top of the loop and see if we can merge
       * in the next fellow in the Out_Seq queue
       */
      second = first->m_next;
    }
  return (1);			/* Everything went OK */
}

void
read_align (struct _cl_chain *buffer, int increment, int strict)
{
  struct mbcluster *mbcluster = NULL;

  buffer->read_off += increment;

  if ((strict) && (buffer->read_off & 0x1))
    buffer->read_off++;

  while (buffer->read_off >= SMCLBYTES)
    {
      if ((buffer->read_head->c_next) &&
	  (buffer->read_head != buffer->write_head))

	{
	  buffer->read_off -= SMCLBYTES;
	  buffer->read_head = buffer->read_head->c_next;

	  /* This should always be true but... */
	  if (buffer->start == buffer->read_head->c_prev)
	    {
	      mbcluster = deq_mclus (buffer);
	    }
	  else
	    {
	      printf ("WARNING BAD BAD BAD %s %d\n", __FILE__, __LINE__);
	      abort ();
	    }
	  /* Free it regardless */
	  free_mclus (mbcluster);
	}
      else
	{
	  buffer->read_off = SMCLBYTES;
	  goto Loop_Exit;
	  /* return; */
	}
    }
Loop_Exit:
  if ((buffer->read_head == buffer->write_head) &&
      (buffer->read_off > buffer->write_off))
    {
      buffer->read_off = buffer->write_off;
    }
  /*      
   * You can't sanity check the buffer structure here because... there might
   * be mbuffs that point to the dequeued mbcluster which are about to get
   * snapped off after an mbtrim call that's coming up from higher in the
   * call chain.
   */
  return;
}

/* 
 * write_align maintains even-word alignment for a
 * buffer from the writer's perspective. If a 
 * write_align is going to happen, it must 
 * ALWAYS preceed a read-align!
 */

void
write_align (struct _cl_chain *buffer, int increment, int strict)
{
  struct mbcluster *mbcluster;

  buffer->write_off += increment;

  /* 
   * We must have built a packet to have done this, make sure
   * that the buffer->run_length is == 0 now...
   */

  /* buffer->run_length = 0; */

  if ((strict) && (buffer->write_off & 0x1))
    buffer->write_off++;

  while (buffer->write_off >= SMCLBYTES)
    {
      if ((!(buffer->write_head->c_next)) && (!(grow_chain (buffer, 1))))
	{
	  return;
	}
      else
	{
	  buffer->write_off -= SMCLBYTES;
	  buffer->write_head = buffer->write_head->c_next;
	  if (buffer->bytes_beyond)
	    buffer->bytes_beyond -= SMCLBYTES;
	}
    }

  if (buffer->read_off == SMCLBYTES)
    {
      buffer->read_off = 0;
      buffer->read_head = buffer->read_head->c_next;

      mbcluster = deq_mclus (buffer);
      free_mclus (mbcluster);
    }
}

int
grow_chain (struct _cl_chain *chain, int clusters_needed)
{
  struct mbcluster *mbcluster = 0x0;

  while (clusters_needed > 0)
    {
      if ((chain->num_elements >= chain->max_elements) ||
	  (!(mbcluster = alloc_mbclus (0))))
	{
	  return (0);
	}
      mbcluster->c_count = 1;
      if (!(enq_mclus (mbcluster, chain)))
	{
	  free_mclus (mbcluster);
	  return (0);
	}
      clusters_needed--;
      chain->bytes_beyond += SMCLBYTES;
    }
  return (1);
}

/* 
 * Note: trim chain currently removes a single cluster from the 
 * front of a chain, it will remove N clusters at some point
 * but it just wasn't too necessary yet...
 */
int
trim_chain (struct _cl_chain *chain)
{
  struct mbcluster *mbcluster;

  if ((mbcluster = deq_mclus (chain)))
    {
      free_mclus (mbcluster);
      return (1);
    }
  return (0);
}

/* Build an iovec representing the packet's data into a msghdr passed down */
int
buff_vec (struct mbuff *mbuf, struct msghdr *msg, int open_slots)
{
  /* 
   * Start at the begining of the data in the packet and create a new
   * iov entry each time we span a cluster. For now, assume we won't
   * overstep the size of the iov[] - very silly assumption 
   */

  int size;

  int vector_offset, temp_offset;
  struct mbcluster *temp_cluster;

  /* 
   * Return the length of the resulting vector 
   */

  /* Leave the proper number of slots open in the iov */
  vector_offset = open_slots;

  /*
   * There is no need to do this if there is no 
   * external data associated with this mbuffer 
   */
  if (mbuf->m_flags & M_EXT)
    {

      /*
       * This is slightly complicated, since we might have multiple
       * clusters chained to this mbuffer. We can determine this
       * from the offset into the first cluster and the overall
       * data length.
       */


      size = mbuf->m_ext.len;

      vector_offset = open_slots;

      temp_cluster = (struct mbcluster *) mbuf->m_ext.ext_buf;
      temp_offset = mbuf->m_ext.offset;

      /* 
       * The first vector entry needs to point to the 
       * start of the referenced cluster data. This is 
       * the base data area in the cluster plus the proper
       * offset identified by in the mbuffer
       */

      /* Handle the initial element differently */

      msg->msg_iov[vector_offset].iov_base =
	((caddr_t) temp_cluster + mbuf->m_ext.offset);

      msg->msg_iov[vector_offset].iov_len =
	min (size, (SMCLBYTES - mbuf->m_ext.offset));

      size -= msg->msg_iov[vector_offset].iov_len;
      vector_offset = vector_offset + 1;

      while (size > 0)

	{
	  /* Need to cross one or more cluster boundaries... */

	  temp_cluster = temp_cluster->c_next;
	  msg->msg_iov[vector_offset].iov_base = (caddr_t) temp_cluster;
	  if (size > SMCLBYTES)
	    msg->msg_iov[vector_offset].iov_len = SMCLBYTES;
	  else
	    msg->msg_iov[vector_offset].iov_len = size;

	  size -= msg->msg_iov[vector_offset].iov_len;
	  vector_offset++;
	}
    }
  msg->msg_iovlen = vector_offset;
  return (msg->msg_iovlen);
}

/*
 * This routine will copy the contents of one mbuff into 
 * another mbuff. The data residing in an external cluster
 * is NOT duplicated, but merely referenced as in the original
 * mbuff. If you need to copy both the headers and the external
 * data, user clone_mbuff() instead.
 *
 * This routine is only used for non-debug purposes by the
 * persist function in tp_timers.c.  In that function, the
 * cluster references are zeroed out and the one byte of
 * probe data is actually shoved into the mbuf (the only
 * place in this code where data resides in an mbuf).
 * In that case, it is important not to update cluster
 * reference counts.  Hence the note below.
 */
void
copy_mbuff (struct mbuff *duplicate, struct mbuff *orig)
{
  memcpy (duplicate, orig, sizeof (struct mbuff));
  duplicate->m_ext = orig->m_ext;
  if ((duplicate->m_ext.ext_buf = orig->m_ext.ext_buf))
    {
      /* 
       * Properly attach the new cluster(s) to the mbuff
       */
      duplicate->m_data = duplicate->m_ext.ext_buf;
      duplicate->m_flags |= M_EXT;

      /* Durst - 7/29/1999 - Although it LOOKS like we need to update the reference count for all
       * clusters affected by this action, this is only called in situations
       * where we actually SHOULDN'T.  So don't worry.  Much.  Really.
       */
    }
}

#ifdef DEBUG
/*
 * This routine will clone one cluster/chain into another
 * The only callers of this routine should be internal, and
 * the only one using it to date is clone_mbuff()
 */

struct mbcluster *
clone_cluster (struct mbcluster *cluster, int original_offset, int length)
{
  int space, amount, new_offset;
  struct mbcluster *original_element, *new_head, *new_element;

  new_offset = 0;
  space = length;

  original_element = cluster;

  /* Sanity check to save some work, but get a new cluster */
  if ((!(cluster)) || (!(length)) || !(new_head = alloc_mbclus (0)))
    return (0x0);

  space -= SMCLBYTES;

  /* Now, get as many clusters as you might need */
  while (space > 0)
    {
      if (!(new_element = alloc_mbclus (0)))
	return (0x0);
      new_element->c_next = new_head;
      new_head->c_prev = new_element;
      new_head = new_element;
      space -= SMCLBYTES;
    }

  new_head->c_prev = 0x0;

  /*
   * At this point we have enough buffer space to duplicate the 
   * desired data space. We now perform a series of copies to 
   * make this happen. 
   */

  space = length;
  new_element = new_head;

  while (space)
    {
      /* Figure out how much I can copy in this spin */
      amount = min (space, (SMCLBYTES - max (original_offset, new_offset)));

      /* 
       * Copy the data from the old cluster(s) to the new 
       * We use clust_copy() here instead of a straight memcpy()
       * because we might be spanning a cluster at either the source
       * or the destination;
       */

      clust_copy (original_element, (new_element->c_data + new_offset),
		  amount, original_offset);

      /* Fix the respective offsets in the clusters */
      original_offset += amount;
      new_offset += amount;

      /* Check to see if either needs to jump to next cluster */

      if (original_offset == SMCLBYTES)
	{
	  original_element = original_element->c_next;
	  original_offset = 0;
	}

      if (new_offset == SMCLBYTES)
	{
	  new_element = new_element->c_next;
	  new_offset = 0;
	}

      /* Decrement how much more we need to copy */
      space -= amount;
    }

  return (new_head);
}

/* 
 * This routine clones an existing mbuff and the data in the associated
 * cluster. Unlike copy_mbuff, the data in the cluster is also duplicated
 * instead of just being referenced by the new mbuff.
 */

struct mbuff *
clone_mbuff (struct mbuff *orig)
{
  struct mbuff *new_mbuff;

  /*
   * If we can't get a new mbuff, we need to fail gracefully.
   */

  if (!(new_mbuff = alloc_mbuff (orig->m_type)))
    return (0x0);

  /*
   * First, duplicate the contents of the original mbuff 
   */
  copy_mbuff (new_mbuff, orig);

  /*
   * If there is external data associated with the original mbuff
   * we need to clone it for attachment to the new mbuff
   */
  if ((new_mbuff->m_ext.ext_buf =
       (caddr_t) clone_cluster ((struct mbcluster *) orig->m_ext.ext_buf,
				orig->m_ext.offset, orig->m_ext.len)))
    {
      /* 
       * Properly attach the new cluster(s) to the mbuff
       */
      new_mbuff->m_data = new_mbuff->m_ext.ext_buf;
      (((struct mbcluster *) (new_mbuff->m_ext.ext_buf))->c_count) = 1;
      new_mbuff->m_flags |= M_EXT;
      new_mbuff->m_ext.ext_size = SMCLBYTES;
    }
}
#endif /* DEBUG */
/*
 * struct mbuff *
 * mb_attach(struct mbuff *mbuffer, char *linear_space, int space_len)
 *
 * This routine will copy the contents of a linear 
 * buffer into clusterspace and attach the data to
 * an mbuffer. If no mbuffer is provided, one will
 * be allocated for use. 
 * 
 * This routine could be optimized (quite a bit) 
 * and not waste the data-area in the mbuffer. At this
 * time, the only caller/user of this routine is the 
 * SCPS-SP (Security Protocol) sp_dgram_request() function
 * for moving its linear packet-handling operations into
 * cluster-space for handling by the network protocol.
 *
 */

struct mbuff *
mb_attach (struct mbuff *mbuffer, char *linear_space, int space_len)
{
  struct mbcluster *new_head, *new_element;
  int to_copy, length, offset;

  /* Get an mbuff is one is not provided to us */

  if (!(mbuffer))
    {
      if (!(mbuffer = alloc_mbuff (MT_HEADER)))
	return (0x0);
    }

  /* 
   * Now, we want to copy the data from the 
   * linear_space into attached cluster(s)
   */

  length = space_len;

  /* Sanity check to save some work, but get a new cluster */
  if ((!(length)) || !(new_head = alloc_mbclus (0)))
    return (0x0);

  length -= SMCLBYTES;

  /* Now, get as many clusters as you might need */

  while (length > 0)
    {
      if (!(new_element = alloc_mbclus (0)))
	return (0x0);

      new_element->c_next = new_head;
      new_head->c_prev = new_element;
      new_head = new_element;
      length -= SMCLBYTES;
    }

  new_head->c_prev = 0x0;

  /* 
   * Properly attach the new cluster(s) to the mbuff
   */
  mbuffer->m_len = 0;
  mbuffer->m_offset = 0;
  mbuffer->m_ext.ext_buf = (caddr_t) new_head;
  mbuffer->m_data = mbuffer->m_ext.ext_buf;
  (((struct mbcluster *) (mbuffer->m_ext.ext_buf))->c_count) = 1;
  mbuffer->m_flags |= M_EXT;
  mbuffer->m_ext.ext_size = SMCLBYTES;
  mbuffer->m_ext.len = space_len;

  /* Start copying from the linear buffer into the clusters */

  new_element = new_head;
  offset = 0;

  while (space_len > 0)
    {
      to_copy = min (space_len, SMCLBYTES);
      memcpy (new_element->c_data,
	      (linear_space + offset), to_copy);
      space_len -= to_copy;
      offset += to_copy;
      new_element = new_element->c_next;
    }

  return (mbuffer);
}
