
/* Queue routines from PC/IP  (modified) */
/* 
 * Further modified by Mary Jo Zukoski (MITRE) 1995-1997
 *                     Pat Feighery (MITRE)    1997
 * for use with SCPS-NP
 */

/* General-purpose queue manipulation routines.  Contains the following
 * routines:
 *	q{e}_deq	dequeue and return first element from queue
 *	q{e}_del	delete element from queue
 *	q_find		determine whether an element is in a queue
 *	q_create	create a queue
 *	q_addh, q_addt	add to head or tail of queue
 *	q_adda		add to a queue after an element
 *	q_obliterate	Wipe out a queue
 *      q_tailcpy       returns a copy of the last element in the queue
 *      q_headcpy       returns a copy of the first element in the queue
 */

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include "q.h"
/* For use with SCPS code */
#include "scps.h"
#include "thread.h"
#include "scps_np.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: q.c,v $ -- $Revision: 1.5 $\n";
#endif

extern void free (void *ptr);
extern void *malloc (size_t size);


extern np_Internals np_Int;
q_elt *
qe_deq (q)

/* Dequeue and return the first element of the specified queue.  Returns
 * a pointer to the first element if any, or 0 if the queue is empty.
 *
 * Arguments:
 */

     register queue *q;
{
  q_elt *temp;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);
  if (q->q_len <= 0)
    {				/* queue empty? */
      sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
      return (NULL);
    }				/* yes, show none */
  if (q->q_head == q->q_head->qe_next)
    {				/* Caught my problem ... */
      q->q_head = NULL;
      q->q_tail = NULL;
      q->q_len = 0;
      sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
      return (NULL);
    }

  temp = q->q_head;
  q->q_head = q->q_head->qe_next;	/* else unlink */
  if (!q->q_head)		/* queue empty? */
    {
      /* yes, update tail pointer too */
      q->q_tail = NULL;
      if (q->q_len > 1)
	{
	  np_Int.total_proc_pkts -= (q->q_len - 1);
	}
      q->q_len = 1;		/* Will be decrimented shortly */
    }
  q->q_len--;			/* update queue length */

  if (q->q_len < q->q_min)
    q->q_min = q->q_len;

  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (temp);
}

caddr_t
q_deq (q)
     register queue *q;
{
  caddr_t data;
  register q_elt *head;

  head = qe_deq (q);
  if (!head)
    return (NULL);
  data = head->qe_data;

/* Change by Forrest Palmer - Feb. 3, 1992
 * This routine must use `cfree' rather than `free' because queue elements
 * are created with `calloc' via the `sim_calloc' routine.
 *
 * Original line:
 */
  free ((char *) head);
  /* cfree(head, 1, sizeof(q_elt));  */
  return (data);
}


int
qe_del (q, elt)

/* Delete the specified element from the queue.  This requires scanning
 * the queue from the top to find and remove the element, so it takes
 * O(queue length) time to execute.  Note that this routine must not
 * run at interrupt level.
 */

     register queue *q;		/* the queue */
     register q_elt *elt;	/* element to delete */
{
  register q_elt **tmp;		/* temp for chaining */

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);
  for (tmp = &q->q_head; *tmp; tmp = &((*tmp)->qe_next))
    if (*tmp == elt)
      {
	if (q->q_tail == *tmp)
	  {			/* at end of queue? */
	    if (tmp == &q->q_head)	/* yes; if first elt, zero out tail */
	      q->q_tail = NULL;
	    else		/* otherwise tail is previous elt */
	      q->q_tail = (q_elt *) tmp;
	  }
	*tmp = (*tmp)->qe_next;	/* link it out of the queue */
	q->q_len--;		/* update element count */
	if (q->q_len < q->q_min)
	  q->q_min = q->q_len;
	sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
	return (1);
      }

  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (0);			/* not in queue, fail */
}

int
q_del (q, elt)
     register queue *q;
     register caddr_t elt;
{
  register q_elt **tmp, *qe;	/* temps for chaining */

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  for (tmp = &q->q_head; *tmp; tmp = &((*tmp)->qe_next))
    if ((*tmp)->qe_data == elt)
      {
	qe = *tmp;
	if (q->q_tail == qe)
	  {			/* at end of queue? */
	    if (tmp == &q->q_head)	/* yes; if first elt, zero out tail */
	      q->q_tail = NULL;
	    else		/* otherwise tail is previous elt */
	      q->q_tail = (q_elt *) tmp;
	  }
	*tmp = (*tmp)->qe_next;	/* link it out of the queue */
	q->q_len--;		/* update element count */
	if (q->q_len < q->q_min)
	  q->q_min = q->q_len;

	free ((char *) qe);

	sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
	return (1);
      }

  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (0);			/* not in queue, fail */
}


queue *
q_create ()			/* Modified 6/7/91 by N. Schult */
{
  register queue *q;

  q = (queue *) malloc (sizeof (queue));
  q->q_head = (q_elt *) NULL;
  q->q_tail = (q_elt *) NULL;
  q->q_len = 0;
  return (q);
}


/* Search the queue for a particular q_elt. */
q_elt *
qe_find (q, qe)
     register queue *q;
     register q_elt *qe;
{
  register q_elt *tmp;

  for (tmp = q->q_head; tmp; tmp = tmp->qe_next)
    if (tmp == qe)
      return (qe);

  return (NULL);
}


/* Procedure to determine if an element is in a queue.
   Returns NULL if not found, and the pointer if it is found. */
q_elt *
q_find (q, qe)
     register queue *q;
     register caddr_t qe;
{
  register q_elt *tmp;		/* temp for chaining */

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  for (tmp = q->q_head; !tmp || tmp->qe_data != qe; tmp = tmp->qe_next)
    if (!tmp)
      {
	sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
	return (NULL);		/* if not in queue, punt */
      }
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);

  return (tmp);
}


/* Addh, addt, & adda.  These are now all procedures instead of macros
   because I didn't want to sim_malloc() from a macro.
*/

q_elt *
q_addh (q, elt)
     register queue *q;
     register caddr_t elt;
{
  register q_elt *new = (q_elt *) malloc (sizeof (q_elt));
  /* register q_elt *new = (q_elt *)calloc(1, sizeof(q_elt));  */

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  new->qe_data = elt;

  new->qe_next = q->q_head;
  if (!q->q_head)
    {
      q->q_len = 0;		/* Let's be sure */
      q->q_head = new;
      q->q_tail = new;
      new->qe_next = (q_elt *) NULL;	/* Added 6/25/91 */
    }
  else
    {
      new->qe_next = q->q_head;
      q->q_head = new;
    }
  if (++q->q_len > q->q_max)
    q->q_max = q->q_len;

  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (new);
}

q_elt *
q_addt (q, elt)
     register queue *q;
     register caddr_t elt;
{
/*  register q_elt *new = (q_elt *)calloc(1, sizeof(q_elt)); */
  register q_elt *new = (q_elt *) malloc (sizeof (q_elt));

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  new->qe_data = elt;
  new->qe_next = (q_elt *) NULL;	/* Added 6/25/91 */

  if (!q->q_head)
    {
      q->q_len = 0;		/* Let's be sure */
      q->q_head = new;
      q->q_tail = new;
    }
  else
    q->q_tail->qe_next = new;
  q->q_tail = new;
  if (++q->q_len > q->q_max)
    q->q_max = q->q_len;

  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (new);
}

/* q_adda and q_dela are both O(n) */

/* If prev == NULL, then new is added to the head of the queue. */
q_elt *
q_adda (q, prev, new)
     register queue *q;
     register caddr_t prev, new;
{
  register q_elt *found = NULL;
  register q_elt *newqe = NULL;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  if (prev)
    {
      /* First find data in the queue */
      if (!(found = q_find (q, prev)))
	{
	  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
	  return (NULL);	/* Abort if not found */
	}
    }

  newqe = (q_elt *) malloc (sizeof (q_elt));
  newqe->qe_data = new;

  if (prev)
    {
      qe_adda (q, found, newqe);	/* Now add it in */
    }
  else
    {
      qe_addh (q, newqe);
    }
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (newqe);
}


/*  Routine to wipe out a queue and **ALL** the data in it. */
void
q_obliterate (q)
     register queue *q;
{
  register q_elt *qe, *next;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  for (qe = q->q_head; qe; qe = next)
    {
      next = qe->qe_next;
      free (qe->qe_data);

      free ((char *) qe);
    }

  free (q);
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
}

caddr_t
q_tailcpy (q)
     register queue *q;
{
/* Be *real* careful using this routine.  I don't like providing it, but
   for now, I need to examine the upper limits of my buffers - that requires
   LOOKING at the last element in the queue;   Remember, don't do anything
   with this pointer (especially freeing it!!)                             */

  if (q->q_tail == NULL)
    return (NULL);
  else
    return (q->q_tail->qe_data);
}

caddr_t
q_headcpy (q)
     register queue *q;
{
/* Be *real* careful using this routine.  I don't like providing it, but
   for now, I need to examine the upper limits of my buffers - that requires
   LOOKING at the last element in the queue;   Remember, don't do anything
   with this pointer (especially freeing it!!)                             */

  if (q->q_head == NULL)
    return (NULL);
  else
    return (q->q_head->qe_data);
}
