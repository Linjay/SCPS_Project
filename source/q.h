/* $Header: /home/cvsroot/SCPS_RI/source/q.h,v 1.7 1999/03/23 20:24:41 scps Exp $ */

#ifndef Q_H
#define Q_H

#include <sys/types.h>

/* Queue routines hacked from PC/IP software */

/*  Copyright 1983 by the Massachusetts Institute of Technology  */

/* Definitions for general-purpose queue manipulation package.
   Modified from Larry Allen's queue package from CSR Unix for TCP and
   tasks. */

typedef struct _q_elt
  {				/* queue element: cast to right type */
    struct _q_elt *qe_next;	/* it's just a pointer to next elt */
    caddr_t qe_data;		/* Pointer to stuff being stored */
  }
q_elt;

typedef struct _queue
  {				/* queue header */
    q_elt *q_head;		/* first element in queue */
    q_elt *q_tail;		/* last element in queue */
    /* int  dummy; */
    int q_len;			/* number of elements in queue */
    int q_max;			/* maximum length */
    int q_min;			/* minimum length */
  }
queue;

extern caddr_t q_deq (), q_tailcpy (), q_headcpy ();
extern queue *q_create ();
extern q_elt *q_find (), *q_addh (), *q_addt (), *q_adda (), *qe_find ();

/* Some queue operations implemented with following macros */
/* Is the queue empty? */

#define	q_empty(q)	((q)->q_len == 0)

/* Add an element to the head of the queue */

#define	qe_addh(q, elt) 	{ \
	if ((q)->q_head == NULL) (q)->q_tail = (q_elt *)(elt); \
	((q_elt *)(elt))->qe_next = (q)->q_head; \
	(q)->q_head = (q_elt *)(elt); \
	if(++((q)->q_len) > (q)->q_max) (q)->q_max = (q)->q_len; \
}

/* Add an element to the tail of a queue */

#define	qe_addt(q, elt)	{ \
	((q_elt *)(elt))->qe_next = NULL; \
	if ((q)->q_head == NULL) { \
                (q)->q_tail = (q_elt *)(elt); \
                ((q_elt *)(elt))->qe_next = (q)->q_head; \
		(q)->q_head = (q_elt *)(elt); \
                (q)->q_len = 0; \
	} else { \
		(q)->q_tail->qe_next = (q_elt *)(elt); \
	        (q)->q_tail = (q_elt *)(elt); \
	} \
	if(++((q)->q_len) > (q)->q_max) (q)->q_max = (q)->q_len; \
}

/* Add an element after a specified element in the queue.  If prev == */
/* &q->q_head, can be used to add an element to the head of the queue */

#define	qe_adda(q, prev, new)	{ \
	if ((q)->q_tail == (q_elt *)(prev) || (q)->q_tail == NULL) { \
		(q)->q_tail = (q_elt *)(new); \
	} \
	((q_elt *)(new))->qe_next = ((q_elt *)(prev))->qe_next; \
	((q_elt *)(prev))->qe_next = (q_elt *)(new); \
	if(++((q)->q_len) > (q)->q_max) (q)->q_max = (q)->q_len; \
}

/* Delete an element from a queue, given a pointer to the preceeding element */
/* Will delete the first element if prev == &q->q_head */

#define	qe_dela(q, prev)	{ \
	q_elt *next = ((q_elt *)(prev))->qe_next; \
	if ((q)->q_tail == next) { \
		if ((q)->q_head == next) \
			(q)->q_tail = NULL; \
		else \
			(q)->q_tail = (q_elt *)(prev); \
	} \
	((q_elt *)(prev))->qe_next = next->qe_next; \
	next->qe_next = 0; \
	if(--((q)->q_len) < (q)->q_min) (q)->q_min = (q)->q_len; \
}
#endif /* Q_H   */
