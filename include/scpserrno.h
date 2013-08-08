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

/*
 * Error codes
 */

#ifndef _scps_errno_h
#define _scps_errno_h

#ifndef EPERM_XXX			/* Don't redefine the standard errors */

#define	SCPS_EPERM		1	/* Not owner */
#define	SCPS_ENOENT		2	/* No such file or directory */
#define	SCPS_ESRCH		3	/* No such process */
#define	SCPS_EINTR		4	/* Interrupted system call */
#define	SCPS_EIO		5	/* I/O error */
#define	SCPS_ENXIO		6	/* No such device or address */
#define	SCPS_E2BIG		7	/* Arg list too int32_t */
#define	SCPS_ENOEXEC		8	/* Exec format error */
#define	SCPS_EBADF		9	/* Bad file number */
#define	SCPS_ECHILD		10	/* No children */
#define	SCPS_EAGAIN		11	/* No more processes */
#define	SCPS_ENOMEM		12	/* Not enough core */
#define	SCPS_EACCES		13	/* Permission denied */
#define	SCPS_EFAULT		14	/* Bad address */
#define	SCPS_ENOTBLK		15	/* Block device required */
#define	SCPS_EBUSY		16	/* Mount device busy */
#define	SCPS_EEXIST		17	/* File exists */
#define	SCPS_EXDEV		18	/* Cross-device link */
#define	SCPS_ENODEV		19	/* No such device */
#define	SCPS_ENOTDIR		20	/* Not a directory */
#define	SCPS_EISDIR		21	/* Is a directory */
#define	SCPS_EINVAL		22	/* Invalid argument */
#define	SCPS_ENFILE		23	/* File table overflow */
#define	SCPS_EMFILE		24	/* Too many open files */
#define	SCPS_ENOTTY		25	/* Not a typewriter */
#define	SCPS_ETXTBSY		26	/* Text file busy */
#define	SCPS_EFBIG		27	/* File too large */
#define	SCPS_ENOSPC		28	/* No space left on device */
#define	SCPS_ESPIPE		29	/* Illegal seek */
#define	SCPS_EROFS		30	/* Read-only file system */
#define	SCPS_EMLINK		31	/* Too many links */
#define	SCPS_EPIPE		32	/* Broken pipe */

/* math software */
#define	SCPS_EDOM		33	/* Argument too large */
#define	SCPS_ERANGE		34	/* Result too large */

/* non-blocking and interrupt i/o */
#define	SCPS_EWOULDBLOCK	35	/* Operation would block */
#define	SCPS_EINPROGRESS	36	/* Operation now in progress */
#define	SCPS_EALREADY	37	/* Operation already in progress */
/* ipc/network software */

	/* argument errors */
#define	SCPS_ENOTSOCK	38	/* Socket operation on non-socket */
#define	SCPS_EDESTADDRREQ	39	/* Destination address required */
#define	SCPS_EMSGSIZE	40	/* Message too int32_t */
#define	SCPS_EPROTOTYPE	41	/* Protocol wrong type for socket */
#define	SCPS_ENOPROTOOPT	42	/* Protocol not available */
#define	SCPS_EPROTONOSUPPORT	43	/* Protocol not supported */
#define	SCPS_ESOCKTNOSUPPORT	44	/* Socket type not supported */
#define	SCPS_EOPNOTSUPP	45	/* Operation not supported on socket */
#define	SCPS_EPFNOSUPPORT	46	/* Protocol family not supported */
#define	SCPS_EAFNOSUPPORT	47	/* Address family not supported by protocol family */
#define	SCPS_EADDRINUSE	48	/* Address already in use */
#define	SCPS_EADDRNOTAVAIL	49	/* Can't assign requested address */

	/* operational errors */
#define	SCPS_ENETDOWN	50	/* Network is down */
#define	SCPS_ENETUNREACH	51	/* Network is unreachable */
#define	SCPS_ENETRESET	52	/* Network dropped connection on reset */
#define	SCPS_ECONNABORTED	53	/* Software caused connection abort */
#define	SCPS_ECONNRESET	54	/* Connection reset by peer */
#define	SCPS_ENOBUFS		55	/* No buffer space available */
#define	SCPS_EISCONN		56	/* Socket is already connected */
#define	SCPS_ENOTCONN	57	/* Socket is not connected */
#define	SCPS_ESHUTDOWN	58	/* Can't send after socket shutdown */
#define	SCPS_ETOOMANYREFS	59	/* Too many references: can't splice */
#define	SCPS_ETIMEDOUT	60	/* Connection timed out */
#define	SCPS_ECONNREFUSED	61	/* Connection refused */

	/* */
#define	SCPS_ELOOP		62	/* Too many levels of symbolic links */
#define	SCPS_ENAMETOOLONG	63	/* File name too int32_t */

/* should be rearranged */
#define	SCPS_EHOSTDOWN	64	/* Host is down */
#define	SCPS_EHOSTUNREACH	65	/* No route to host */
#define	SCPS_ENOTEMPTY	66	/* Directory not empty */

/* quotas & mush */
#define	SCPS_EPROCLIM	67	/* Too many processes */
#define	SCPS_EUSERS		68	/* Too many users */
#define	SCPS_EDQUOT		69	/* Disc quota exceeded */

/* Network File System */
#define	SCPS_ESTALE		70	/* Stale NFS file handle */
#define	SCPS_EREMOTE		71	/* Too many levels of remote in path */

/* streams */
#define	SCPS_ENOSTR		72	/* Device is not a stream */
#define	SCPS_ETIME		73	/* Timer expired */
#define	SCPS_ENOSR		74	/* Out of streams resources */
#define	SCPS_ENOMSG		75	/* No message of desired type */
#define	SCPS_EBADMSG		76	/* Trying to read unreadable message */

/* SystemV IPC */
#define SCPS_EIDRM		77	/* Identifier removed */

/* SystemV Record Locking */
#define SCPS_EDEADLK		78	/* Deadlock condition. */
#define SCPS_ENOLCK		79	/* No record locks available. */

/* RFS */
#define SCPS_ENONET		80	/* Machine is not on the network */
#define SCPS_ERREMOTE	81	/* Object is remote */
#define SCPS_ENOLINK		82	/* the link has been severed */
#define SCPS_EADV		83	/* advertise error */
#define SCPS_ESRMNT		84	/* srmount error */
#define SCPS_ECOMM		85	/* Communication error on send */
#define SCPS_EPROTO		86	/* Protocol error */
#define SCPS_EMULTIHOP	87	/* multihop attempted */
#define SCPS_EDOTDOT		88	/* Cross mount point (not an error) */
#define SCPS_EREMCHG		89	/* Remote address changed */

/* POSIX */
#define SCPS_ENOSYS		90	/* function not implemented */

#endif /* EPERM */

/* SCPS */
#define SCPS_EBETS		128	/* Best Effort receipt with hole */
				       /* Check socket variable for size */
#define SCPS_ENOBETS         129	/* Best Effort unsupported on connect */
#define SCPS_ESOCKOUTSTATE	130	/* Socket in wrong state for this op */
#define SCPS_ESOCKINUSE	131	/* Socket is still in the chain */

/* NP ERRORS */
#define SCPS_ELENGTH         132	/* unsupported length */
#define SCPS_EREQADDR        133	/* error with requirements addr */
#define SCPS_ENODSTADDR      134	/* no dest addr where one expected */
#define SCPS_EDELIVER        135	/* pkt delivered in error */
#define SCPS_EIPV6           136	/* IPv6 not yet supported */
#define SCPS_EHOPCOUNT       137	/* hop count exceeded */
#define SCPS_ECHECKSUM       138	/* checksum error */
#define SCPS_ENOSRCADDR      139	/* no src addr where one expected */
#define SCPS_ETIMESTAMP      140	/* time stamp expired */
#define SCPS_EVERSION        141	/* unknown NP version */
#define SCPS_EBADMCLEN	142	/* bad multicast address length */
#define SCPS_EFILEOPEN	143	/* couldn't open file */
#define SCPS_ECORRUPTION	144	/* incoming SCMP corruption message */
#define SCPS_ESRCQUENCH	145	/* incoming SCMP source quench */
#define SCORRUPTION	146	/* outgoing SCMP corruption msg */
#define SSRCQUENCH	147	/* outgoing SCMP source quench */
#define SCPS_EBADTPID	148	/* unsupported TPID number */

#endif /*!_sys_errno_h */
