/*
  This is unclassified Government software.

  The SCPS File Protocol (SCPS-FP) software was developed under
  contract to the Jet Propulsion Laboratory, an operating division of
  the California Institute of Technology and is available for use by
  the public without need of a licence.

  DISCLAIMER:

  THE SCPS-FP SOFTWARE AND RELATED MATERIALS ARE PROVIDED "AS-IS"
  WITHOUT WARRANTY OR INDEMNITY OF ANY KIND INCLUDING ANY WARRANTIES
  OF USE, PEROFMRNACE, OR MERCHANTABILITY OR FITNESS FOR A PRTICULAR
  USE OR PURPOSE (as set forth in UCC section 2312-2313) OR FOR ANY
  PURPOSE WHATSOEVER.

  USER BEARS ALL RISK RELATING TO USE, QUALITY, AND PERFORMANCE OF THE
  SOFTWARE.

  The Jet Propulsion Laboratory, the California Institute of
  Technology, and the United States government retain a paid-up
  royalty free world wide license in this product.

  SAIC Disclaimer:
    (1) SAIC assumes no legal responsibility for the source code and
        its subsequent use.
    (2) No warranty or representation is expressed or implied.
    (3) Portions (e.g. Washington University FTP Replacement Daemon)
        are copyright (c) Regents of the University of California.
	All rights reserved.  Restrictions included in said copyright
	are also applicable to this release.

*/
/*
 * Copyright (c) 1983, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)ftp.h	5.5 (Berkeley) 6/1/90
 */
/* $Id: ftp.h,v 1.7 1999/11/22 15:52:43 scps Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/ftp.h,v 1.7 1999/11/22 15:52:43 scps Exp $ */

/*
 * Definitions for FTP
 * See RFC-765
 */

/*
 * Reply codes.
 */
#define PRELIM		1	/* positive preliminary */
#define COMPLETE	2	/* positive completion */
#define CONTINUE	3	/* positive intermediate */
#define TRANSIENT	4	/* transient negative completion */
#define ERROR		5	/* permanent negative completion */

/*
 * Type codes
 */
#define	TYPE_A		1	/* ASCII */
#define	TYPE_E		2	/* EBCDIC */
#define	TYPE_I		3	/* image */
#define	TYPE_L		4	/* local byte size */

#ifdef FTP_NAMES
char *typenames[] =
{"0", "ASCII", "EBCDIC", "Image", "Local"};
#endif

/*
 * Form codes
 */
#define	FORM_N		1	/* non-print */
#define	FORM_T		2	/* telnet format effectors */
#define	FORM_C		3	/* carriage control (ASA) */
#ifdef FTP_NAMES
char *formnames[] =
{"0", "Nonprint", "Telnet", "Carriage-control"};
#endif

/*
 * Structure codes
 */
#define	STRU_F		1	/* file (no record structure) */
#define	STRU_R		2	/* record structure */
#define	STRU_P		3	/* page structure */
#ifdef FTP_NAMES
char *strunames[] =
{"0", "File", "Record", "Page"};
#endif

/*
 * Mode types
 */
#define	MODE_S		1	/* stream */
#define	MODE_B		2	/* block */
#define	MODE_C		3	/* compressed */
#ifdef FTP_NAMES
char *modenames[] =
{"0", "Stream", "Block", "Compressed"};
#endif

/*
 * Record Tokens
 */
#define	REC_ESC		'\377'	/* Record-mode Escape */
#define	REC_EOR		'\001'	/* Record-mode End-of-Record */
#define REC_EOF		'\002'	/* Record-mode End-of-File */

/*
 * Block Header
 */
#define	BLK_EOR		0x80	/* Block is End-of-Record */
#define	BLK_EOF		0x40	/* Block is End-of-File */
#define BLK_ERRORS	0x20	/* Block is suspected of containing errors */
#define	BLK_RESTART	0x10	/* Block is Restart Marker */

#define	BLK_BYTECOUNT	2	/* Bytes in this block */

#ifdef MSVC
/*  macros taken from telnet.h:  saves having a
 *  separate file.  */
#define	IAC	255		/* interpret as command: */
#define	DM	242		/* data mark--for connect. cleaning */
#define	IP	244		/* interrupt process--permanently */

#endif
