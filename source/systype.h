/*
 *
 * Stolen from Stevens, A.1
 *
 */

#ifdef unix
#define UNIX	1		/* BSD, Sys 5, not Xenix */
#ifndef BSD
#define BSD	1		/* this is a cheat */
#endif /* BSD */
#endif /* unix */
