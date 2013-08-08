/* Define __P() macro, if necessary */
#ifndef __P
#if __STDC__
#define __P(protos) protos
#else /*  __STDC__ */
#define __P(protos) ()
#endif /* __STDC__ */
#endif /* __P */

/* inline foo */
#ifdef __GNUC__
#define inline __inline
#else /* __GNUC__ */
#define inline
#endif /* __GNUC__ */

/*
 * Handle new and old "dead" routine prototypes
 *
 * For example:
 *
 *	__dead void foo(void) __attribute__((volatile));
 *
 */
#ifdef __GNUC__
#ifndef __dead
#define __dead volatile
#endif /* __dead */
#if __GNUC__ < 2  || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#ifndef __attribute__
#define __attribute__(args)
#endif /* __attribute__ */
#endif /* __GNUC__ < 2  || (__GNUC__ == 2 && __GNUC_MINOR__ < 5) */
#else /* __GNUC__ */
#ifndef __dead
#define __dead
#endif /* __dead */
#ifndef __attribute__
#define __attribute__(args)
#endif /* __attribute__ */
#endif /* __GNUC__ */
