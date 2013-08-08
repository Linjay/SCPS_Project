#ifndef _memory_debugger
#define _memory_debugger
#include <stdlib.h>

#define HAVE_MEMMOVE 0

#ifdef DEBUG_MEMORY
/*
 *	These are the values for the status parameter
 *	of the ALLOCATIONINFO structure.
 */
#define MS_SHOULD_BE_FREED			0
#define MS_SHOULD_NOT_BE_FREED		1

#define MAXMEMFNAME	50


#define	MALLOC(b)				myMalloc((size_t) b, __FILE__, __LINE__);
#define	REALLOC(p, b)			myRealloc((void *) (p), (size_t) (b), __FILE__, __LINE__);
#define REGISTER_BLOCK(p, b)	registerBlock((void *)p, (size_t) b, __FILE__, __LINE__)
#define UPDATEBLOCKINFO(p, f, l) updateBlockInfo((p), (f), (l));
#define UNREGISTER_BLOCK(p)		unregisterBlock((void *)p, __FILE__, __LINE__)
#define MEMORY_CHECK(p)			memory_check((void *)p, __FILE__, __LINE__)

#define MEMMOVE(dest, source, size) myMemmove((dest), (source), (size_t) (size), __FILE__, __LINE__)
#define MEMCPY(dest, source, size) myMemmove((dest), (source), (size_t) (size), __FILE__, __LINE__)
#if 1
#define FREE(p)			myFree((void *)p, __FILE__, __LINE__);
#else
#define FREE(p)			{ myFree((void *) p, __FILE__, __LINE__); p = NULL; }
#endif

typedef struct Memory_AllocationInfo {
	void *	buffer;
	char  	file[MAXMEMFNAME];
        char    gComment[256];
	long		line;
	size_t	size;
	long		whichTime;
	int			status;
} MEMORYALLOCATIONINFO;

extern char globalComment[];

int			registerBlock(void *p, size_t b, char *file, int line);
void			updateBlockInfo(void *p, char *file, int line);
void			updateLastBlockInfo (char *file, int line);
int			purgeMemoryTracking();
int			unregisterBlock(void *p, char *file, int line);
int			memory_check(void *p, char *file, int line);

int			memory_checkpoint(MEMORYALLOCATIONINFO **theInfo);
int			newSince(MEMORYALLOCATIONINFO *theInfo, int num);

void 		myFree(void *p, char *file, int line);
void *		myMalloc(size_t b, char *file, int line);
void *		myRealloc(void *p, size_t b, char *file, int line);
void *		myMemmove(void *dest, const void *source, size_t size, char *file,
										int line);
int		 	logMemoryInfo();
int			inAllocatedSpace(void *p);
int			memoryUsed(size_t *currentUsed, size_t *maxUsed, size_t *overhead);
int			setMemoryTracking(int track);
int			getMemoryTracking(void);
int			pushMemoryTrackingStack();
int			pushMemoryTracking(int newState);
int			popMemoryTracking();
int			pushMemoryStatus(int newStatus);
int			popMemoryStatus();
int			setStatus(void *p, int status);
int			assertGoodMemoryStatus(int status);

void *
myBsearch(	const void *key,
			const void *base,
			size_t nel,
			size_t elemSize,
			int (*compar) (const void *p1, const void *p2),
			void **nextLower);

#else // DEBUG_MEMORY

#define MALLOC	malloc
#define REALLOC	realloc
#define FREE	free
#ifdef HAVE_MEMMOVE
#define MEMMOVE memmove
#else // HAVE_MEMMOVE
#define MEMMOVE memcpy
#endif // HAVE_MEMMOVE
#define MEMCPY memcpy
#define REGISTER_BLOCK(p,b)
#define UPDATEBLOCKINFO(p, f, l)
#define UNREGISTER_BLOCK(p)
#define setMemoryTracking(x)
#define getMemoryTracking(x)
#define inAllocatedSpace(x)
#define logMemoryInfo()
#define memoryUsed(a,b,c)
#define setStatus(a,b)

#endif // DEBUG_MEMORY

#endif
