/*
 * get_local_internet_addr uses the gethostname function and 
 * gethostbyname function to retrieve the internet address of 
 * the local host (the first one encountered is used).  The 
 * host address is copied into the user-provided storage 
 * pointed to by the calling parameter.
 *
 *  usage:
 *  get_local_internet_addr(&place_to_stick_addr);
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/param.h>
#include <stdio.h>
#include "systype.h"
#include <syslog.h>
#include <string.h>

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: get_local_internet_addr.c,v $ -- $Revision: 1.11 $\n";
#endif

extern int gethostname (char *name, size_t namelen);
#ifdef SOLARIS
#ifndef _IN_ADDR_T
#define _IN_ADDR_T
typedef uint32_t in_addr_t;
#endif /* _IN_ADDR_T */
in_addr_t inet_addr (const char *cp);
#else /* SOLARIS */
uint32_t inet_addr (const char *cp);
#endif /* SOLARIS */


#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 80
#endif /* MAXHOSTNAMELEN */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif /* INADDR_NONE */

struct hostent *hp;
static char hostname[MAXHOSTNAMELEN + 1];
int temp;

int
get_local_internet_addr (char *storage)
{
  if (gethostname (hostname, sizeof (hostname)) == -1)
    {
      syslog (LOG_ERR, "get_local_internet_addr:  could not find local host name");
      return (-1);
    }
  hostname[MAXHOSTNAMELEN] = '\0';	/* null terminate */

  if ((hp = gethostbyname (hostname)) == NULL)
    {
      syslog (LOG_ERR, "gethostbyname error for %s\n", hostname);
      return (-1);
    }

  memcpy (storage, hp->h_addr, hp->h_length);
  return (0);
}

int32_t
get_remote_internet_addr (char *hostname)
{
  uint32_t temp_inaddr;

  if ((temp_inaddr = inet_addr (hostname)) != INADDR_NONE)
    return (temp_inaddr);
  else
    {
      if ((hp = gethostbyname (hostname)) == NULL)
	{
	  syslog (LOG_ERR, "Could not get remote internet address for %s", hostname);
	  exit (-1);
	}
      memcpy ((char *) &temp_inaddr, hp->h_addr, hp->h_length);
      return (temp_inaddr);
    }
}
