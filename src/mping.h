#ifndef __MPING_H__
#define __MPING_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"
#include "mping_opt.h"
#include "mping_ns.h"

struct ping_info
{
  struct timespec time_sent;
  struct timespec time_recv;
  int count_recv;
  struct mping_addr daddr_send;
  struct mping_addr saddr_recv;
  int id;
  int seq;
  asyncns_query_t *asyncns_name_query;
};

static void
ping_showrecv_prepare (struct ping_context *pc, int idx, int numeric)
{
  struct ping_info *pi = pc->info + idx;
  int flags = 0;

  if (numeric)
    flags |= NI_NUMERICHOST;
  if ((pi->asyncns_name_query =
       asyncns_getnameinfo (pc->asyncns, &pi->saddr_recv.addr,
			    pi->saddr_recv.addrlen, flags, 1, 0)) == NULL)
    perror ("asyncns_getnameinfo");
}

static void
ping_showrecv_done (struct ping_context *pc, int idx)
{
  struct ping_info *pi = pc->info + idx;
  struct timespec rtt = (pi->time_recv.tv_sec == 0
			 && pi->time_recv.tv_nsec ==
			 0) ? timespec_zero () : timespec_sub (pi->time_recv,
							       pi->time_sent);
  char saddr_name[NI_MAXHOST];

  if (pi->asyncns_name_query == NULL)
    strcpy (saddr_name, "???");
  else
    {
      int err = asyncns_getnameinfo_done (pc->asyncns, pi->asyncns_name_query,
					  saddr_name, sizeof (saddr_name),
					  NULL, 0);
      if (err == EAI_AGAIN)
	return;
      if (err != 0)
	{
	  fprintf (stderr, "asyncns_getnameinfo_done: %s\n",
		   gai_strerror (err));
	  strcpy (saddr_name, "???");
	}
    }

  pi->asyncns_name_query = NULL;
  printf ("%s %ld.%06ld %d\n", saddr_name, rtt.tv_sec,
	  rtt.tv_nsec / 1000, pi->count_recv);
  if (pi->count_recv == 0)
    pi->count_recv = 1;
}

static int
get_addr (const char *node, struct sockaddr *saddr, socklen_t * saddrlen,
	  int ipv4, int ipv6, int numeric)
{
  struct addrinfo *addrinfo, hints, *ai;
  int err;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  if (ipv4 && !ipv6)
    hints.ai_family = AF_INET;
  if (!ipv4 && ipv6)
    hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = 0;
  if (numeric)
    hints.ai_flags |= AI_NUMERICHOST;

  if ((err = getaddrinfo (node, NULL, &hints, &addrinfo)) != 0)
    {
      fprintf (stderr, "%s: %s\n", node, gai_strerror (err));
      errno = 0;
      return -1;
    }
  ai = addrinfo;
  if (*saddrlen >= ai->ai_addrlen)
    {
      memcpy (saddr, ai->ai_addr, ai->ai_addrlen);
      *saddrlen = ai->ai_addrlen;
    }
  else
    {
      errno = ENOSPC;
      return -1;
    }
  freeaddrinfo (addrinfo);
  return 0;
}

#endif
