#ifndef __MPING_SOCK_H__
#define __MPING_SOCK_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct mping_socket
{
  int sock4;
  int sock6;
};

static struct mping_socket
mping_socket_new ()
{
  struct mping_socket sock;
  int errno4, errno6;

  sock.sock4 = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  errno4 = errno;
  sock.sock6 = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  errno6 = errno;

  if (sock.sock4 == -1 && sock.sock6 == -1)
    {
      fprintf (stderr, "socket(IPv4): %s\n", strerror (errno4));
      fprintf (stderr, "socket(IPv6): %s\n", strerror (errno6));
      exit (EXIT_FAILURE);
    }

  if (sock.sock4 != -1)
    {
      int off = 0;

      if (setsockopt (sock.sock4, IPPROTO_IP, IP_HDRINCL, &off, sizeof (off))
	  == -1)
	{
	  perror ("setsockopt(IP_HDRINCL, 0)");
	  exit (EXIT_FAILURE);
	}
    }

  return sock;
}

static void
mping_socket_set_ttl (struct mping_socket sock, int ttl)
{
  if (sock.sock4 != -1)
    {
      if (setsockopt (sock.sock4, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl)) ==
	  -1)
	{
	  fprintf (stderr, "setsockopt(IP_TTL, %d): %s", ttl,
		   strerror (errno));
	  exit (EXIT_FAILURE);
	}
    }
  if (sock.sock6 != -1)
    {
      if (setsockopt
	  (sock.sock6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,
	   sizeof (ttl)) == -1)
	{
	  fprintf (stderr, "setsockopt(IPV6_UNICAST_HOPS, %d): %s", ttl,
		   strerror (errno));
	  exit (EXIT_FAILURE);
	}
    }
}

static void
mping_socket_destory (struct mping_socket sock)
{
  if (sock.sock4 != -1)
    close (sock.sock4);
  if (sock.sock6 != -1)
    close (sock.sock6);
}

#endif
