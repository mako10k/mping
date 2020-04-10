#ifndef __MPING_H__
#define __MPING_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <asyncns.h>

#include "config.h"

struct ping_addr
{
  union
  {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  };
  socklen_t addrlen;
};

struct ping_info
{
  struct timespec time_sent;
  struct timespec time_recv;
  int count_recv;
  struct ping_addr daddr_send;
  struct ping_addr saddr_recv;
  int id;
  int seq;
  asyncns_query_t *asyncns_name_query;
};

static struct timespec
ntots (long sec, long nsec)
{
  struct timespec ts = { sec, nsec };
  return ts;
}

#define PINGOPT_TTL_DEFAULT 30
#define PINGOPT_DATALEN_DEFAULT (64 - sizeof (struct icmphdr))
#define PINGOPT_INTERVAL_DEFAULT (ntots (1, 0))
#define PINGOPT_TIMEOUT_DEFAULT (ntots (0, 10000000))

struct ping_option
{
  int ipv4:1;
  int ipv6:1;
  int ttl:9;
  int numeric_print:1;
  int numeric_parse:1;
  unsigned int datalen:16;
  char *data;
  struct timespec interval;
  struct timespec timeout;
};

struct ping_context
{
  int sock4;
  int sock6;
  asyncns_t *asyncns;
  int asyncnsfd;
  int timeoutfd;
  int intervalfd;
  int id;
  struct ping_info *info;
  size_t infolen;
  int sndidx;
  struct ping_option opt;
};

// 1の補数和の１の補数(IP Checksum)
unsigned short
checksum (struct iovec *iov, size_t iovlen)
{
  unsigned long sum = 0;
  int k = 0;

  for (size_t i = 0; i < iovlen; i++)
    for (size_t j = 0; j < iov[i].iov_len; j++)
      sum += ((char *) iov[i].iov_base)[j] << (8 * (k++ & 1));
  sum = (sum & 65535) + (sum >> 16);
  sum = (sum & 65535) + (sum >> 16);
  return ~sum;
}

static int
icmp_setopt (struct ping_context *ctx)
{
  int flag;
  int ret;

#ifdef ICMP_FILTER
  flag = ~(1 << ICMP_ECHO | 1 << ICMP_ECHOREPLY);
  ret = setsockopt (ctx->sock4, IPPROTO_RAW, ICMP_FILTER, &flag,
		    sizeof (flag));
  if (ret != 0)
    return ret;
#endif
  flag = 0;
  ret = setsockopt (ctx->sock4, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag));
  if (ret != 0)
    return ret;
  if (ctx->opt.ttl >= 0)
    {
      int ttl = ctx->opt.ttl;

      ret = setsockopt (ctx->sock4, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl));
      if (ret != 0)
	return ret;
      if (ctx->opt.ipv6)
	{
	  ttl = ctx->opt.ttl;

	  ret =
	    setsockopt (ctx->sock6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,
			sizeof (ttl));
	  if (ret != 0)
	    return ret;
	}
    }

  return ret;
}

static ssize_t
icmp_echo_send (struct ping_context *ctx)
{
  struct msghdr msghdr;
  struct iovec iov[2];
  struct ping_info *pi;
  ssize_t ret;
  struct icmphdr icmphdr;
  struct icmp6_hdr icmp6_hdr;

  // 送信情報の組み立て
  pi = ctx->info + ctx->sndidx;

  pi->id = ctx->id;
  pi->seq = 0;

  // ヘッダ情報
  switch (pi->daddr_send.addr.sa_family)
    {
    case AF_INET:
      icmphdr.type = ICMP_ECHO;
      icmphdr.code = 0;
      icmphdr.checksum = 0;
      icmphdr.un.echo.id = htons (pi->id);
      icmphdr.un.echo.sequence = htons (pi->seq);

      // 送信情報の作成
      iov[0].iov_base = &icmphdr;
      iov[0].iov_len = sizeof (icmphdr);
      iov[1].iov_base = ctx->opt.data;
      iov[1].iov_len = ctx->opt.datalen;
      // チェックサムの計算
      icmphdr.checksum = checksum (iov, 2);

      break;
    case AF_INET6:
      icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
      icmp6_hdr.icmp6_code = 0;
      icmp6_hdr.icmp6_cksum = 0;
      icmp6_hdr.icmp6_id = htons (pi->id);
      icmp6_hdr.icmp6_seq = htons (pi->seq);

      // 送信情報の作成
      iov[0].iov_base = &icmp6_hdr;
      iov[0].iov_len = sizeof (icmp6_hdr);
      iov[1].iov_base = ctx->opt.data;
      iov[1].iov_len = ctx->opt.datalen;
      // チェックサムの計算
      icmp6_hdr.icmp6_cksum = checksum (iov, 2);

      break;
    }
  msghdr.msg_name = &pi->daddr_send.addr;
  msghdr.msg_namelen = pi->daddr_send.addrlen;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;

  // 送信時間の記録
  if (clock_gettime (CLOCK_REALTIME, &pi->time_sent) == -1)
    return -1;

  // 送信
  ret =
    sendmsg (pi->daddr_send.addr.sa_family ==
	     AF_INET ? ctx->sock4 : ctx->sock6, &msghdr, 0);
  if (ret != -1)
    {
      ctx->id++;
      ctx->sndidx++;
    }
  return ret;
}

static int
icmp4_echoreply_recv (struct ping_context *ctx)
{
  struct iphdr iphdr;
  struct icmphdr icmphdr;
  char data[65536];
  struct msghdr msghdr;
  struct iovec iov[3];
  struct sockaddr_in sin;

  memset (&msghdr, 0, sizeof (msghdr));
  // 受信情報の作成
  iov[0].iov_base = &iphdr;
  iov[0].iov_len = sizeof (iphdr);
  iov[1].iov_base = &icmphdr;
  iov[1].iov_len = sizeof (icmphdr);
  iov[2].iov_base = data;
  iov[2].iov_len = sizeof (data);
  msghdr.msg_name = &sin;
  msghdr.msg_namelen = sizeof (struct sockaddr_in);
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 3;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;
  int ret = recvmsg (ctx->sock4, &msghdr, 0);
  if (ret < 1)
    return ret;

  if (ret < sizeof (iphdr) + sizeof (icmphdr))
    {
      errno = EINVAL;
      return -1;
    }
  // PARSE IP HEADER
  if (iphdr.protocol != IPPROTO_ICMP)
    {
      errno = EAGAIN;
      return -1;
    }

  // PARSE ICMP HEADER
  if (icmphdr.type != ICMP_ECHOREPLY)
    {
      errno = EAGAIN;
      return -1;
    }

  // PING要求と引当
  for (int i = 0; i < ctx->sndidx; i++)
    {
      struct ping_info *pi = ctx->info + i;

      if (icmphdr.un.echo.id == htons (pi->id)
	  && icmphdr.un.echo.sequence == htons (pi->seq))
	{
	  if (ioctl (ctx->sock4, SIOCGSTAMPNS, &pi->time_recv) != 0)
	    return -1;
	  memcpy (&pi->saddr_recv.addr, msghdr.msg_name, msghdr.msg_namelen);
	  pi->saddr_recv.addrlen = msghdr.msg_namelen;
	  return i;
	}
    }

  // 応答が要求と異なる
  errno = EAGAIN;
  return -1;
}

static int
icmp6_echoreply_recv (struct ping_context *ctx)
{
  struct icmp6_hdr icmp6_hdr;
  char data[65536];
  struct msghdr msghdr;
  struct iovec iov[2];
  struct sockaddr_in6 sin6;

  memset (&msghdr, 0, sizeof (msghdr));
  // 受信情報の作成
  iov[0].iov_base = &icmp6_hdr;
  iov[0].iov_len = sizeof (icmp6_hdr);
  iov[1].iov_base = data;
  iov[1].iov_len = sizeof (data);
  msghdr.msg_name = &sin6;
  msghdr.msg_namelen = sizeof (struct sockaddr_in6);
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 3;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;
  int ret = recvmsg (ctx->sock6, &msghdr, 0);
  if (ret < 1)
    return ret;

  if (ret < sizeof (icmp6_hdr))
    {
      errno = EINVAL;
      return -1;
    }

  // PARSE ICMP HEADER
  if (icmp6_hdr.icmp6_type != ICMP6_ECHO_REPLY)
    {
      errno = EAGAIN;
      return -1;
    }

  // PING要求と引当
  for (int i = 0; i < ctx->sndidx; i++)
    {
      struct ping_info *pi = ctx->info + i;

      if (icmp6_hdr.icmp6_id == htons (pi->id)
	  && icmp6_hdr.icmp6_seq == htons (pi->seq))
	{
	  if (ioctl (ctx->sock6, SIOCGSTAMPNS, &pi->time_recv) != 0)
	    return -1;
	  memcpy (&pi->saddr_recv, msghdr.msg_name, msghdr.msg_namelen);
	  pi->saddr_recv.addrlen = msghdr.msg_namelen;
	  return i;
	}
    }

  // 応答が要求と異なる
  errno = EAGAIN;
  return -1;
}

static struct ping_option
po_defaults ()
{
  struct ping_option po;

  memset (&po, 0, sizeof (po));
  po.ttl = PINGOPT_TTL_DEFAULT;
  po.datalen = PINGOPT_DATALEN_DEFAULT;
  po.interval = PINGOPT_INTERVAL_DEFAULT;
  po.timeout = PINGOPT_TIMEOUT_DEFAULT;

  return po;
}

static int
ping_context_new (struct ping_context *pc, struct ping_option *po)
{
  pc->sock4 = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (pc->sock4 == -1)
    return -1;
  pc->sock6 = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (pc->sock6 == -1)
    {
      int _errno = errno;
      close (pc->sock4);
      errno = _errno;
      return -1;
    }
  pc->asyncns = asyncns_new (2);
  if (pc->asyncns == NULL)
    {
      int _errno = errno;
      close (pc->sock4);
      errno = _errno;
      return -1;
    }
  pc->asyncnsfd = asyncns_fd (pc->asyncns);
  if (icmp_setopt (pc) == -1)
    {
      int _errno = errno;
      close (pc->sock4);
      close (pc->sock6);
      asyncns_free (pc->asyncns);
      errno = _errno;
      return -1;
    }
  pc->timeoutfd = timerfd_create (CLOCK_MONOTONIC, 0);
  if (pc->timeoutfd == -1)
    {
      int _errno = errno;
      close (pc->sock4);
      close (pc->sock6);
      asyncns_free (pc->asyncns);
      errno = _errno;
      return -1;
    }
  pc->intervalfd = timerfd_create (CLOCK_MONOTONIC, 0);
  if (pc->intervalfd == -1)
    {
      int _errno = errno;
      close (pc->sock4);
      close (pc->sock6);
      close (pc->timeoutfd);
      asyncns_free (pc->asyncns);
      errno = _errno;
      return -1;
    }
  pc->id = getpid ();
  pc->info = NULL;
  pc->infolen = 0;
  pc->sndidx = 0;
  pc->opt = po ? *po : po_defaults ();
  return 0;
}

static void
ping_context_destory (struct ping_context *pc)
{
  close (pc->sock4);
  close (pc->sock6);
  asyncns_free (pc->asyncns);
  if (pc->timeoutfd != -1)
    close (pc->timeoutfd);
  if (pc->intervalfd != -1)
    close (pc->intervalfd);
}

#if 0
static struct timespec
timespec_add (struct timespec a, struct timespec b)
{
  struct timespec c;

  c.tv_sec = a.tv_sec + b.tv_sec;
  c.tv_nsec = a.tv_nsec + b.tv_nsec;
  if (c.tv_nsec >= 1000000000)
    {
      c.tv_sec++;
      c.tv_nsec -= 1000000000;
    }
  return c;
}
#endif

static struct timespec
timespec_sub (struct timespec a, struct timespec b)
{
  struct timespec c;

  if (a.tv_nsec < b.tv_nsec)
    {
      a.tv_sec--;
      a.tv_nsec += 1000000000;
    }
  c.tv_sec = a.tv_sec - b.tv_sec;
  c.tv_nsec = a.tv_nsec - b.tv_nsec;
  return c;
}

#if 0
static int
timespec_cmp (struct timespec a, struct timespec b)
{
  if (a.tv_sec == b.tv_sec)
    return a.tv_nsec - b.tv_nsec;
  return a.tv_sec - b.tv_sec;
}
#endif

static struct timespec
timespec_zero ()
{
  struct timespec ret = { 0, 0 };
  return ret;
}

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

static void
print_version (FILE * fp, int argc, char *argv[])
{
  fprintf (fp, "%s in %s (bug-report: %s)\n", basename (argv[0]),
	   PACKAGE_STRING, PACKAGE_BUGREPORT);
  fprintf (fp, "\n");
}

static void
print_usage (FILE * fp, int argc, char *argv[])
{
  fprintf (fp, "Usage:\n");
  fprintf (fp, "  %s [options] ipaddr ...\n", argv[0]);
  fprintf (fp, "\n");
  fprintf (fp, "Options:\n");
  fprintf (fp, "  -w timeout  : timeout for response\n");
  fprintf (fp, "  -i interval : interval to send\n");
  fprintf (fp, "  -s size     : payload data size\n");
  fprintf (fp, "  -d data     : payload data\n");
  fprintf (fp, "  -t ttl      : set ip time to live\n");
  fprintf (fp, "  -n          : printing by numeric host\n");
  fprintf (fp, "  -N          : don't resolve hostname\n");
  fprintf (fp, "  -4          : ipv4 only\n");
  fprintf (fp, "  -6          : ipv6 only\n");
  fprintf (fp, "  -v          : print version\n");
  fprintf (fp, "  -h          : print usage\n");
  fprintf (fp, "\n");
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

static struct timespec
dtots (double d)
{
  struct timespec ts;

  ts.tv_sec = d;
  ts.tv_nsec = (d - ts.tv_sec) * 1000000000;
  return ts;
}

#endif
