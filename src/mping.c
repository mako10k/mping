#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

struct ping_info
{
  struct sockaddr_in addr_sent;
  struct icmphdr icmphdr_sent;
  struct timespec time_sent;
  struct sockaddr_in saddr_recv;
  struct sockaddr_in daddr_recv;
  struct icmphdr icmphdr_recv;
  struct timespec time_recv;
  int count_recv;
};

struct ping_context
{
  int sock;
  int timeoutfd;
  int intervalfd;
  int id;
  struct ping_info *info;
  size_t infolen;
  int sndidx;
};

// 1の補数和の１の補数(IP Checksum)
unsigned short
checksum (struct iovec *iov, size_t iovlen)
{
  unsigned long sum = 0;
  int k = 0;

  for (int i = 0; i < iovlen; i++)
    {
      for (int j = 0; j < iov[i].iov_len; j++)
	{
	  sum += ((char *) iov[i].iov_base)[j] << (8 * (k++ & 1));
	}
    }
  sum = (sum & 65535) + (sum >> 16);
  sum = (sum & 65535) + (sum >> 16);
  return ~sum;
}

#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif

static int
icmp_setopt (struct ping_context *ctx)
{
  int flag = ~(1 << ICMP_ECHO | 1 << ICMP_ECHOREPLY);
  int ret = setsockopt (ctx->sock, IPPROTO_RAW, ICMP_FILTER, &flag,
			sizeof (flag));
  if (ret != 0)
    return ret;
  flag = 0;
  return setsockopt (ctx->sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag));
}

static ssize_t
icmp_echo_send (struct ping_context *ctx, char *data, size_t datalen)
{
  struct msghdr msghdr;
  struct iovec iov[2];
  struct ping_info *pi;
  ssize_t ret;

  // 送信情報の組み立て
  pi = ctx->info + ctx->sndidx;

  // ヘッダ情報 
  pi->icmphdr_sent.type = ICMP_ECHO;
  pi->icmphdr_sent.code = 0;
  pi->icmphdr_sent.checksum = 0;
  pi->icmphdr_sent.un.echo.id = htons (ctx->id);
  pi->icmphdr_sent.un.echo.sequence = 0;

  // 送信情報の作成
  iov[0].iov_base = &pi->icmphdr_sent;
  iov[0].iov_len = sizeof (pi->icmphdr_sent);
  iov[1].iov_base = data;
  iov[1].iov_len = datalen;
  // チェックサムの計算
  pi->icmphdr_sent.checksum = checksum (iov, 2);

  msghdr.msg_name = &pi->addr_sent;
  msghdr.msg_namelen = sizeof (pi->addr_sent);
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;

  // 送信時間の記録
  if (clock_gettime (CLOCK_REALTIME, &pi->time_sent) == -1)
    return -1;

  // 送信
  ret = sendmsg (ctx->sock, &msghdr, 0);
  if (ret != -1)
    {
      ctx->id++;
      ctx->sndidx++;
    }
  return ret;
}

static int
icmp_echoreply_recv (struct ping_context *ctx)
{
  struct iphdr iphdr;
  struct icmphdr icmphdr;
  char buf[65536 - sizeof (iphdr) - sizeof (icmphdr)];
  struct msghdr msghdr;
  struct iovec iov[3];
  struct sockaddr_in sin;

  memset (&msghdr, 0, sizeof (msghdr));
  // 送信情報の作成
  iov[0].iov_base = &iphdr;
  iov[0].iov_len = sizeof (iphdr);
  iov[1].iov_base = &icmphdr;
  iov[1].iov_len = sizeof (icmphdr);
  iov[2].iov_base = buf;
  iov[2].iov_len = sizeof (buf);
  msghdr.msg_name = &sin;
  msghdr.msg_namelen = sizeof (struct sockaddr_in);
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;
  int ret = recvmsg (ctx->sock, &msghdr, 0);
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
      if (icmphdr.un.echo.id == pi->icmphdr_sent.un.echo.id
	  && icmphdr.un.echo.sequence == pi->icmphdr_sent.un.echo.sequence)
	{
	  if (ioctl (ctx->sock, SIOCGSTAMPNS, &pi->time_recv) != 0)
	    return -1;
	  memcpy (&pi->icmphdr_recv, &icmphdr, sizeof (icmphdr));
	  memcpy (&pi->saddr_recv.sin_addr, &iphdr.saddr,
		  sizeof (iphdr.saddr));
	  memcpy (&pi->daddr_recv.sin_addr, &iphdr.daddr,
		  sizeof (iphdr.daddr));
	  return i;
	}
    }
  return -1;
}

static int
ping_context_new (struct ping_context *pc)
{
  pc->sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (pc->sock == -1)
    return -1;
  if (icmp_setopt (pc) == -1)
    {
      close (pc->sock);
      return -1;
    }
  pc->timeoutfd = timerfd_create (CLOCK_MONOTONIC, 0);
  if (pc->timeoutfd == -1)
    {
      close (pc->sock);
      return -1;
    }
  pc->intervalfd = timerfd_create (CLOCK_MONOTONIC, 0);
  if (pc->intervalfd == -1)
    {
      close (pc->sock);
      close (pc->timeoutfd);
    }
  pc->id = getpid ();
  pc->info = NULL;
  pc->infolen = 0;
  pc->sndidx = 0;
  return 0;
}

static void
ping_context_destory (struct ping_context *pc)
{
  close (pc->sock);
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
ping_showrecv (struct ping_context *pc, int idx)
{
  struct ping_info *pi = pc->info + idx;
  char daddr[INET_ADDRSTRLEN];
  char saddr[INET_ADDRSTRLEN];
  struct timespec rtt = (pi->time_recv.tv_sec == 0
			 && pi->time_recv.tv_nsec ==
			 0) ? timespec_zero () : timespec_sub (pi->time_recv,
							       pi->time_sent);
  const char *daddr_name;
  const char *saddr_name;

  if (pi->daddr_recv.sin_addr.s_addr == INADDR_ANY)
    daddr_name = "-";
  else
    daddr_name =
      inet_ntop (AF_INET, &pi->daddr_recv.sin_addr, daddr, sizeof (daddr));

  saddr_name =
    inet_ntop (AF_INET, &pi->saddr_recv.sin_addr, saddr, sizeof (saddr));

  printf ("%s %s %ld.%06ld %d\n", daddr_name, saddr_name, rtt.tv_sec,
	  rtt.tv_nsec / 1000, pi->count_recv);
}

int
main (int argc, char *argv[])
{
  struct ping_context ctx;
  int exitcode = EXIT_SUCCESS;
  int opt;
  double opt_double;
  char *p;
  struct timespec to_spec = { 1, 0 };
  struct timespec in_spec = { 0, 10000000 };

  while ((opt = getopt (argc, argv, "w:i:vh")) != -1)
    {
      switch (opt)
	{
	case 'w':
	  opt_double = strtod (optarg, &p);
	  if (p == optarg || *p != '\0')
	    {
	      fprintf (stderr, "error argument -%c %s\n", opt, optarg);
	      exit (EXIT_FAILURE);
	    }
	  to_spec.tv_sec = opt_double;
	  to_spec.tv_nsec = (opt_double - to_spec.tv_sec) * 1000000000;
	  break;
	case 'i':
	  opt_double = strtod (optarg, &p);
	  if (p == optarg || *p != '\0')
	    {
	      fprintf (stderr, "error argument -%c %s\n", opt, optarg);
	      exit (EXIT_FAILURE);
	    }
	  in_spec.tv_sec = opt_double;
	  in_spec.tv_nsec = (opt_double - in_spec.tv_sec) * 1000000000;
	  break;
	case 'v':
	case 'h':
	  printf ("%s version 0.1\n", argv[0]);
	  printf ("\n");
	  if (opt != 'h')
	    exit (EXIT_SUCCESS);
	  printf ("Usage:\n");
	  printf ("  %s [-w timeout] [-i interval] ipaddr ...\n", argv[0]);
	  printf ("\n");
	  exit (EXIT_SUCCESS);
	default:
	  exit (EXIT_FAILURE);
	}
    }
  if (ping_context_new (&ctx) == -1)
    {
      perror ("ping_context_new");
      exit (EXIT_FAILURE);
    }
  ctx.infolen = argc - optind;
  ctx.info = alloca (sizeof (*ctx.info) * ctx.infolen);
  memset (ctx.info, 0, sizeof (*ctx.info) * ctx.infolen);

  for (int i = 0; i < ctx.infolen; i++)
    {
      struct ping_info *pi = ctx.info + i;
      int ret =
	inet_pton (AF_INET, argv[i + optind], &pi->addr_sent.sin_addr);
      if (ret != 1)
	{
	  perror (argv[i + optind]);
	  exit (EXIT_FAILURE);
	}
      pi->addr_sent.sin_family = AF_INET;
      pi->addr_sent.sin_port = 0;
    }

  do
    {
      struct itimerspec it_in;

      it_in.it_value.tv_sec = 0;
      it_in.it_value.tv_nsec = 1;
      it_in.it_interval = in_spec;

      if (timerfd_settime (ctx.intervalfd, 0, &it_in, NULL) == -1)
	{
	  perror ("timerfd_settime");
	  exitcode = EXIT_FAILURE;
	  break;
	}

      do
	{
	  int nfds = -1;
	  fd_set rfds;

	  FD_ZERO (&rfds);
	  FD_SET (ctx.sock, &rfds);
	  if (nfds < ctx.sock)
	    nfds = ctx.sock;
	  FD_SET (ctx.timeoutfd, &rfds);
	  if (nfds < ctx.timeoutfd)
	    nfds = ctx.timeoutfd;
	  if (ctx.intervalfd != -1)
	    {
	      FD_SET (ctx.intervalfd, &rfds);
	      if (nfds < ctx.intervalfd)
		nfds = ctx.intervalfd;
	    }

	  int ret = select (nfds + 1, &rfds, NULL, NULL, NULL);
	  if (ret == -1)
	    {
	      perror ("select");
	      exitcode = EXIT_FAILURE;
	      break;
	    }

	  if (ctx.intervalfd != -1 && FD_ISSET (ctx.intervalfd, &rfds))
	    {
	      uint64_t count;
	      int ret = read (ctx.intervalfd, &count, sizeof (count));
	      if (ret == -1)
		{
		  perror ("read");
		  exitcode = EXIT_FAILURE;
		  break;
		}
	      if (ret != sizeof (count))
		{
		  fprintf (stderr, "FATAL ERROR while reading timer\n");
		  exitcode = EXIT_FAILURE;
		  break;
		}
	      for (int i = 0; i < count; i++)
		{
		  static char data[] = "0123456789";
		  size_t datalen = sizeof (data);

		  if (ctx.sndidx >= ctx.infolen)
		    {
		      struct itimerspec it_to;

		      close (ctx.intervalfd);
		      ctx.intervalfd = -1;
		      it_to.it_value = to_spec;
		      it_to.it_interval.tv_sec = 0;
		      it_to.it_interval.tv_nsec = 0;

		      if (timerfd_settime (ctx.timeoutfd, 0, &it_to, NULL) ==
			  -1)
			{
			  perror ("timerfd_settime");
			  exitcode = EXIT_FAILURE;
			  break;
			}
		      break;
		    }

		  if (icmp_echo_send (&ctx, data, datalen) == -1)
		    {
		      perror ("icmp_echo_send");
		      exitcode = EXIT_FAILURE;
		      break;
		    }
		}
	    }

	  if (FD_ISSET (ctx.timeoutfd, &rfds))
	    {
	      for (int i = 0; i < ctx.infolen; i++)
		if (ctx.info[i].count_recv == 0)
		  {
		    memcpy (&ctx.info[i].saddr_recv, &ctx.info[i].addr_sent,
			    sizeof (ctx.info->addr_sent));
		    ping_showrecv (&ctx, i);
		  }
	      break;
	    }

	  if (FD_ISSET (ctx.sock, &rfds))
	    {
	      int idx = icmp_echoreply_recv (&ctx);
	      if (idx == -1)
		{
		  if (errno == EAGAIN)
		    continue;
		  perror ("icmp_echoreply_recv");
		  break;
		}
	      ctx.info[idx].count_recv++;
	      ping_showrecv (&ctx, idx);
	    }

	  int count_recvs = 0;
	  for (int i = 0; i < ctx.infolen; i++)
	    if (ctx.info[i].count_recv > 0)
	      count_recvs++;
	  if (count_recvs >= ctx.infolen)
	    break;
	}
      while (1);
    }
  while (0);
  ping_context_destory (&ctx);
  return exitcode;
}
