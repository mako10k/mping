#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>

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

#define MAX_DATALEN4 (65535-sizeof(struct iphdr)-sizeof(struct icmphdr))
#define MAX_DATALEN6 (65535-sizeof(struct ip6_hdr)-sizeof(struct icmp6_hdr))

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
  unsigned int verbose:3;
  int pstderr:1;
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

  for (int i = 0; i < iovlen; i++)
    for (int j = 0; j < iov[i].iov_len; j++)
      sum += ((char *) iov[i].iov_base)[j] << (8 * (k++ & 1));
  sum = (sum & 65535) + (sum >> 16);
  sum = (sum & 65535) + (sum >> 16);
  return ~sum;
}

static int
icmp_setopt (struct ping_context *ctx)
{
  int ret = 0;

#if 0
  {
    int flag = 0;
    ret =
      setsockopt (ctx->sock4, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag));
    if (ret != 0)
      return ret;
  }
#endif
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
  {
    int flags = fcntl (ctx->sock4, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl (ctx->sock4, F_SETFL, &flags);
  }
  {
    int flags = fcntl (ctx->sock6, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl (ctx->sock6, F_SETFL, &flags);
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
  char data[MAX_DATALEN4];
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
  char data[MAX_DATALEN6];
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
  po.pstderr = isatty (STDIN_FILENO);

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
  if (icmp_setopt (pc) == -1)
    {
      int _errno = errno;
      close (pc->sock4);
      close (pc->sock6);
      asyncns_free (pc->asyncns);
      errno = _errno;
      return -1;
    }
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
    syslog (LOG_CRIT, "asyncns_getnameinfo: %s", strerror (errno));
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
	  syslog (LOG_WARNING, "asyncns_getnameinfo_done: %s\n",
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
  fprintf (fp, "  -v          : increase verbosity\n");
  fprintf (fp, "  -e          : force print stderr\n");
  fprintf (fp, "  -E          : suppress print stderr\n");
  fprintf (fp, "  -V          : print version\n");
  fprintf (fp, "  -h          : print usage\n");
  fprintf (fp, "\n");
}

static void
setloglevel (int level)
{
  switch (level)
    {
    case 0:
      setlogmask (LOG_UPTO (LOG_ERR));
      break;
    case 1:
      setlogmask (LOG_UPTO (LOG_WARNING));
      break;
    case 2:
      setlogmask (LOG_UPTO (LOG_NOTICE));
      break;
    case 3:
      setlogmask (LOG_UPTO (LOG_INFO));
      break;
    default:
      setloglevel (LOG_UPTO (LOG_DEBUG));
      break;
    }
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
      syslog (LOG_ERR, "%s: %s\n", node, gai_strerror (err));
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

int
main (int argc, char *argv[])
{
  struct ping_context ctx;
  struct ping_option ctx_opt = po_defaults ();
  int exitcode = EXIT_SUCCESS;
  int opt;
  long opt_long;
  double opt_double;
  char *p;

  while ((opt = getopt (argc, argv, "w:i:s:d:t:nN46vVh")) != -1)
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
	  ctx_opt.timeout = dtots (opt_double);
	  break;

	case 'i':
	  opt_double = strtod (optarg, &p);
	  if (p == optarg || *p != '\0')
	    {
	      fprintf (stderr, "error argument -%c %s\n", opt, optarg);
	      exit (EXIT_FAILURE);
	    }
	  ctx_opt.interval = dtots (opt_double);
	  break;

	case 's':
	  opt_long = strtol (optarg, &p, 0);
	  if (p == optarg || *p != '\0')
	    {
	      fprintf (stderr, "error argument -%c %s\n", opt, optarg);
	      exit (EXIT_FAILURE);
	    }
	  if (opt_long < 0 || opt_long > 65536)
	    {
	      fprintf (stderr, "packet size must be between 0 and %d\n",
		       65536);
	      exit (EXIT_FAILURE);
	    }
	  ctx_opt.data = NULL;
	  ctx_opt.datalen = opt_long;
	  break;

	case 'd':
	  opt_long = strlen (optarg);
	  if (opt_long < 0 || opt_long > 65536)
	    {
	      fprintf (stderr, "packet size must be between 0 and %d\n",
		       65536);
	      exit (EXIT_FAILURE);
	    }
	  ctx_opt.data = optarg;
	  ctx_opt.datalen = opt_long;
	  break;

	case 't':
	  opt_long = strtol (optarg, &p, 0);
	  if (optarg == p || *p != '\0' || opt_long > 255)
	    {
	      fprintf (stderr, "ttl must be between 0 and 255\n");
	      exit (EXIT_FAILURE);
	    }
	  ctx_opt.ttl = opt_long;
	  break;

	case 'n':
	  ctx_opt.numeric_print = 1;
	  break;

	case 'N':
	  ctx_opt.numeric_parse = 1;
	  break;

	case '4':
	  ctx_opt.ipv4 = 1;
	  break;

	case '6':
	  ctx_opt.ipv6 = 1;
	  break;

	case 'v':
	  ctx_opt.verbose++;
	  break;

	case 'e':
	  ctx_opt.pstderr = 1;
	  break;

	case 'E':
	  ctx_opt.pstderr = 0;
	  break;

	case 'V':
	  print_version (stdout, argc, argv);
	  exit (EXIT_SUCCESS);

	case 'h':
	  print_version (stdout, argc, argv);
	  print_usage (stdout, argc, argv);
	  exit (EXIT_SUCCESS);

	default:
	  exit (EXIT_FAILURE);
	}
    }

  int logflag = LOG_PID;
  if (ctx_opt.pstderr)
    logflag |= LOG_PERROR;
  openlog (NULL, logflag, LOG_USER);
  setloglevel (ctx_opt.verbose);

  if (!ctx_opt.ipv4 && !ctx_opt.ipv6)
    {
      syslog (LOG_INFO, "-4 nor -6 is not specified, imply -4 and -6");
      ctx_opt.ipv4 = 1;
      ctx_opt.ipv6 = 1;
    }
  if (ctx_opt.data == NULL)
    {
      ctx_opt.data = malloc (ctx_opt.datalen);
      if (ctx_opt.data == NULL)
	{
	  syslog (LOG_CRIT, "malloc: %s", strerror (errno));
	  exit (EXIT_FAILURE);
	}
      // fill in by ascii printables
      for (int i = 0; i < ctx_opt.datalen; i++)
	ctx_opt.data[i] = i % (127 - 32) + 32;
    }
  if (ping_context_new (&ctx, &ctx_opt) == -1)
    {
      syslog (LOG_CRIT, "ping_context_new: %s", strerror (errno));
      exit (EXIT_FAILURE);
    }
  ctx.infolen = argc - optind;
  ctx.info = alloca (sizeof (*ctx.info) * ctx.infolen);
  memset (ctx.info, 0, sizeof (*ctx.info) * ctx.infolen);

  for (int i = 0; i < ctx.infolen; i++)
    {
      struct ping_info *pi = ctx.info + i;

      pi->daddr_send.addrlen = sizeof (pi->daddr_send);
      if (get_addr
	  (argv[optind + i], &pi->daddr_send.addr,
	   &pi->daddr_send.addrlen, ctx.opt.ipv4, ctx.opt.ipv6,
	   ctx.opt.numeric_parse) == -1)
	{
	  if (errno)
	    syslog (LOG_CRIT, "%s: %s", argv[optind + i], strerror (errno));
	  exit (EXIT_FAILURE);
	}
    }

  do
    {
      struct itimerspec it_in;

      it_in.it_value.tv_sec = 0;
      it_in.it_value.tv_nsec = 1;
      it_in.it_interval = ctx.opt.interval;

      if (timerfd_settime (ctx.intervalfd, 0, &it_in, NULL) == -1)
	{
	  syslog (LOG_CRIT, "timerfd_settime: %s", strerror (errno));
	  exitcode = EXIT_FAILURE;
	  break;
	}

      do
	{
	  int nfds = -1;
	  fd_set rfds;

	  FD_ZERO (&rfds);
	  FD_SET (ctx.sock4, &rfds);
	  if (nfds < ctx.sock4)
	    nfds = ctx.sock4;
	  FD_SET (ctx.sock6, &rfds);
	  if (nfds < ctx.sock6)
	    nfds = ctx.sock6;
	  if (asyncns_getnqueries (ctx.asyncns) > 0)
	    {
	      FD_SET (ctx.asyncnsfd, &rfds);
	      if (nfds < ctx.asyncnsfd)
		nfds = ctx.asyncnsfd;
	    }
	  if (ctx.timeoutfd != -1)
	    {
	      FD_SET (ctx.timeoutfd, &rfds);
	      if (nfds < ctx.timeoutfd)
		nfds = ctx.timeoutfd;
	    }
	  if (ctx.intervalfd != -1)
	    {
	      FD_SET (ctx.intervalfd, &rfds);
	      if (nfds < ctx.intervalfd)
		nfds = ctx.intervalfd;
	    }

	  int ret = select (nfds + 1, &rfds, NULL, NULL, NULL);
	  if (ret == -1)
	    {
	      syslog (LOG_CRIT, "select: %s", strerror (errno));
	      exitcode = EXIT_FAILURE;
	      break;
	    }

	  if (FD_ISSET (ctx.asyncnsfd, &rfds))
	    {
	      if (asyncns_wait (ctx.asyncns, 0) < 0)
		syslog (LOG_CRIT, "asyncns_wait: %s", strerror (errno));
	      else
		{
		  asyncns_query_t *query;

		  while ((query = asyncns_getnext (ctx.asyncns)) != NULL)
		    for (int i = 0; i < ctx.sndidx; i++)
		      if (query == ctx.info[i].asyncns_name_query)
			{
			  ping_showrecv_done (&ctx, i);
			  break;
			}
		}
	    }
	  if (ctx.intervalfd != -1 && FD_ISSET (ctx.intervalfd, &rfds))
	    {
	      uint64_t count;
	      int ret = read (ctx.intervalfd, &count, sizeof (count));
	      if (ret == -1)
		{
		  syslog (LOG_CRIT, "read: %s", strerror (errno));
		  exitcode = EXIT_FAILURE;
		  break;
		}
	      if (ret != sizeof (count))
		{
		  syslog (LOG_CRIT, "while reading timer");
		  exitcode = EXIT_FAILURE;
		  break;
		}
	      for (int i = 0; i < count; i++)
		{
		  if (ctx.sndidx >= ctx.infolen)
		    {
		      struct itimerspec it_to;

		      close (ctx.intervalfd);
		      ctx.intervalfd = -1;
		      it_to.it_value = ctx.opt.timeout;
		      it_to.it_interval.tv_sec = 0;
		      it_to.it_interval.tv_nsec = 0;

		      if (timerfd_settime (ctx.timeoutfd, 0, &it_to, NULL) ==
			  -1)
			{
			  syslog (LOG_CRIT, "timerfd_settime: %s",
				  strerror (errno));
			  exitcode = EXIT_FAILURE;
			  break;
			}
		      break;
		    }

		  if (icmp_echo_send (&ctx) == -1)
		    {
		      syslog (LOG_CRIT, "icmp_echo_send: %s",
			      strerror (errno));
		      exitcode = EXIT_FAILURE;
		      break;
		    }
		}
	      if (exitcode != EXIT_SUCCESS)
		break;
	    }

	  if (ctx.timeoutfd != -1 && FD_ISSET (ctx.timeoutfd, &rfds))
	    {
	      for (int i = 0; i < ctx.infolen; i++)
		if (ctx.info[i].count_recv == 0)
		  {
		    memcpy (&ctx.info[i].saddr_recv, &ctx.info[i].daddr_send,
			    sizeof (ctx.info[i].saddr_recv));
		    ping_showrecv_prepare (&ctx, i, ctx.opt.numeric_print);
		  }
	      close (ctx.timeoutfd);
	      ctx.timeoutfd = -1;
	    }

	  if (FD_ISSET (ctx.sock4, &rfds))
	    {
	      int idx = icmp4_echoreply_recv (&ctx);
	      if (idx == -1)
		{
		  if (errno == EAGAIN)
		    goto next;
		  syslog (LOG_CRIT, "icmp_echoreply_recv: %s",
			  strerror (errno));
		  break;
		}
	      ctx.info[idx].count_recv++;
	      ping_showrecv_prepare (&ctx, idx, ctx.opt.numeric_print);
	    }

	  if (FD_ISSET (ctx.sock6, &rfds))
	    {
	      int idx = icmp6_echoreply_recv (&ctx);
	      if (idx == -1)
		{
		  if (errno == EAGAIN)
		    goto next;
		  syslog (LOG_CRIT, "icmp_echoreply_recv: %s",
			  strerror (errno));
		  break;
		}
	      ctx.info[idx].count_recv++;
	      ping_showrecv_prepare (&ctx, idx, ctx.opt.numeric_print);
	    }

	next:{
	    int count_recvs = 0;
	    for (int i = 0; i < ctx.infolen; i++)
	      if (ctx.info[i].asyncns_name_query == NULL
		  && ctx.info[i].count_recv > 0)
		count_recvs++;
	    if (count_recvs >= ctx.infolen)
	      break;
	  }
	}
      while (1);
    }
  while (0);
  ping_context_destory (&ctx);
  return exitcode;
}
