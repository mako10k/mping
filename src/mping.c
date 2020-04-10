#define _GNU_SOURCE
#include "mping.h"
#include <unistd.h>
#include <alloca.h>
#include <sys/select.h>

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

  while ((opt = getopt (argc, argv, "w:i:s:d:t:nN46vh")) != -1)
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

  if (!ctx_opt.ipv4 && !ctx_opt.ipv6)
    {
      ctx_opt.ipv4 = 1;
      ctx_opt.ipv6 = 1;
    }
  if (ctx_opt.data == NULL)
    {
      ctx_opt.data = malloc (ctx_opt.datalen);
      if (ctx_opt.data == NULL)
	{
	  perror ("malloc");
	  exit (EXIT_FAILURE);
	}
      // fill in by ascii printables
      for (int i = 0; i < ctx_opt.datalen; i++)
	ctx_opt.data[i] = i % (127 - 32) + 32;
    }
  if (ping_context_new (&ctx, &ctx_opt) == -1)
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

      pi->daddr_send.addrlen = sizeof (pi->daddr_send);
      if (get_addr
	  (argv[optind + i], &pi->daddr_send.addr,
	   &pi->daddr_send.addrlen, ctx.opt.ipv4, ctx.opt.ipv6,
	   ctx.opt.numeric_parse) == -1)
	{
	  if (errno)
	    perror (argv[optind + i]);
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
	  perror ("timerfd_settime");
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
	      perror ("select");
	      exitcode = EXIT_FAILURE;
	      break;
	    }

	  if (FD_ISSET (ctx.asyncnsfd, &rfds))
	    {
	      if (asyncns_wait (ctx.asyncns, 0) < 0)
		perror ("asyncns_wait");
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
			  perror ("timerfd_settime");
			  exitcode = EXIT_FAILURE;
			  break;
			}
		      break;
		    }

		  if (icmp_echo_send (&ctx) == -1)
		    {
		      perror ("icmp_echo_send");
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
		  perror ("icmp_echoreply_recv");
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
		  perror ("icmp_echoreply_recv");
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
