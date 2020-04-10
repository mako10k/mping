#ifndef __MPING_OPT_H__
#define __MPING_OPT_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "mping_time.h"

#define PINGOPT_TTL_DEFAULT 30
#define PINGOPT_DATALEN_DEFAULT 56
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

static struct ping_option
mping_opt_parse (int argc, char *argv[])
{
  struct ping_option ctx_opt = po_defaults ();
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
      ctx_opt.data = (char *) malloc (ctx_opt.datalen);
      if (ctx_opt.data == NULL)
	{
	  perror ("malloc");
	  exit (EXIT_FAILURE);
	}
      // fill in by ascii printables
      for (int i = 0; i < ctx_opt.datalen; i++)
	ctx_opt.data[i] = i % (127 - 32) + 32;
    }

  return ctx_opt;
}
#endif
