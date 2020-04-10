#ifndef __MPING_TIME_H__
#define __MPING_TIME_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>

#include <sys/timerfd.h>

#include "config.h"

static struct timespec
ntots (long sec, long nsec)
{
  struct timespec ts = { sec, nsec };
  return ts;
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

static struct timespec
dtots (double d)
{
  struct timespec ts;

  ts.tv_sec = d;
  ts.tv_nsec = (d - ts.tv_sec) * 1000000000;
  return ts;
}

#endif
