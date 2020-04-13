#ifndef __MPING_TIMER_H__
#define __MPING_TIMER_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/timerfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct mping_timer
{
  int fd;
};

static struct mping_timer
mping_timer_new ()
{
  struct mping_timer timer;

  timer.fd = timerfd_create (CLOCK_MONOTONIC, 0);
  if (timer.fd == -1)
    {
      perror ("timerfd_create");
      exit (EXIT_FAILURE);
    }

  return timer;
}

static void
mping_timer_destory (struct mping_timer timer)
{
  close (timer.fd);
}

#endif
