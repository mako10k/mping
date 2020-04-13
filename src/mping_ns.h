#ifndef __MPING_NS_H__
#define __MPING_NS_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <asyncns.h>
#include <stdio.h>
#include <stdlib.h>

struct mping_ns {
  asyncns_t *asyncns;
  int fd;
};

static mping_ns
mping_ns_new()
{
  struct mping_ns ns;

  ns.asyncns = asyncns_new (2);
  if (ns.asyncns == NULL)
  {
    perror("asyncns_new");
    exit(EXIT_FAILURE);
  }
  ns.fd = asyncns_fd (ns.asyncns);

  return ns;
}

static void
mping_ns_destory(struct mping_ns ns)
{
  asyncns_free(ns.asyncns);
}

#endif
