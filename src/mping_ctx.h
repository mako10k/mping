#ifndef __MPING_CTX_H__
#define __MPING_CTX_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mping_opt.h"
#include "mping_sock.h"
#include "mping_ns.h"
#include "mping_timer.h"
#include <errno.h>

struct ping_context
{
  struct mping_socket sock;
  struct mping_ns ns;
  struct mping_timer timeout;
  struct mping_timer interval;
  int id;
  struct ping_info *info;
  size_t infolen;
  int sndidx;
  struct ping_option opt;
};

static struct ping_context
ping_context_new (struct ping_option option)
{
  struct ping_context context;

  context.sock = mping_socket_new ();
  context.ns = mping_ns_new ();
  context.timeout = mping_timer_new ();
  context.interval = mping_timer_new ();
  context.id = getpid ();
  context.info = NULL;
  context.infolen = 0;
  context.sndidx = 0;
  context.opt = option;

  return context;
}

static void
ping_context_destory (struct ping_context context)
{
  mping_socket_destory (context.sock);
  mping_ns_destory (context.ns);
  mping_timer_destory (context.timeout);
  mping_timer_destory (context.interval);
}

#endif
