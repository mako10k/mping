#ifndef __MPING_ADDR_H__
#define __MPING_ADDR_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netinet/in.h>
#include <netinet/ip6.h>

struct mping_addr
{
  union
  {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  };
  socklen_t addrlen;
};


#endif
