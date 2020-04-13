#ifndef __MPING_ICMP_H__
#define __MPING_ICMP_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mping_sock.h"
#include "mping_addr.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <sys/timerfd.h>

struct mping_icmp_echo_result
{
  int result;
  struct timespec time_send;
};

// 1の補数和の１の補数(IP Checksum)
static unsigned short
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

static struct mping_icmp_echo_result
mping_icmp_echo_send (struct mping_socket sock, struct mping_addr addr, int id, int seq, char *data, size_t datalen)
{
  struct msghdr msghdr;
  struct iovec iov[2];
  struct icmphdr icmphdr;
  struct icmp6_hdr icmp6_hdr;
  struct mping_icmp_echo_result ret;
  ssize_t size_sent;

  // ヘッダ情報
  switch (addr.addr.sa_family)
    {
    case AF_INET:
      icmphdr.type = ICMP_ECHO;
      icmphdr.code = 0;
      icmphdr.checksum = 0;
      icmphdr.un.echo.id = htons (id);
      icmphdr.un.echo.sequence = htons (seq);

      // 送信情報の作成
      iov[0].iov_base = &icmphdr;
      iov[0].iov_len = sizeof (icmphdr);
      iov[1].iov_base = data;
      iov[1].iov_len = datalen;
      // チェックサムの計算
      icmphdr.checksum = checksum (iov, 2);

      break;
    case AF_INET6:
      icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
      icmp6_hdr.icmp6_code = 0;
      icmp6_hdr.icmp6_cksum = 0;
      icmp6_hdr.icmp6_id = htons (id);
      icmp6_hdr.icmp6_seq = htons (seq);

      // 送信情報の作成
      iov[0].iov_base = &icmp6_hdr;
      iov[0].iov_len = sizeof (icmp6_hdr);
      iov[1].iov_base = data;
      iov[1].iov_len = datalen;
      // チェックサムの計算
      icmp6_hdr.icmp6_cksum = checksum (iov, 2);

      break;
    }
  msghdr.msg_name = &addr.addr;
  msghdr.msg_namelen = addr.addrlen;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 2;
  msghdr.msg_control = NULL;
  msghdr.msg_controllen = 0;
  msghdr.msg_flags = 0;

  // 送信時間の記録
  if (clock_gettime (CLOCK_REALTIME, &ret.time_send) == -1) {
    ret.result = -1;
    return ret;
  }

  // 送信
  size_sent = sendmsg (addr.addr.sa_family == AF_INET ? sock.sock4 : sock.sock6, &msghdr, 0);
  if (size_sent == -1)
    perror("sendmsg");
  ret.result = size_sent != -1;

  return ret;
}

static int
mping_icmp_echoreply_recv_6 (struct ping_context *ctx)
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


#endif
