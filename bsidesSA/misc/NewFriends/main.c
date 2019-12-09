
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/types.h>
#include <netinet/in.h>

extern char auth_key[16];

extern char secret[];

static void reply(const char* msg);

static unsigned int checksum(const unsigned short* data, int datalen);

static void decodeauth(char* auth);

int main() {
  int i = 0;
  int auth_success = 0;

  char auth[16] = { 0 };

  union {
    unsigned int alignme;
    char pkt[0x1000];
  } pkt = { 0 };

  unsigned int pktsize = 0;
  {
    int thisread;

    while ((thisread = read(STDIN_FILENO, pkt.pkt + pktsize, sizeof(pkt.pkt) - pktsize)) > 0) {
      pktsize += thisread;
    }
  }

  // check for header
  if (pktsize < 8) {
    reply("short packet");
  }

  pkt.pkt[pktsize] = 0;

  const unsigned short* const pkts = pkt.pkt;

  const unsigned short ver = ntohs(pkts[0]);
  unsigned int authlen = (ntohs(pkts[2]) << 16) | ntohs(pkts[3]);

  // only version 1 supported
  if (ver != 1) {
    reply("invalid version");
  }

  // validate checksum
  if (checksum(pkts, pktsize) != 0) {
    reply("invalid checksum");
  }

  // check for too large authlen or integer overflow
  if (pkt.pkt + 8 + authlen >= pkt.pkt + sizeof(pkt.pkt)
      || pkt.pkt + 8 + authlen < pkt.pkt) {
    reply("auth length longer than packet");
  }

  if (authlen < 1) {
    // if auth is empty then allow the request
    if (strlen(auth_key) == 0) {
      auth_success = 1;
    }
  } else {
    // check for too large authlen or integer overflow
    if (auth + authlen >= auth + sizeof(auth)
        || auth + authlen < auth) {
      reply("large auth length");
    }

    while (pkt.pkt[i + 8] != 0 && pkt.pkt[i + 8] != ';' && authlen) {
      auth[i] = pkt.pkt[i + 8];

      --authlen;
      ++i;
    }

    // decode authorization in-place
    decodeauth(auth);

    // check auth
    if (strcmp(auth, auth_key) == 0) {
      auth_success = 1;
    }
  }

  // deny access to secret if auth failed
  if (!auth_success) {
    reply("auth failed");
  }

  reply(secret);

  return 0;
}

static unsigned int checksum(const unsigned short* data, int datalen) {
  unsigned int checksum = 0x1234;

  while (datalen > 0) {
    checksum += ntohs(*data);

    if (checksum > 0xffff) {
      checksum = (checksum & 0xffff) + 1;
    }

    datalen -= 2;
    ++data;
  }

  return (~checksum) & 0xffff;
}

static void reply(const char* msg) {
  char payload[100] = { 0 };
  unsigned short* pkts = payload;

  pkts[0] = htons(1);

  strncpy(payload + 8, msg, strlen(msg));

  const unsigned short msglen = 8 + strlen(msg);

  pkts[2] = htons((msglen >> 16) & 0xffff);
  pkts[3] = htons(msglen & 0xffff);

  pkts[1] = htons(checksum(pkts, msglen));

  struct sockaddr_in addr;

#if 0
  socklen_t addrlen = sizeof(addr);
  if (getpeername(STDIN_FILENO, &addr, &addrlen) != 0) {
    fprintf(stderr, "getpeername() failed: %s\n", strerror(errno));
    exit(1);
  }

  sendto(STDIN_FILENO, msg, msglen, 0, &addr, addrlen);
#endif

  fwrite(payload, msglen, 1, stdout);

  exit(0);
}

static int hexdigit(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('a' <= c && c <= 'f')
    return c - 'a';
  if ('A' <= c && c <= 'F')
    return c - 'F';
  return 0;
}

static void decodeauth(char* const msg) {
  char* outptr = msg, * inptr = msg;

  while (inptr[0] && inptr[1]) {
    *outptr = (hexdigit(inptr[0]) << 4) | hexdigit(inptr[1]);
    ++outptr;
    inptr += 2;
  }

  *outptr = 0;
}

