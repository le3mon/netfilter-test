#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdint.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "sys/types.h"
#include <regex>
#include <string.h>
#include <string>
/* returns packet id */

using namespace std;

int host_len;
char *host;
regex pattern("\x48\x6f\x73\x74\x3a\x20(.*)"); // "Host: "
typedef struct _type_ip{
    uint8_t h_len:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t idneti;
    uint8_t off:5;
    uint8_t flag:3;
    uint8_t off_2;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    in_addr_t src_ip;
    in_addr_t dst_ip;
}type_ip;

typedef struct _type_tcp{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t flag:4;
    uint8_t h_len:4;
    uint8_t flag_2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
}type_tcp;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data); //*** 패킷의 시작 위치가 data , ret는 패킷 길이
    if (ret >= 0){
        printf("payload_len=%d ", ret);
        //        dump(data,ret);
    }

    fputc('\n', stdout);

    return id;
}
bool is_warning(struct nfq_data *tb){
    u_char *data;
    int length = nfq_get_payload(tb, &data);
    if (length == 0)
        return false;
    type_ip *iph = reinterpret_cast<type_ip *>(const_cast<u_char *>(data));
    if (iph->proto != IPPROTO_TCP)
        return false;
    type_tcp *tcph = reinterpret_cast<type_tcp *>(const_cast<u_char *>((data+(iph->h_len*4))));
    if (ntohs(tcph->dst_port) != 80)
        return false;
    data = data + iph->h_len*4 + tcph->h_len*4;
    smatch tmp;
    string str(reinterpret_cast<char *>(const_cast<u_char *>(data)));
    if (regex_search(str,tmp,pattern)){
        if(tmp[1].length() != host_len)
            return false;
        cout << tmp[1].str() << endl;
        if (0 == tmp[1].str().compare(host)){
            printf("success drop the packet\n");
            return true;
        }
    }
    return false;
}

//call back
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    (void)data;
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if (is_warning(nfa))
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr); //******
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

void usage(){
    printf("usage : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2){
        usage();
        return -1;
    }
    host_len = strlen(argv[1]);
    host = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
//    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, nullptr); // **********
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {

        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
