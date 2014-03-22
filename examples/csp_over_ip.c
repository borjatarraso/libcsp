/*
csp_over_ip.c - Example of CSP protocol running over ip raw sockets
Copyright (C) 2014 Aalto University, Department of Radio Science and Engineering

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/ip.h>

#include <csp/csp.h>
#include <csp/csp_interface.h>

#define TYPE_SERVER 1
#define TYPE_CLIENT 2
#define PORT        10
#define BUF_SIZE    250

#define SERV_PORT 10000
#define MAXLINE 4096

#define CSP_PROTO 213

pthread_t rx_thread;
int server_socket, tx_channel;
struct sockaddr_in servaddr;

int csp_socket_tx(csp_packet_t *packet, uint32_t timeout);

csp_iface_t csp_if_socket = {
    .name = "socket",
    .nexthop = csp_socket_tx,
    .mtu = BUF_SIZE,
};

int csp_socket_tx(csp_packet_t *packet, uint32_t timeout) {
    socklen_t length;

    printf("Debug tx: %i\n", packet->length);

    if (sendto(tx_channel, &packet->length, packet->length + sizeof(uint32_t) + sizeof(uint16_t), 0, (struct sockaddr *) &servaddr , sizeof(servaddr)) < 0)
        perror("sendto");

    csp_buffer_free(packet);
    return 1;
}

void * socket_rx(void * parameters) {
    csp_packet_t *buf;
    struct sockaddr_in sa;
    socklen_t length;
    struct iphdr *ip;
    int hlen;
    int numbytes;
    uint8_t buffer[BUF_SIZE];

    /* To check origin/destination of the packet */
    char ipbuf[INET_ADDRSTRLEN];

    while ((numbytes = recvfrom(server_socket, buffer, BUF_SIZE, 0, (struct sockaddr *) &sa , &length)) > 0) {
        ip = (struct iphdr *) buffer;
        hlen = ip->ihl << 2; /* length of IP header */

        buf = csp_buffer_get(BUF_SIZE);

        memcpy(&buf->length, buffer+hlen, numbytes-hlen );

        printf("Debug rx: Got packet from IP: %s with raw length %i payload %i\n", inet_ntop(AF_INET, &ip->saddr, ipbuf, sizeof(ipbuf)), numbytes-hlen, buf->length);
        csp_new_packet(buf, &csp_if_socket, NULL);
    }

    return NULL;
}

int main(int argc, char **argv) {

    int me, other, type;
    char *message = "Testing CSP";
    csp_socket_t *sock;
    csp_conn_t *conn;
    csp_packet_t *packet;

    /* Required root to create a RAW socket */
    if(geteuid() != 0) {
        printf("Required special privileges for create ip raw sockets\n\n");
        printf("You must be root or set CAP_NET_RAW capability\n");
        return -1;
    }

    /* Run as either server or client */
    if (argc < 2) {
        printf("usage: %s <server/client> [ip]\n", argv[0]);
        return -1;
    } else if (strcmp(argv[1],"client") == 0 && argc != 3) {
        printf("Unspecified destination IP address\n\n");
        printf("usage: server <server/client> [ip]\n");
        return -1;
    }

    /* Set type */
    if (strcmp(argv[1], "server") == 0) {
        me = 1;
        other = 2;

        if ((server_socket = socket(AF_INET, SOCK_RAW, CSP_PROTO)) == -1) {
            perror("socket");
            exit(1);
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

        type = TYPE_SERVER;
    } else if (strcmp(argv[1], "client") == 0) {
        me = 2;
        other = 1;

        if ((tx_channel = socket(AF_INET, SOCK_RAW, CSP_PROTO)) == -1) {
            perror("socket");
            exit(1);
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        inet_pton(AF_INET, argv[2], &servaddr.sin_addr);

        type = TYPE_CLIENT;
    } else {
        printf("Invalid type. Must be either 'server' or 'client'\r\n");
        return -1;
    }

    /* Init CSP and CSP buffer system */
    if (csp_init(me) != CSP_ERR_NONE || csp_buffer_init(10, 300) != CSP_ERR_NONE) {
        printf("Failed to init CSP\r\n");
        return -1;
    }

    /* Start socket RX task */
    pthread_create(&rx_thread, NULL, socket_rx, NULL);

    /* Set default route and start router */
    csp_route_set(CSP_DEFAULT_ROUTE, &csp_if_socket, CSP_NODE_MAC);
    csp_route_start_task(0, 0);

    /* Create socket and listen for incoming connections */
    if (type == TYPE_SERVER) {
        sock = csp_socket(CSP_SO_NONE);
        csp_bind(sock, PORT);
        csp_listen(sock, 5);
    }

    /* Super loop */
    while (1) {
        if (type == TYPE_SERVER) {
            /* Process incoming packet */
            conn = csp_accept(sock, 1000);
            if (conn) {
                packet = csp_read(conn, 0);
                if (packet)
                        printf("Received: %s\r\n", packet->data);
                csp_buffer_free(packet);
                csp_close(conn);
            }
        } else {
            /* Send a new packet */
            packet = csp_buffer_get(strlen(message));
            if (packet) {
                strcpy((char *) packet->data, message);
                packet->length = strlen(message);

                conn = csp_connect(CSP_PRIO_NORM, other, PORT, 1000, CSP_O_NONE);
                printf("Sending: %s\r\n", message);
                if (!conn || !csp_send(conn, packet, 1000))
                    return -1;
                csp_close(conn);
            }
            sleep(1);
        }
    }

    close(server_socket);
    close(tx_channel);

    return 0;
}
