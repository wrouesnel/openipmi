/*
 * rmcp_ping.c
 *
 * OpenIPMI RMCP pinger
 *
 * Author: Montavista Software
 *         Corey Minyard <cminyard@mvista.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>

unsigned char ping_msg[12] =
{
    0x06, /* RMCP version 1.0 */
    0x00, /* reserved */
    0xff, /* RMCP seq num, not used for IPMI */
    0x06, /* ASF message */
    0x00, 0x00, 0x11, 0xbe, /* ASF IANA */
    0x80, /* Presence Ping */
    0x00, /* Message tag */
    0x00, /* Reserved */
    0x00  /* Data Length */
};

static char *progname;

static void
usage(void)
{
    fprintf(stderr,
	    "Send an RMCP ping packet onces a second to the destination,\n");
    fprintf(stderr,
	    "printing unique responses it receives\n");
    fprintf(stderr,
	    "Usage:\n");
    fprintf(stderr,
	    "  %s [-p <port>] [-t <waittime>] [-s <starttag>]"
	    " [-d] [destination]\n",
	    progname);
    fprintf(stderr,
	    "    -p - Destination port, defaults to 623\n");
    fprintf(stderr,
	    "    -t - Sets the number of seconds to wait for responses"
	    " (default 10)\n");
    fprintf(stderr,
	    "    -s - Sets the start tag to start sending at"
	    " (0-254, default 0\n");
    fprintf(stderr,
	    "    -d - enable debugging\n");
    fprintf(stderr,
	    "    destination - the target address, default is the broadcast\n");
    fprintf(stderr,
	    "        address (default 255.255.255.255)\n");
    exit(1);
}

int port = 0x26f;
int waittime = 10;
int starttag = 0;
int debug_packet = 0;

struct socklist
{
    struct in_addr addr;
    struct socklist *next;
};
struct socklist *socklist = NULL;

static int
add_host(struct sockaddr *addr)
{
    struct socklist *curr = socklist;
    struct sockaddr_in *ip;

    if (addr->sa_family != AF_INET)
	return 0;

    ip = (struct sockaddr_in *) addr;
    while (curr) {
	if (ip->sin_addr.s_addr == curr->addr.s_addr)
	    break;
	curr = curr->next;
    }
    if (curr)
	return 0;
    curr = malloc(sizeof(*curr));
    curr->addr = ip->sin_addr;
    curr->next = socklist;
    socklist = curr;
    return 1;
}

int
main(int argc, char *argv[])
{
    unsigned char      rsp[28];
    int                sock;
    int                rv;
    char               dest_data[sizeof(struct sockaddr)];
    struct sockaddr    *dest = (struct sockaddr *) dest_data;
    size_t             destlen;
    char               src_data[sizeof(struct sockaddr)];
    struct sockaddr    *src = (struct sockaddr *) src_data;
    int                val;
    socklen_t          fromlen;
    fd_set             readfds;
    struct timeval     currtime;
    struct timeval     endtime;
    struct timeval     twait;
    char               host[200];
    char               serv[200];
    char               *addrname;
    int                send_next;
    int                i;
    char               *end;


    progname = argv[0];

    for (i=1; i<argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (argv[i][1] == '\0')
	    usage();
	if (strcmp(argv[i], "--") == 0) {
	    i++;
	    break;
	} else if (strcmp(argv[i], "-p") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No parameter given for -p\n\n");
		usage();
	    }
	    port = strtoul(argv[i], &end, 0);
	    if (port < 0 || port > 65535 || *end != '\0') {
		fprintf(stderr, "Wrong port specified for -p\n\n");
		usage();
	    }
	} else if (strcmp(argv[i], "-t") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No parameter given for -t\n\n");
		usage();
	    }
	    waittime = strtoul(argv[i], &end, 0);
	    if (waittime < 0 || *end != '\0') {
		fprintf(stderr, "Wrong waittime specified for -t\n\n");
		usage();
	    }
	} else if (strcmp(argv[i], "-s") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No parameter given for -s\n\n");
		usage();
	    }
	    starttag = strtoul(argv[i], &end, 0);
	    if (starttag < 0 || starttag > 254 || *end != '\0') {
		fprintf(stderr, "Invalid start tag for -s\n\n");
		usage();
	    }
	} else if (strcmp(argv[i], "-d") == 0) {
	    debug_packet++;
	}
    }
    
    if (i < argc) {
	struct addrinfo hints, *res0;
	char ports[16];

	snprintf(ports, sizeof(ports), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
	rv = getaddrinfo(argv[i], ports, &hints, &res0);
	if (rv != 0) {
	    fprintf(stderr, "Unable to handle given address: %s\n\n",
		    gai_strerror(rv));
	    usage();
	}
	*dest = *(res0->ai_addr);
	destlen = res0->ai_addrlen;
	freeaddrinfo(res0);
    } else {
	struct sockaddr_in *ip = (struct sockaddr_in *) dest;
	ip->sin_family = AF_INET;
	ip->sin_port = htons(port);
	ip->sin_addr.s_addr = INADDR_BROADCAST;
	destlen = sizeof(*ip);
    }

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
	perror("socket");
	exit(1);
    }

    /* We want it to be non-blocking. */
    rv = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (rv) {
	close(sock);
	perror("fcntl(sock, F_SETFL, O_NONBLOCK)");
	exit(1);
    }

    val = 1;
    rv = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
    if (rv) {
	close(sock);
	perror("setsockopt(sock, SO_BROADCAST)");
	exit(1);
    }

    gettimeofday(&currtime, NULL);
    endtime = currtime;
    endtime.tv_sec += waittime;
    send_next = 1;
    for (;;) {
	if ((endtime.tv_sec < currtime.tv_sec)
	    || ((endtime.tv_sec == currtime.tv_sec)
		&& (endtime.tv_usec < currtime.tv_usec)))
	    break;

	if (send_next) {
	    ping_msg[9] = starttag;
	    starttag++;
	    if (starttag > 254)
		starttag = 0;
	    rv = sendto(sock, ping_msg, sizeof(ping_msg), 0, dest, destlen);
	    if (rv < 0) {
		close(sock);
		perror("sendto");
		exit(1);
	    }
	    send_next = 0;
	}

	twait.tv_usec = 0;
	twait.tv_sec = 1;
	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	rv = select(sock+1, &readfds, NULL, NULL, &twait);
	if (rv < 0) {
	    close(sock);
	    perror("select");
	    exit(1);
	}
	if (rv == 0) {
	    send_next = 1;
	    goto next;
	}
	
	fromlen = sizeof(*src);
	rv = recvfrom(sock, rsp, sizeof(rsp), 0, src, &fromlen);

	if (debug_packet && (rv > 0)) {
	    int i;
	    printf("Got packet:");
	    for (i=0; i<rv; i++) {
		if ((i % 16) == 0)
		    printf("\n   ");
		printf(" %2.2x", rsp[i]);
	    }
	    printf("\n");
	}

	if (rv < 0) {
	    perror("recvfrom");
	} else if (rv < 28) {
	    fprintf(stderr, "Invalid receive length: %d, should be 28\n", rv);
	} else if ((rsp[0] != 6) || (rsp[3] != 6) || (rsp[4] != 0x00)
		   || (rsp[5] != 0x00) || (rsp[6] != 0x11) || (rsp[7] != 0xbe)
		   || (rsp[8] != 0x40) || (rsp[11] < 16))
	{
	    fprintf(stderr, "Invalid ping response\n");
	} else {
	    if (! add_host(src))
		goto next;
	    rv = getnameinfo(src, fromlen, host, sizeof(host),
			     serv, sizeof(serv), 0);
	    if (rv) {
		struct sockaddr_in *ip = (struct sockaddr_in *) src;
		addrname = inet_ntoa(ip->sin_addr);
	    } else
		addrname = host;
	    printf("%s", addrname);
	    if ((rsp[20] & 0x80) && ((rsp[20] & 0xf) == 0x01))
		printf(" IPMI");
	    printf("\n");
	}
    next:
	gettimeofday(&currtime, NULL);
    }

    return 0;
}
