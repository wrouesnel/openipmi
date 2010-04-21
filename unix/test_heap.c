/*
 * test_heap.c
 *
 * Code to test the heap.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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
#include <signal.h>
#include <string.h>
#include <time.h>

#define HEAP_EXPORT_NAME(s) test_ ## s
typedef struct heap_val_s { int a; } heap_val_t;
#define heap_node_s test_heap_node_s
#define heap_s test_heap_s

typedef struct test_heap_node_s test_heap_node_t;
typedef struct test_heap_s test_heap_t;

int debug = 0;

int
heap_cmp_key(heap_val_t *val1, heap_val_t *val2)
{
    if (val1->a < val2->a) {
	return -1;
    } else if (val1->a > val2->a) {
	return 1;
    } else {
	return 0;
    }
}
#define HEAP_OUTPUT_PRINTF "(%d)"
#define HEAP_OUTPUT_DATA pos->val.a

#define HEAP_DEBUG

#include "heap.h"

static int random_seed;

void
handle_fault(int sig)
{
    fprintf(stderr, "Died on sig %d\n", sig);
    printf("Seed was %d\n", random_seed);
    exit(1);
}

#define TEST_SIZE 2048
test_heap_node_t *(nodes[TEST_SIZE]);

int
main(int argc, char *argv[])
{
    test_heap_t      heap;
    int              i;
    int              err;
    test_heap_node_t *val1;
    struct sigaction act;
    int              rand_val;

    i = 1;
    while ((i < argc) && (argv[i][0] == '-')) {
	if (strcmp(argv[i], "--") == 0)
	    break;
	else if (strcmp(argv[i], "-d") == 0)
	    debug++;
	else {
	    fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
	    exit(1);
	}
	
	i++;
    }
    if (i < argc) {
	random_seed = atoi(argv[i]);
    } else {
	random_seed = time(NULL);
    }
    if (debug)
	printf("Random seed is %d\n", random_seed);
    srand(random_seed);
    test_debug_out = &stdout;

    act.sa_handler = handle_fault;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    err = sigaction(SIGSEGV, &act, NULL);
    if (err) {
	perror("sigaction");
    }

    test_init(&heap);

    for (i=0; i<TEST_SIZE; i++) {
	rand_val = rand() & (TEST_SIZE-1);
	if (nodes[rand_val]) {
	    if (debug > 1)
		printf("Removing item %d\n", nodes[rand_val]->val.a);
	    test_remove(&heap, nodes[rand_val]);
	    free(nodes[rand_val]);
	    nodes[rand_val] = NULL;
	} else {
	    val1 = malloc(sizeof(*val1));
	    val1->val.a = rand();
	    if (debug > 1)
		printf("Adding item %d\n", val1->val.a);
	    test_add(&heap, val1);
	    nodes[rand_val] = val1;
	}
	test_check(&heap);
    }
    if (debug > 1)
	test_print(&heap);
    if (debug)
	printf("Seed was %d\n", random_seed);

    return 0;
}
