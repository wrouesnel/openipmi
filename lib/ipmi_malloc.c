/*
 * ipmi.c
 *
 * MontaVista IPMI generic code
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

#include <malloc.h>
#include <string.h>
#include <execinfo.h> /* For backtrace() */
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ilist.h>

#define DBG_ALIGN 16

#define TB_SIZE 6

#define SIGNATURE 0x82c2e45a
#define FREE_SIGNATURE 0xb981cef1
#define BYTE_SIGNATURE 0x74

struct dbg_malloc_header
{
    unsigned long signature;
    unsigned long size;
    void          *tb[TB_SIZE];
};

struct dbg_malloc_trailer
{
    void                     *tb[TB_SIZE];
    struct dbg_malloc_header *next, *prev;
};

static struct dbg_malloc_header *free_queue = NULL;
static struct dbg_malloc_header *free_queue_tail = NULL;
static int free_queue_len;
static int max_free_queue = 100;

static struct dbg_malloc_header *alloced = NULL;
static struct dbg_malloc_header *alloced_tail = NULL;

static size_t
dbg_align(size_t size)
{
    if (size & (DBG_ALIGN-1))
	size = (size & (~(DBG_ALIGN - 1))) + DBG_ALIGN;
    return size;
}

static struct dbg_malloc_trailer *
trlr_from_hdr(struct dbg_malloc_header *hdr)
{
    size_t real_size = dbg_align(hdr->size);
    return (struct dbg_malloc_trailer *)
	(((char *) hdr) + sizeof(*hdr) + real_size);
}

static void *
ipmi_debug_malloc(size_t size, void **tb)
{
    char                      *data;
    struct dbg_malloc_header  *hdr;
    struct dbg_malloc_trailer *trlr;
    struct dbg_malloc_trailer *trlr2;
    int                       i;
    size_t                    real_size;

    real_size = dbg_align(size);

    data = malloc(real_size
		  + sizeof(struct dbg_malloc_header)
		  + sizeof(struct dbg_malloc_trailer));
    if (!data)
	return NULL;

    hdr = (struct dbg_malloc_header *) data;
    trlr = (struct dbg_malloc_trailer *) (data + real_size + sizeof(*hdr));

    hdr->signature = SIGNATURE;
    hdr->size = size;
    memcpy(hdr->tb, tb, sizeof(hdr->tb));
    for (i=0; i<TB_SIZE; i++) {
	trlr->tb[i] = (void *) SIGNATURE;
    }

    data += sizeof(*hdr);
    for (i=size; i<real_size; i++)
	data[i] = BYTE_SIGNATURE;

    /* Add it to the alloced list. */
    trlr->next = NULL;
    trlr->prev = alloced_tail;
    if (alloced_tail) {
	trlr2 = trlr_from_hdr(alloced_tail);
	trlr2->next = hdr;
    } else
	alloced = hdr;
    alloced_tail = hdr;

    return data;
}

static void
mem_debug_log(void                      *data,
	      struct dbg_malloc_header  *hdr,
	      struct dbg_malloc_trailer *trlr,
	      void                      **tb,
	      char                      *text)
{
    int  i;

    ipmi_log(IPMI_LOG_DEBUG_START, "%s", text);
    if (hdr) {
	ipmi_log(IPMI_LOG_DEBUG_CONT,
		 " %d bytes at %p, allocated at",
		 hdr->size, data);
	for (i=0; i<TB_SIZE; i++)
	    ipmi_log(IPMI_LOG_DEBUG_CONT, " %p", hdr->tb[i]);
    } else if (data) {
	ipmi_log(IPMI_LOG_DEBUG_CONT, " at %p", data);
    }
    if (trlr) {
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n originally freed at");
	for (i=0; i<TB_SIZE; i++)
	    ipmi_log(IPMI_LOG_DEBUG_CONT, " %p", trlr->tb[i]);
    }
    if (tb) {
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  at");
	for (i=0; i<TB_SIZE; i++)
	    ipmi_log(IPMI_LOG_DEBUG_CONT, " %p", tb[i]);
    }
    ipmi_log(IPMI_LOG_DEBUG_END, "");
}

static void
dbg_remove_free_queue(void)
{
    struct dbg_malloc_header  *hdr;
    struct dbg_malloc_trailer *trlr;
    size_t                    real_size;
    long                      *dp;
    int                       i;
    char                      *data;
    int                       overwrite;
	
    hdr = free_queue;
    trlr = trlr_from_hdr(hdr);
    free_queue = trlr->next;
    if (!free_queue)
	free_queue_tail = NULL;
    free_queue_len--;

    data = ((char *) hdr) + sizeof(*hdr);

    if (hdr->signature != FREE_SIGNATURE) {
	mem_debug_log(data, hdr, trlr, NULL, "Header overrun");
	goto out;
    }

    real_size = dbg_align(hdr->size);

    overwrite = 0;
    for (i=hdr->size; i<real_size; i++)
	if (data[i] != BYTE_SIGNATURE)
	    overwrite = 1;
    if (overwrite) {
	mem_debug_log(data, hdr, trlr, NULL, "Overrun while free");
	goto out;
    }

    dp = (long *) data;
    for (i=0; i<real_size; i+=sizeof(long), dp++)
	if (*dp != FREE_SIGNATURE)
	    overwrite = 1;
    if (overwrite)
	mem_debug_log(data, hdr, trlr, NULL, "Write while free");

 out:
    free(hdr);
}

static void
enqueue_dbg_free(struct dbg_malloc_header  *hdr,
		 struct dbg_malloc_trailer *trlr)
{
    while (free_queue_len >= max_free_queue) {
	dbg_remove_free_queue();
    }

    trlr->next = NULL;
    if (free_queue_tail) {
	struct dbg_malloc_trailer *trlr2;

	trlr2 = trlr_from_hdr(free_queue_tail);
	trlr2->next = hdr;
    } else {
	free_queue = hdr;
    }
    free_queue_tail = hdr;
}

static void
ipmi_debug_free(void *to_free, void **tb)
{
    struct dbg_malloc_header  *hdr;
    struct dbg_malloc_trailer *trlr;
    struct dbg_malloc_trailer *trlr2;
    int                       i;
    size_t                    real_size;
    long                      *dp;
    char                      *data = to_free;
    int                       overwrite;

    if (to_free == NULL) {
	mem_debug_log(data, NULL, NULL, tb, "Free called with NULL");
	return;
    }

    hdr = (struct dbg_malloc_header *) (data - sizeof(*hdr));
    if ((hdr->signature != SIGNATURE) && (hdr->signature != FREE_SIGNATURE)) {
	mem_debug_log(data, NULL, NULL, tb, "Free of invalid data");
	return;
    }

    trlr = trlr_from_hdr(hdr);

    if (hdr->signature == FREE_SIGNATURE) {
	mem_debug_log(data, hdr, trlr, tb, "Double free");
	return;
    }

    /* Remove it from the alloced list. */
    if (trlr->next) {
	trlr2 = trlr_from_hdr(trlr->next);
	trlr2->prev = trlr->prev;
    } else {
	alloced_tail = trlr->prev;
	trlr2 = trlr_from_hdr(alloced_tail);
	trlr2->next = NULL;
    }
    if (trlr->prev) {
	trlr2 = trlr_from_hdr(trlr->prev);
	trlr2->next = trlr->next;
    } else {
	alloced = trlr->next;
	trlr2 = trlr_from_hdr(alloced);
	trlr2->prev = NULL;
    }

    real_size = dbg_align(hdr->size);

    /* Check for writes after the end of data. */
    overwrite = 0;
    for (i=0; i<TB_SIZE; i++)
	if (trlr->tb[i] != ((void *) SIGNATURE))
	    overwrite = 1;
    for (i=hdr->size; i<real_size; i++)
	if (data[i] != BYTE_SIGNATURE)
	    overwrite = 1;
    if (overwrite) {
	mem_debug_log(data, hdr, trlr, tb, "Overwrite");
    }

    hdr->signature = FREE_SIGNATURE;
    memcpy(trlr->tb, tb, sizeof(trlr->tb));

    /* Fill the data area with a signature. */
    dp = (long *) (((char *) hdr) + sizeof(*hdr));
    for (i=0; i<real_size; i+=sizeof(long), dp++)
	*dp = FREE_SIGNATURE;

    enqueue_dbg_free(hdr, trlr);
}

void
ipmi_debug_malloc_cleanup(void)
{
    struct dbg_malloc_trailer *trlr;
    void                      *to_free;

    if (DEBUG_MALLOC) {
	/* Check the free queue for any problems. */
	while (free_queue_len > 0) {
	    dbg_remove_free_queue();
	}

	/* Now log everything that was still allocated. */
	while (alloced) {
	    trlr = trlr_from_hdr(alloced);
	    mem_debug_log(((char *) alloced) + sizeof(*alloced),
			  alloced, NULL, NULL, "Never freed");
	    to_free = alloced;
	    alloced = trlr->next;
	    free(to_free);
	}
    }
}

void *
ipmi_mem_alloc(int size)
{
    if (DEBUG_MALLOC) {
	void *tb[TB_SIZE+1];
	memset(tb, 0, sizeof(tb));
	backtrace(tb, TB_SIZE+1);
	return ipmi_debug_malloc(size, tb+1);
    } else
	return malloc(size);
}

void
ipmi_mem_free(void *data)
{
    if (DEBUG_MALLOC) {
	void *tb[TB_SIZE+1];
	memset(tb, 0, sizeof(tb));
	backtrace(tb, TB_SIZE+1);
	ipmi_debug_free(data, tb+1);
    } else
	free(data);
}

void *
ilist_mem_alloc(size_t size)
{
    return ipmi_mem_alloc(size);
}

void
ilist_mem_free(void *data)
{
    ipmi_mem_free(data);
}
