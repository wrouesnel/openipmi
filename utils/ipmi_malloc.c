/*
 * ipmi_malloc.c
 *
 * MontaVista IPMI memory handling code.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <config.h>
#include <string.h>

#ifdef HAVE_EXECINFO_H
#include <execinfo.h> /* For backtrace() */
#endif

#include <OpenIPMI/ipmi_log.h>
#include <OpenIPMI/os_handler.h>

#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/ilist.h>

void (*ipmi_malloc_log)(enum ipmi_log_type_e log_type, const char *format, ...)
#if __GNUC__ > 2
     __attribute__ ((__format__ (__printf__, 2, 3)))
#endif
 = NULL;

#define DBG_ALIGN 16

#define TB_SIZE 6

#define SIGNATURE 0x82c2e45a
#define FREE_SIGNATURE 0xb981cef1
#define BYTE_SIGNATURE 0x74

int __ipmi_debug_malloc = 0;

os_handler_t *malloc_os_hnd;

struct dbg_malloc_header
{
    unsigned long signature;
    unsigned long size;
    /*
     * The following tb is included even if !HAVE_EXECINFO_H, because
     * it is used to detect buffer underruns.
     */
    void          *tb[TB_SIZE];
};

struct dbg_malloc_trailer
{
    /*
     * The following tb is included even if !HAVE_EXECINFO_H, because
     * it is used to detect buffer overruns.
     */
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
    size_t                    i;
    size_t                    real_size;

    real_size = dbg_align(size);

    data = malloc_os_hnd->mem_alloc(real_size
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
#ifdef HAVE_EXECINFO_H
    int  i;
#endif

    if (!ipmi_malloc_log)
	return;

    ipmi_malloc_log(IPMI_LOG_DEBUG_START, "%s", text);
    if (hdr) {
	ipmi_malloc_log(IPMI_LOG_DEBUG_CONT,
		 " %ld bytes at %p",
		 hdr->size, data);
#ifdef HAVE_EXECINFO_H
	ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, ", allocated at");
	for (i=0; i<TB_SIZE && hdr->tb[i]; i++)
	    ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, " %p", hdr->tb[i]);
#endif
    } else if (data) {
	ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, " at %p", data);
    }
#ifdef HAVE_EXECINFO_H
    if (trlr) {
	ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, "\n originally freed at");
	for (i=0; i<TB_SIZE && trlr->tb[i]; i++)
	    ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, " %p", trlr->tb[i]);
    }
    if (tb) {
	ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, "\n  at");
	for (i=0; i<TB_SIZE && tb[i]; i++)
	    ipmi_malloc_log(IPMI_LOG_DEBUG_CONT, " %p", tb[i]);
    }
#endif
    ipmi_malloc_log(IPMI_LOG_DEBUG_END, " ");
}

static void
dbg_remove_free_queue(void)
{
    struct dbg_malloc_header  *hdr;
    struct dbg_malloc_trailer *trlr;
    size_t                    real_size;
    unsigned long             *dp;
    size_t                    i;
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
    dp = (unsigned long *) data;
    for (i=0; i<real_size; i+=sizeof(unsigned long), dp++)
	if (*dp != FREE_SIGNATURE)
	    overwrite = 1;
    if (overwrite)
	mem_debug_log(data, hdr, trlr, NULL, "Write while free");

 out:
    malloc_os_hnd->mem_free(hdr);
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
    free_queue_len++;
}

static void
ipmi_debug_free(void *to_free, void **tb)
{
    struct dbg_malloc_header  *hdr;
    struct dbg_malloc_trailer *trlr;
    struct dbg_malloc_trailer *trlr2;
    size_t                    i;
    size_t                    real_size;
    unsigned long             *dp;
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
	if (alloced_tail) {
	    trlr2 = trlr_from_hdr(alloced_tail);
	    trlr2->next = NULL;
	}
    }
    if (trlr->prev) {
	trlr2 = trlr_from_hdr(trlr->prev);
	trlr2->next = trlr->next;
    } else {
	alloced = trlr->next;
	if (alloced) {
	    trlr2 = trlr_from_hdr(alloced);
	    trlr2->prev = NULL;
	}
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
#ifdef HAVE_EXECINFO_H
    memcpy(trlr->tb, tb, sizeof(trlr->tb));
#endif

    /* Fill the data area with a signature. */
    dp = (unsigned long *) (((char *) hdr) + sizeof(*hdr));
    for (i=0; i<real_size; i+=sizeof(unsigned long), dp++)
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
	}
    }
}

void *
ipmi_mem_alloc(int size)
{
    void          *rv;
    unsigned char *c;
    static int    seed;
    int           i;

    if (DEBUG_MALLOC) {
#ifdef HAVE_EXECINFO_H
	void *tb[TB_SIZE+1];
	memset(tb, 0, sizeof(tb));
	backtrace(tb, TB_SIZE+1);
	rv = ipmi_debug_malloc(size, tb+1);
#else
	rv = ipmi_debug_malloc(size, NULL);
#endif
	if (rv) {
	    c = rv;
	    /* Fill it with junk to catch using before initializing. */
	    for (i=0; i<size; i++)
		*c++ = i + seed;
	    seed += size;
	}
	return rv;
    } else
	return malloc_os_hnd->mem_alloc(size);
}

void
ipmi_mem_free(void *data)
{
    if (DEBUG_MALLOC) {
#ifdef HAVE_EXECINFO_H
	void *tb[TB_SIZE+1];
	memset(tb, 0, sizeof(tb));
	backtrace(tb, TB_SIZE+1);
	ipmi_debug_free(data, tb+1);
#else
	ipmi_debug_free(data, NULL);
#endif
    } else
	malloc_os_hnd->mem_free(data);
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

char *
ipmi_strdup(const char *str)
{
    char *rv = ipmi_mem_alloc(strlen(str)+1);

    if (!rv)
	return NULL;

    strcpy(rv, str);
    return rv;
}

char *
ipmi_strndup(const char *str, int n)
{
    int  length;
    char *rv = ipmi_mem_alloc(strlen(str)+1);

    for (length=0; length<n; length++) {
	if (! str[length])
	    break;
    }

    rv = ipmi_mem_alloc(length+1);
    if (!rv)
	return NULL;

    memcpy(rv, str, length);

    return rv;
}

int
ipmi_malloc_init(os_handler_t *os_hnd)
{
    malloc_os_hnd = os_hnd;
    return 0;
}
