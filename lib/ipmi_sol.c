/*
 * ipmi_sol.c
 *
 * IPMI Serial-over-LAN Client Code
 *
 * Author: Cyclades Australia Pty. Ltd.
 *         Darius Davis <darius.davis@cyclades.com>
 *
 * Copyright 2005 Cyclades Australia Pty. Ltd.
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

/*
 * TODO:
 *	- We only support UDP port 623 for now.  Add support for other ports.
 *
 * CAVEATS:
 *	- Multiple connections at once: should work, but UNTESTED.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/ipmi_sol.h>

/* FIXME - after processing waiting packets, a transmitter prod may be
   necessary in some cases.  Figure out where. */


/*
 * Locking notes:
 *
 * You may claim the queue_lock or the oob_lock if you already hold
 * packet_lock.  The reverse is not allowed.  You may not claim the
 * oob_lock and the queue lock at the same time.
 *
 * You may not hold the conn_lock with any other lock; use the
 * refcounts instead.
 *
 * The packet_lock is the "general" lock for the connection; it
 * protects the non-atomic data updates that would affect the
 * operation of the connection.
 *
 * No locks may be held in user callbacks.  All the do_xxx_callbacks()
 * functions must be called with the packet lock held.  They will
 * release the packet lock and reclaim it.  These functions are
 * responsible for serializing
 */

/*
 * Bit masks for status conditions sent BMC -> console, see Table 15-2
 * [1], page 208, 3rd column.
 */
#define IPMI_SOL_STATUS_NACK_PACKET 0x40
#define IPMI_SOL_STATUS_CHARACTER_TRANSFER_UNAVAIL 0x20
#define IPMI_SOL_STATUS_DEACTIVATED 0x10
#define IPMI_SOL_STATUS_BMC_TX_OVERRUN 0x08
#define IPMI_SOL_STATUS_BREAK_DETECTED 0x04


/*
 * Bit masks for operations sent console -> BMC, see Table 15-2 [1],
 * page 208, 4th column.
 */
#define IPMI_SOL_OPERATION_NACK_PACKET 0x40
#define IPMI_SOL_OPERATION_RING_REQUEST 0x20
#define IPMI_SOL_OPERATION_GENERATE_BREAK 0x10
#define IPMI_SOL_OPERATION_CTS_PAUSE 0x08
#define IPMI_SOL_OPERATION_DROP_DCD_DSR 0x04
#define IPMI_SOL_OPERATION_FLUSH_CONSOLE_TO_BMC 0x02
#define IPMI_SOL_OPERATION_FLUSH_BMC_TO_CONSOLE 0x01


#define IPMI_SOL_AUX_USE_ENCRYPTION 0x80
#define IPMI_SOL_AUX_USE_AUTHENTICATION 0x40
#define IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT 2
#define IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_MASK 0x03
#define IPMI_SOL_AUX_DEASSERT_HANDSHAKE 0x02


#define IPMI_SOL_MAX_DATA_SIZE 103

#if 0
#define IPMI_SOL_DEBUG_TRANSMIT
#define IPMI_SOL_VERBOSE
#define IPMI_SOL_DEBUG_RECEIVE
#endif


typedef struct ipmi_sol_transmitter_context_s ipmi_sol_transmitter_context_t;


/**
 * Stores a list of generic callback functions.  Values are to be typecast as
 * they are extracted.
 */
typedef struct callback_list_s callback_list_t;
struct callback_list_s {
    void            *cb;
    void            *cb_data;
    int             error;
    callback_list_t *next;
};

/**
 * Stores a write-request from the client software, along with its transmit
 * complete callback and in-band operation mask (currently used only for serial
 * breaks).
 */
typedef struct ipmi_sol_outgoing_queue_item_s ipmi_sol_outgoing_queue_item_t;
struct ipmi_sol_outgoing_queue_item_s {
    /* The bytes to transmit.  This will be NULL if the queue item
       represents a BREAK. */
    char *data;

    /* The number of bytes in this packet.  Will be zero if the queue
       item represents a BREAK. */
    unsigned char data_len;

    /* The in-band (sequential) operation.  Should only contain
       IPMI_SOL_GENERATE_BREAK for now. */
    unsigned char ib_op;
	
    /* The callback to call when the data (or BREAK) have been ACKed
       or sent. */
    ipmi_sol_transmit_complete_cb transmit_complete_callback;
    void *cb_data;

    ipmi_sol_outgoing_queue_item_t *next;
};



/**
 * Outgoing write-requests are queued for transmission as the SoL channel
 * is available.  This structure stores the queue.
 */
typedef struct ipmi_sol_outgoing_queue_s {
    ipmi_sol_outgoing_queue_item_t *head;
    ipmi_sol_outgoing_queue_item_t *tail;
} ipmi_sol_outgoing_queue_t;


/**
 * Offsets of fields within the SoL packet
 */
#define PACKET_SEQNR 0
#define PACKET_ACK_NACK_SEQNR 1
#define PACKET_ACCEPTED_CHARACTER_COUNT 2
#define PACKET_OP 3
#define PACKET_STATUS 3
#define PACKET_DATA 4

typedef struct ipmi_sol_outgoing_packet_record_s {
    /* OS handler for freeing the timer. */
    os_handler_t *os_hnd;

    /* The connection that owns this packet. */
    ipmi_sol_conn_t *conn;

    /* The outgoing SoL payload data.  Min 4 bytes long. */
    unsigned char *packet;

    /* The length of the outgoing SoL payload data. */
    int packet_size;

    /* The timer to manage retransmits.  Needs a lock for concurrency
       handling. */
    int deleted;
    int timer_running;
    ipmi_lock_t *timer_lock;
    os_hnd_timer_id_t *ack_timer;

    /* Nonzero iff we're expecting an ACK for this packet. */
    int expecting_ACK;

    /* Countdown of number of transmission attempts left before we
       declare the packet "lost". */
    int transmit_attempts_remaining;

    /* callbacks for operations in this packet. */
    callback_list_t *op_callback_list;
} ipmi_sol_outgoing_packet_record_t;


/* Used to keep a list of incoming packets to process. */
typedef struct sol_in_packet_info_s
{
    unsigned int  data_len;

    struct sol_in_packet_info_s *next;

    /* Data is tacked on to the end of this. */
} sol_in_packet_info_t;

/* Used to keep a list of pending state transitions. */
typedef struct sol_state_cb_info_s
{
    ipmi_sol_state state;
    int            error;

    struct sol_state_cb_info_s *next;
} sol_state_cb_info_t;

struct ipmi_sol_transmitter_context_s {
    /* A queue of un-acked transmit requests. */
    ipmi_sol_outgoing_queue_t outgoing_queue;

    /* A reference back to the SoL connection to which this
       transmitter belongs. */
    ipmi_sol_conn_t *sol_conn;

    /* The latest entire packet transmitted is stored here. */
    ipmi_sol_outgoing_packet_record_t *transmitted_packet;

    /* A buffer into which the data is coalesced for transmission. */
    unsigned char *scratch_area;

    /* The size of the scratch_area buffer. */
    int scratch_area_size;

    /* Keep track of the sequence number that we've most recently sent. */
    int latest_outgoing_seqnr;

    /* Next outgoing packet will ACK/NACK this packet. */
    int packet_to_acknowledge;

    /* We accepted this many chars from the above packet. */
    int accepted_character_count;

    /* Nack returns pending that we need release_nack calls for. */
    int nack_count;

    /* Are we currently in a receive callback? */
    int in_recv_cb;

    /* We have already acked this many chars from the request at the
       head of the tx queue. */
    int bytes_acked_at_head;

    /* Lock for the op callback list and the op data. */
    ipmi_lock_t   *oob_op_lock;

    /* a combination of IPMI_SOL_OPERATION_RING_REQUEST,
       IPMI_SOL_OPERATION_CTS_PAUSE,
       IPMI_SOL_OPERATION_DROP_DCD_DSR */
    unsigned char oob_persistent_op;

    /* a combination of IPMI_SOL_OPERATION_FLUSH_CONSOLE_TO_BMC,
       IPMI_SOL_OPERATION_FLUSH_BMC_TO_CONSOLE */
    unsigned char oob_transient_op;

    /* callbacks for operations currently in oob_persistent_op and
       oob_transient_op but not yet transmitted */
    callback_list_t *op_callback_list;

    /* Locking for queue operations and packet operations */
    ipmi_lock_t *queue_lock, *packet_lock;
};

struct ipmi_sol_conn_s {
    /* The IPMI connection for commands. */
    ipmi_con_t *ipmi;

    /* The IPMI connection for SOL data. */
    ipmi_con_t *ipmid;

    /* Used to know how many users are using this right now. */
    unsigned int refcount;

    /* The system interface address is cached here for sending RMCP+
       commands. */
    ipmi_system_interface_addr_t addr;

    /* The RMCP+ destination address is cached here for sending SoL
       packets. */
    ipmi_rmcpp_addr_t sol_payload_addr;

    unsigned char initial_bit_rate;
    unsigned char privilege_level;

    /* Nonzero allows ipmi_sol_open to alter the nonvolatile
       configuration to force SoL to come up if at all possible.  Only
       for debugging, please! */
    int force_connection_configure;

    /* Connects more quickly, but will give a lot less diagnostic info
       if it fails. */
    int try_fast_connect;

    /* The current state of the SoL connection.  Note that state
       changes are protected by the packet lock. */
    ipmi_sol_state state;

    /* Max payload size outbound from here->BMC */
    unsigned int max_outbound_payload_size;

    /* Max payload size inbound from BMC->here */
    unsigned int max_inbound_payload_size;

    unsigned int payload_port_number;

    /* We choose a payload instance number when activating the SoL payload */
    unsigned int payload_instance;

    /* This is the transmitter for this connection */
    ipmi_sol_transmitter_context_t transmitter;

    /* The last sequence number we received from the BMC. */
    unsigned char prev_received_seqnr;

    /* The number of characters we ACKed in the last packet received
       from the BMC. */
    unsigned char prev_character_count;

    /* Configuration data used at Payload Activation */
    unsigned char auxiliary_payload_data;
    int ACK_timeout_usec;
    int ACK_retries;

    /* A list of callbacks that are called when data received from the BMC. */
    locked_list_t *data_received_callback_list;

    /* A list of callbacks that are called when a break is reported by
       the BMC. */
    locked_list_t *break_detected_callback_list;

    /* A list of callbacks that are called when a transmit overrun is
       reported by the BMC. */
    locked_list_t *bmc_transmit_overrun_callback_list;

    /* A list of callbacks that are called when the SoL connection
       changes state. */
    locked_list_t *connection_state_callback_list;

    /* We single-thread the processing of packets for a connection.
       New packets get queued to be process later if processing is
       already going on. The following handle this. */
    unsigned int         processing_packet;
    sol_in_packet_info_t *waiting_packets;
    callback_list_t      *waiting_callbacks;
    sol_state_cb_info_t  *waiting_states;

    /* Used to make a linked-list of these */
    ipmi_sol_conn_t *next;
};


static int transmitter_startup(ipmi_sol_transmitter_context_t *transmitter);
static void transmitter_shutdown(ipmi_sol_transmitter_context_t *transmitter,
				 int error);
static void transmitter_prod_nolock
    (ipmi_sol_transmitter_context_t *transmitter);
static void process_packet(ipmi_sol_conn_t *conn,
			   unsigned char   *packet,
			   unsigned int    data_len);

static void
dump_hex(unsigned char *data, int len)
{
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	}
	ipmi_log(IPMI_LOG_DEBUG_CONT, " %2.2x", data[i]);
    }
}


/****************************************************************************
 * SoL Connection List
 *
 * Used to match up an incoming packet with the SoL connection that should
 * be interested in that packet.
 */

/* FIXME - a list is ineffecient for large numbers of connections.  It
   probably doesn't matter for now, but a hash table might be a good
   idea in the future. */

static ipmi_sol_conn_t *conn_list = NULL;
static ipmi_lock_t *conn_lock = NULL;

/**
 * Adds the given (ipmi, sol) pairing to the list of connections we're
 * managing.
 */
static int
add_connection(ipmi_sol_conn_t *nconn)
{
    ipmi_sol_conn_t *conn;

    ipmi_lock(conn_lock);

    /* Make sure the connection doesn't already exist */
    conn = conn_list;
    while (conn) {
	if (conn->ipmi == nconn->ipmi) {
	    ipmi_unlock(conn_lock);
	    return EAGAIN;
	}
	conn = conn->next;
    }

    nconn->next = conn_list;
    conn_list = nconn;
    ipmi_unlock(conn_lock);
    return 0;
}


/**
 * Removes the given connection from the list of connections we're managing.
 */
static void delete_connection(ipmi_sol_conn_t *sol)
{
    ipmi_sol_conn_t *curr;
    ipmi_sol_conn_t *prev = NULL;

    ipmi_lock(conn_lock);
    curr = conn_list;
    while (curr) {
	if (curr == sol) {
	    /*
	     * Delete me!
	     */
	    if (!prev)
		/* Deleting from head of list... */
		conn_list = conn_list->next;
	    else
		/* Deleting from within list */
		prev->next = curr->next;
	    break;
	}

	prev = curr;
	curr = curr->next;
    }
    ipmi_unlock(conn_lock);
}


/**
 * Finds the sol connection for a given ipmi connection.
 */
static ipmi_sol_conn_t *
find_sol_connection_for_ipmi(ipmi_con_t *ipmi)
{
    ipmi_sol_conn_t *conn;

    ipmi_lock(conn_lock);
    conn = conn_list;
    while (conn) {
	if (conn->ipmi == ipmi) {
	    conn->refcount++;
	    ipmi_unlock(conn_lock);
	    return conn;
	}
	conn = conn->next;
    }
    ipmi_unlock(conn_lock);

    return NULL;
}

static ipmi_sol_conn_t *
find_sol_connection(ipmi_sol_conn_t *sol)
{
    ipmi_sol_conn_t *conn;

    ipmi_lock(conn_lock);
    conn = conn_list;
    while (conn) {
	if (conn == sol) {
	    conn->refcount++;
	    ipmi_unlock(conn_lock);
	    return conn;
	}
	conn = conn->next;
    }
    ipmi_unlock(conn_lock);

    return NULL;
}


static void
sol_cleanup(ipmi_sol_conn_t *conn)
{
    if (conn->state != ipmi_sol_state_closed)
	ipmi_sol_force_close(conn);

    delete_connection(conn);

    while (conn->waiting_packets) {
	sol_in_packet_info_t *to_free = conn->waiting_packets;

	conn->waiting_packets = to_free->next;
	ipmi_mem_free(to_free);
    }

    conn->ipmi->close_connection(conn->ipmi);
    if (conn->transmitter.packet_lock)
	ipmi_destroy_lock(conn->transmitter.packet_lock);
    if (conn->transmitter.queue_lock)
	ipmi_destroy_lock(conn->transmitter.queue_lock);
    if (conn->transmitter.oob_op_lock)
	ipmi_destroy_lock(conn->transmitter.oob_op_lock);
    if (conn->data_received_callback_list)
	locked_list_destroy(conn->data_received_callback_list);
    if (conn->break_detected_callback_list)
	locked_list_destroy(conn->break_detected_callback_list);
    if (conn->bmc_transmit_overrun_callback_list)
	locked_list_destroy(conn->bmc_transmit_overrun_callback_list);
    if (conn->connection_state_callback_list)
	locked_list_destroy(conn->connection_state_callback_list);
    ipmi_mem_free(conn);
}

/**
 * Tell the system that a user is done with the connection.
 */
static void
sol_put_connection(ipmi_sol_conn_t *conn)
{
    ipmi_lock(conn_lock);
    conn->refcount--;
    if (conn->refcount == 0) {
	/* No more users, destroy the connection. */
	ipmi_unlock(conn_lock);
	sol_cleanup(conn);
    } else
	ipmi_unlock(conn_lock);
}


/***************************************************************************
 ** Shorthand IPMI messaging; used to set up or close an ipmi_sol_conn_t.
 ** This is NOT used for handling the SoL data... for that, see the payload
 ** functions towards the end of this file.
 **
 ** Note that the packet lock will be held in the callback.
 **/

typedef void (*sol_command_callback)(ipmi_sol_conn_t *conn, ipmi_msg_t *msg);

static int handle_response(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_sol_conn_t      *conn = find_sol_connection(rspi->data1);
    sol_command_callback cb = rspi->data2;

    if (! conn)
	/* Connection went away while in progress... */
	goto out;

    if (cb) {
	ipmi_lock(conn->transmitter.packet_lock);
	cb(conn, &rspi->msg);
	ipmi_unlock(conn->transmitter.packet_lock);
    }

    sol_put_connection(conn);
 out:
    ipmi_free_msg_item(rspi);
    return IPMI_MSG_ITEM_USED;
}


static int
send_message(ipmi_sol_conn_t      *conn,
	     ipmi_msg_t           *msg_out,
	     sol_command_callback cb)
{
    int rv = 0;
    ipmi_msgi_t *rspi = ipmi_alloc_msg_item();

    if (!rspi)
	return ENOMEM;

    rspi->data1 = conn;
    rspi->data2 = cb;
    rspi->data3 = NULL;
    rspi->data4 = NULL;
    rv = conn->ipmi->send_command(conn->ipmi,
				  (ipmi_addr_t *)&conn->addr,
				  sizeof(conn->addr),
				  msg_out,
				  handle_response,
				  rspi);

    if (rv)
	ipmi_free_msg_item(rspi);

    return rv;
}

static int
send_close(ipmi_sol_conn_t *conn, sol_command_callback cb)
{
    ipmi_msg_t    msg_out;
    unsigned char data[6];

    /*
     * Send a Deactivate Payload
     */
    msg_out.data_len = 6;
    msg_out.data = data;

    msg_out.data[0] = IPMI_RMCPP_PAYLOAD_TYPE_SOL & 0x3f; /* payload type */
    msg_out.data[1] = conn->payload_instance; /* payload instance number */
    msg_out.data[2] = 0x00; /* payload aux data */
    msg_out.data[3] = 0x00;
    msg_out.data[4] = 0x00;
    msg_out.data[5] = 0x00;

    msg_out.netfn = IPMI_APP_NETFN;
    msg_out.cmd = IPMI_DEACTIVATE_PAYLOAD_CMD;

    return send_message(conn, &msg_out, cb);
}


/****************************************************************************
 ** Async callback handling - list management, registration, deregistration
 **/

typedef struct do_data_received_callback_s
{
    ipmi_sol_conn_t *conn;
    const void      *buf;
    size_t          count;
    int             nack;
} do_data_received_callback_t;

static int
do_data_received_callback(void *cb_data, void *item1, void *item2)
{
    do_data_received_callback_t *info = cb_data;
    ipmi_sol_data_received_cb   cb = item1;
    
    if (cb(info->conn, info->buf, info->count, item2))
	info->nack++;
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
do_data_received_callbacks(ipmi_sol_conn_t *conn,
			   const void      *buf,
			   size_t          count)
{
    do_data_received_callback_t    info;

    info.conn = conn;
    info.buf = buf;
    info.count = count;
    info.nack = 0;
    locked_list_iterate(conn->data_received_callback_list,
			do_data_received_callback,
			&info);

    /* Only called from the packet handling routine, no need for any
       special handling. for waiting */
    return info.nack;
}

static int
do_break_detected_callback(void *cb_data, void *item1, void *item2)
{
    ipmi_sol_conn_t            *conn = cb_data; 
    ipmi_sol_break_detected_cb cb = item1;
    
    cb(conn, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
do_break_detected_callbacks(ipmi_sol_conn_t *conn)
{
    locked_list_iterate(conn->break_detected_callback_list,
			do_break_detected_callback,
			conn);

    /* Only called from the packet handling routine, no need for any
       special handling. for waiting */
}

static int
do_transmit_overrun_callback(void *cb_data, void *item1, void *item2)
{
    ipmi_sol_conn_t                  *conn = cb_data; 
    ipmi_sol_bmc_transmit_overrun_cb cb = item1;
    
    cb(conn, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
do_transmit_overrun_callbacks(ipmi_sol_conn_t *conn)
{
    locked_list_iterate(conn->bmc_transmit_overrun_callback_list,
			do_transmit_overrun_callback,
			conn);

    /* Only called from the packet handling routine, no need for any
       special handling. for waiting */
}

typedef struct do_connection_state_callback_s
{
    ipmi_sol_conn_t *conn;
    ipmi_sol_state  state;
    int             error;
} do_connection_state_callback_t;

static int
do_connection_state_callback(void *cb_data, void *item1, void *item2)
{
    do_connection_state_callback_t *info = cb_data;
    ipmi_sol_connection_state_cb   cb = item1;
    
    cb(info->conn, info->state, info->error, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
do_connection_state_callbacks(ipmi_sol_conn_t *conn,
			      ipmi_sol_state  new_state,
			      int             error)
{
    do_connection_state_callback_t info;

    info.conn = conn;
    info.state = new_state;
    info.error = error;
    locked_list_iterate(conn->connection_state_callback_list,
			do_connection_state_callback,
			&info);
}

int
ipmi_sol_register_data_received_callback(ipmi_sol_conn_t           *conn,
					 ipmi_sol_data_received_cb cb,
					 void                      *cb_data)
{
    if (locked_list_add(conn->data_received_callback_list, cb, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_sol_deregister_data_received_callback(ipmi_sol_conn_t           *conn,
					   ipmi_sol_data_received_cb cb,
					   void                      *cb_data)
{
    if (locked_list_remove(conn->data_received_callback_list, cb, cb_data))
	return 0;
    else
	return EINVAL;
}


int
ipmi_sol_register_break_detected_callback(ipmi_sol_conn_t            *conn,
					  ipmi_sol_break_detected_cb cb,
					  void                       *cb_data)
{
    if (locked_list_add(conn->break_detected_callback_list, cb, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_sol_deregister_break_detected_callback(ipmi_sol_conn_t            *conn,
					    ipmi_sol_break_detected_cb cb,
					    void                      *cb_data)
{
    if (locked_list_remove(conn->break_detected_callback_list, cb, cb_data))
	return 0;
    else
	return EINVAL;
}


int
ipmi_sol_register_bmc_transmit_overrun_callback(ipmi_sol_conn_t *conn,
						ipmi_sol_bmc_transmit_overrun_cb cb,
						void *cb_data)
{
    if (locked_list_add(conn->bmc_transmit_overrun_callback_list, cb, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_sol_deregister_bmc_transmit_overrun_callback(ipmi_sol_conn_t *conn,
						  ipmi_sol_bmc_transmit_overrun_cb cb,
						  void *cb_data)
{
    if (locked_list_remove(conn->bmc_transmit_overrun_callback_list, cb,
			   cb_data))
	return 0;
    else
	return EINVAL;
}


int
ipmi_sol_register_connection_state_callback(ipmi_sol_conn_t              *conn,
					    ipmi_sol_connection_state_cb cb,
					    void                       *cb_data)
{
    if (locked_list_add(conn->connection_state_callback_list, cb, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_sol_deregister_connection_state_callback(ipmi_sol_conn_t         *conn,
					      ipmi_sol_connection_state_cb cb,
					      void                    *cb_data)
{
    if (locked_list_remove(conn->connection_state_callback_list, cb, cb_data))
	return 0;
    else
	return EINVAL;
}


void
ipmi_sol_set_ACK_timeout(ipmi_sol_conn_t *conn, int timeout_usec)
{
    conn->ACK_timeout_usec = timeout_usec;
}

int
ipmi_sol_get_ACK_timeout(ipmi_sol_conn_t *conn)
{
    return conn->ACK_timeout_usec;
}

void
ipmi_sol_set_ACK_retries(ipmi_sol_conn_t *conn, int retries)
{
    conn->ACK_retries = retries;
}

int
ipmi_sol_get_ACK_retries(ipmi_sol_conn_t *conn)
{
    return conn->ACK_retries;
}


/******************************************************************************
 * SoL auxiliary payload data configuration
 *
 * These parameters will be set when the payload is activated:
 *	- authentication (enabled, disabled)
 *	- encryption (enabled, disabled)
 *	- shared serial alert behaviour (fail, defer, succeed)
 *	- Deassert DSR/DCD/CTS on connect (enabled, disabled)
 */

int
ipmi_sol_set_use_authentication(ipmi_sol_conn_t *conn,
				int             use_authentication)
{
    if (!conn)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    if (use_authentication)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_USE_AUTHENTICATION;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_USE_AUTHENTICATION;
    ipmi_unlock(conn->transmitter.packet_lock);
    
    return 0;
}


int
ipmi_sol_get_use_authentication(ipmi_sol_conn_t *conn)
{
    return ((conn->auxiliary_payload_data & IPMI_SOL_AUX_USE_AUTHENTICATION)
	    != 0);
}

int
ipmi_sol_set_use_encryption(ipmi_sol_conn_t *conn, int use_encryption)
{
    if (!conn)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    if (use_encryption)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_USE_ENCRYPTION;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_USE_ENCRYPTION;
    ipmi_unlock(conn->transmitter.packet_lock);

    return 0;
}

int
ipmi_sol_get_use_encryption(ipmi_sol_conn_t *conn)
{
    return ((conn->auxiliary_payload_data & IPMI_SOL_AUX_USE_ENCRYPTION)
	    != 0);
}


int
ipmi_sol_set_shared_serial_alert_behavior(ipmi_sol_conn_t *conn,
	ipmi_sol_serial_alert_behavior behavior)
{
    if (!conn)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    conn->auxiliary_payload_data
	&= ~(IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_MASK
	     << IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT);
    conn->auxiliary_payload_data
	|= behavior << IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT;
    ipmi_unlock(conn->transmitter.packet_lock);

    return 0;
}


ipmi_sol_serial_alert_behavior
ipmi_sol_get_shared_serial_alert_behavior(ipmi_sol_conn_t *conn)
{
    return (ipmi_sol_serial_alert_behavior)
	((conn->auxiliary_payload_data
	  >> IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT)
	 & IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_MASK);
}

int
ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(ipmi_sol_conn_t *conn,
					     int             deassert)
{
    if (!conn)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    if (deassert)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_DEASSERT_HANDSHAKE;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_DEASSERT_HANDSHAKE;
    ipmi_unlock(conn->transmitter.packet_lock);

    return 0;
}


int
ipmi_sol_get_deassert_CTS_DCD_DSR_on_connect(ipmi_sol_conn_t *conn)
{
    return ((conn->auxiliary_payload_data & IPMI_SOL_AUX_DEASSERT_HANDSHAKE)
	    != 0);
}


int ipmi_sol_set_bit_rate(ipmi_sol_conn_t *conn, unsigned char rate)
{
    if (!conn)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    conn->initial_bit_rate = rate;
    ipmi_unlock(conn->transmitter.packet_lock);

    return 0;
}

unsigned char
ipmi_sol_get_bit_rate(ipmi_sol_conn_t *conn)
{
    return conn->initial_bit_rate;
}


static void
do_and_destroy_transmit_complete_callbacks(callback_list_t *list,
					   ipmi_sol_conn_t *conn)
{
    callback_list_t *temp;

    while (NULL != list) {
	((ipmi_sol_transmit_complete_cb)list->cb)(conn, list->error,
						  list->cb_data);
	temp = list;
	list = list->next;
	ipmi_mem_free(temp);
    }
}


/*
 * Handle and packets that are waiting to be processed.
 */
static void
process_waiting_packets(ipmi_sol_conn_t *conn)
{
    while ((conn->waiting_packets) || conn->waiting_callbacks
	   || (conn->waiting_states))
    {
	while (conn->waiting_callbacks) {
	    callback_list_t *callbacks = conn->waiting_callbacks;
	    conn->waiting_callbacks = NULL;
	    ipmi_unlock(conn->transmitter.packet_lock);
	    do_and_destroy_transmit_complete_callbacks(callbacks, conn);
	    ipmi_lock(conn->transmitter.packet_lock);
	}

	if (conn->waiting_states) {
	    sol_state_cb_info_t *state = conn->waiting_states;
	    conn->waiting_states = state->next;
	    ipmi_unlock(conn->transmitter.packet_lock);
	    do_connection_state_callbacks(conn, state->state, state->error);
	    ipmi_mem_free(state);
	    ipmi_lock(conn->transmitter.packet_lock);
	    continue;
	}

	if (conn->waiting_packets) {
	    sol_in_packet_info_t *packet = conn->waiting_packets;
	    unsigned char        *pdata
		= ((unsigned char *) packet) + sizeof(*packet);

	    /* Connection may have closed during reporting information,
	       make sure to check this. */
	    if (conn->state == ipmi_sol_state_closed) {
		ipmi_log(IPMI_LOG_WARNING,
			 "ipmi_sol.c(sol_handle_recv_async): "
			 "Dropped incoming SoL packet: connection closed.");
		while (packet) {
		    sol_in_packet_info_t *npacket = packet->next;
		    ipmi_mem_free(packet);
		    packet = npacket;
		}
		conn->waiting_packets = NULL;
		return;
	    }

	    process_packet(conn, pdata, packet->data_len);
	    ipmi_mem_free(packet);
	    continue;
	}
    }
}

/**
 * Changes the currently recorded "state" for the SoL connection.
 *
 * Does nothing if the currently recorded state is the same as the new state.
 *
 * @param [in] conn	The SoL connection
 * @param [in] state	The new connection state
 * @param [in] error	The error value to pass to callbacks that are listening
 *			for connection state changes.
 */
static void
ipmi_sol_set_connection_state(ipmi_sol_conn_t *conn,
			      ipmi_sol_state  new_state,
			      int             error)
{
    if (conn->state == new_state)
	return;

    if (new_state == ipmi_sol_state_closed) {
	transmitter_shutdown(&conn->transmitter, error);
    } else if (((new_state == ipmi_sol_state_connected)
		|| (new_state == ipmi_sol_state_connected_ctu))
	       && (conn->state == ipmi_sol_state_connecting))
    {
	int rv = transmitter_startup(&conn->transmitter);
	if (rv) {
	    new_state = ipmi_sol_state_closed;
	    error = rv;
	}
    }

    conn->state = new_state;

    if (conn->processing_packet) {
	sol_state_cb_info_t *sp = ipmi_mem_alloc(sizeof(*sp));
	if (!sp) {
	    /* Yikes, no memory to store this.  Just log and give up. */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "ipmi_sol.c(ipmi_sol_set_connection_state): "
		     "Could not allocate memory to queue state change.");
	    
	}
	sp->state = new_state;
	sp->error = error;
	sp->next = NULL;
	if (conn->waiting_states) {
	    sol_state_cb_info_t *end = conn->waiting_states;
	    while (end->next)
		end = end->next;
	    end->next = sp;
	} else {
	    conn->waiting_states = sp;
	}
	return;
    }

    conn->processing_packet = 1;
    ipmi_unlock(conn->transmitter.packet_lock);
    do_connection_state_callbacks(conn, new_state, error);
    ipmi_lock(conn->transmitter.packet_lock);

    /* See if some other thread stuck some packets in for me to
       process.  Do that now. */
    process_waiting_packets(conn);

    conn->processing_packet = 0;
}


/*****************************************************************************
 ** IPMI SoL write operations
 **/
 
#ifdef IPMI_SOL_DEBUG_TRANSMIT
/**
 * Dump the transmitter state.
 */
static void
dump_transmitter_queue_state(ipmi_sol_transmitter_context_t *transmitter)
{
    /* DEBUG: Just dump the queue! */
    ipmi_lock(transmitter->queue_lock);
    printf("Outgoing queue: 0x%p\n", &transmitter->outgoing_queue);
    if (!transmitter->outgoing_queue)
	return;

    printf("   head: 0x%p\n"
	   "   tail: 0x%p\n", transmitter->outgoing_queue.head,
	   transmitter->outgoing_queue.tail
	   );
	
    printf("vvvvv Outgoing queue:\n");
    if (transmitter->outgoing_queue.head) {
	ipmi_sol_outgoing_queue_item_t *i = transmitter->outgoing_queue.head;
	while (i) {
	    printf("%p -> %d chars at %p -> [", i, i->data_len, i->data);
	    fflush(stdout);
	    int j;
	    for (j = 0; j < i->data_len; ++j)
		printf("%c", i->data[j]);
	    printf("]\n"); fflush(stdout);
	    i = i->next;
	}
    }
    else
	printf("is empty.");

    ipmi_unlock(transmitter->queue_lock);

    printf("^^^^^ Outgoing queue\n\n"); fflush(stdout);
}
#endif

static ipmi_sol_outgoing_packet_record_t *
transmitter_gather(ipmi_sol_transmitter_context_t *transmitter,
		   int                            control_only)
{
    int data_len = 0;
    unsigned char *ptr = &transmitter->scratch_area[0];
    ipmi_sol_outgoing_packet_record_t *new_packet_record = NULL;
    ipmi_sol_outgoing_queue_item_t *qi = transmitter->outgoing_queue.head;
    unsigned char ib_op = 0;
    unsigned int already_acked = transmitter->bytes_acked_at_head;

    if ((control_only || !qi)
	&& !transmitter->packet_to_acknowledge
	&& !transmitter->op_callback_list)
	/*
	 * Absolutely nothing to transmit.
	 */
	return NULL;

    if (!control_only) {
	/*
	 * Do the data gather into the transmitter scratch area
	 */
	while (qi && (data_len < transmitter->scratch_area_size)) {
	    /*
	     * Is this queue item a break?
	     */
	    if (0 == qi->data_len) {
		/*
		 * It's a break... can we add it to this packet?
		 */
		if (0 == data_len)
		    ib_op |= IPMI_SOL_OPERATION_GENERATE_BREAK;
		else
		    /*
		     * The data packet endeth here, if we want the break
		     * to occur at the right time (and we do...).
		     */
		    break;
	    } else {
		/*
		 * Data in this qi: Figure out how many chars we are going to
		 * copy.  Skip any bytes that the BMC has already ACKed,
		 * then limit our copy to fit within the buffer space.
		 */
		int copychars = qi->data_len - already_acked;
		if (copychars > transmitter->scratch_area_size - data_len)
		    copychars = transmitter->scratch_area_size - data_len;

		memcpy(ptr, &qi->data[already_acked], copychars);
		ptr += copychars;
		data_len += copychars;
		already_acked = 0;
	    }
	    qi = qi->next;
	}
    }
	
    /*
     * There's something there to send. Allocate the structure that
     * holds the packet info
     */
    new_packet_record = ipmi_mem_alloc(sizeof(*new_packet_record));
    if (!new_packet_record)
	return NULL;
    memset(new_packet_record, 0, sizeof(*new_packet_record));

    new_packet_record->packet_size = 4 + data_len;

    new_packet_record->packet = ipmi_mem_alloc(new_packet_record->packet_size);
    if (!new_packet_record->packet) {
	ipmi_mem_free(new_packet_record);
	return NULL;
    }

    /*
     * Put the control and ack/nack information into the packet
     */
    new_packet_record->packet[PACKET_ACK_NACK_SEQNR]
	= transmitter->packet_to_acknowledge;
    if (! (transmitter->oob_transient_op & IPMI_SOL_OPERATION_NACK_PACKET))
	/* We have to ack the packet if we nack it, leave it around
	   for the release if we are nack-ing. */
	transmitter->packet_to_acknowledge = 0;

    new_packet_record->packet[PACKET_ACCEPTED_CHARACTER_COUNT]
	= transmitter->accepted_character_count;
    transmitter->accepted_character_count = 0;

    ipmi_lock(transmitter->oob_op_lock);
    new_packet_record->packet[PACKET_OP]
	= (transmitter->oob_transient_op | transmitter->oob_persistent_op
	   | ib_op);

    /* Transmitted NACK has to be cleared by the user */
    transmitter->oob_transient_op &= IPMI_SOL_OPERATION_NACK_PACKET;

    new_packet_record->op_callback_list = transmitter->op_callback_list;
    transmitter->op_callback_list = NULL;
    ipmi_unlock(transmitter->oob_op_lock);

    /*
     * Note here that control_only implies data_len==0.
     */
    new_packet_record->expecting_ACK = (data_len > 0);

    if (new_packet_record->expecting_ACK) {
	/* Data-bearing packet; will be ACKed (hopefully), needs a
	   sequence number and a retransmit count */
	new_packet_record->packet[PACKET_SEQNR]
	    = transmitter->latest_outgoing_seqnr++;
	if (transmitter->latest_outgoing_seqnr > 15)
	    transmitter->latest_outgoing_seqnr = 1;

	new_packet_record->transmit_attempts_remaining
	    = transmitter->sol_conn->ACK_retries;

	/* Give it the data */
	memcpy(&new_packet_record->packet[PACKET_DATA],
	       transmitter->scratch_area,
	       data_len);
    } else {
	/* Zero sequence number for control-only packet */
	new_packet_record->packet[PACKET_SEQNR] = 0;
    }

    new_packet_record->os_hnd = transmitter->sol_conn->ipmi->os_hnd;

    return new_packet_record;
}


static void
do_outstanding_op_callbacks(ipmi_sol_transmitter_context_t *transmitter,
			    int                            error)
{
    callback_list_t *callbacks;
    callback_list_t *end;
    ipmi_sol_conn_t *conn = transmitter->sol_conn;

    callbacks = transmitter->transmitted_packet->op_callback_list;
    if (!callbacks)
	return;
    transmitter->transmitted_packet->op_callback_list = NULL;

    end = callbacks;
    while (!end) {
	end->error = error;
	end = end->next;
    }

    if (conn->processing_packet) {
	if (conn->waiting_callbacks) {
	    end = conn->waiting_callbacks;
	    while (end->next)
		end = end->next;
	    end->next = callbacks;
	} else {
	    conn->waiting_callbacks = callbacks;
	}
	return;
    }

    conn->processing_packet = 1;
    ipmi_unlock(transmitter->packet_lock);
    do_and_destroy_transmit_complete_callbacks(callbacks,
					       transmitter->sol_conn);
    ipmi_lock(transmitter->packet_lock);

    /* See if some other thread stuck some packets in for me to
       process.  Do that now. */
    process_waiting_packets(conn);

    conn->processing_packet = 0;
}


/**
 * Get rid of any packet that we've recently transmitted and still
 * have in storage.
 *
 * MUST be called with the packet_lock held.
 *
 * @param [in] transmitter	The SoL transmitter
 * @param [in] error		The error code to return to any callbacks
 *				waiting on this packet or its data.
 */
static void
dispose_of_outstanding_packet(ipmi_sol_transmitter_context_t *transmitter,
			      int                            error)
{
    os_handler_t *os_hnd;
    int          rv = 0;
    ipmi_sol_outgoing_packet_record_t *packet
	= transmitter->transmitted_packet;

    if (!packet)
	return;
    
    if (packet->ack_timer) {
	os_hnd = transmitter->sol_conn->ipmi->os_hnd;

	ipmi_lock(packet->timer_lock);
	if (packet->timer_running)
	    rv = os_hnd->stop_timer(os_hnd, packet->ack_timer);
	if (! rv) {
	    ipmi_unlock(packet->timer_lock);
	    ipmi_destroy_lock(packet->timer_lock);
	    os_hnd->free_timer(os_hnd, packet->ack_timer);
	} else {
	    /* Tell the timer handler to throw the packet away, since
	       it's about to run. */
	    packet->deleted = 1;
	    ipmi_unlock(packet->timer_lock);
	    packet = NULL;
	}
    }

    do_outstanding_op_callbacks(transmitter, error);

    if (packet) {
	if (packet->packet)
	    ipmi_mem_free(packet->packet);

	ipmi_mem_free(packet);
    }
    transmitter->transmitted_packet = NULL;
}

/*
 * Must be called with the packet lock held.
 */
static int
transmit_outstanding_packet(ipmi_sol_transmitter_context_t *transmitter)
{
    int rv;
    /*
     * Pack the packet into a pseudo-IPMI message.
     */
    ipmi_msg_t msg;
    ipmi_con_option_t options[3];
    int                curr_opt = 0;
    ipmi_sol_conn_t   *conn = transmitter->sol_conn;

    options[curr_opt].option = IPMI_CON_MSG_OPTION_CONF;
    options[curr_opt].ival = ipmi_sol_get_use_encryption(conn);
    curr_opt++;
    options[curr_opt].option = IPMI_CON_MSG_OPTION_AUTH;
    options[curr_opt].ival = ipmi_sol_get_use_authentication(conn);
    curr_opt++;
    options[curr_opt].option = IPMI_CON_OPTION_LIST_END;

    msg.netfn = 1;
    msg.cmd = 0;
    msg.data = (unsigned char *)transmitter->transmitted_packet->packet;
    msg.data_len = transmitter->transmitted_packet->packet_size;

#ifdef IPMI_SOL_DEBUG_TRANSMIT
    printf("Sending a packet! %d bytes: ",
	   transmitter->transmitted_packet->packet_size);
    dump_hex(msg.data, msg.data_len);
    printf("That's it!\n");
    fflush(stdout);
#endif

    /*
     * And fire it off!
     */
    rv = conn->ipmid->send_command_option
	(conn->ipmi,
	 (ipmi_addr_t *)&transmitter->sol_conn->sol_payload_addr,
	 sizeof(transmitter->sol_conn->sol_payload_addr),
	 &msg,
	 options,
	 NULL, NULL);

    if (rv) {
	char buf[50];
	ipmi_log(IPMI_LOG_WARNING, "ipmi_sol.c(transmit_outstanding_packet): "
		 "ipmi_send_command_addr: [%s]",
		 ipmi_get_error_string(rv, buf, 50));
	dispose_of_outstanding_packet(transmitter, rv);
    }
    return rv;
}


/**
 * Handle expiration of the timer for a packet ACK.
 */
static void sol_ACK_timer_expired(void *cb_data, os_hnd_timer_id_t *id);

static int
setup_ACK_timer(ipmi_sol_transmitter_context_t *transmitter)
{
    struct timeval timeout;
    os_handler_t   *os_hnd;
    int            rv;
    ipmi_sol_outgoing_packet_record_t *packet
	= transmitter->transmitted_packet;

    os_hnd = transmitter->sol_conn->ipmi->os_hnd;

    ipmi_lock(packet->timer_lock);
    if (packet->timer_running) {
	ipmi_unlock(packet->timer_lock);
	ipmi_log(IPMI_LOG_WARNING, "ipmi_sol.c(setup_ACK_timer): "
		 "Timer start when timer was already running");
	return 0;
    }
    timeout.tv_sec = transmitter->sol_conn->ACK_timeout_usec / 1000000;
    timeout.tv_usec = transmitter->sol_conn->ACK_timeout_usec % 1000000;

    rv = os_hnd->start_timer(os_hnd,
			     packet->ack_timer,
			     &timeout,
			     sol_ACK_timer_expired,
			     packet);
    if (!rv)
	packet->timer_running = 1;
    ipmi_unlock(packet->timer_lock);
    return rv;
}

static void
sol_ACK_timer_expired(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_sol_transmitter_context_t    *transmitter;
    ipmi_sol_conn_t                   *conn;
    ipmi_sol_outgoing_packet_record_t *packet = cb_data;

#ifdef SOL_DEBUG_TRANSMIT
    printf("sol_ACK_timer_expired!\n");
#endif

    ipmi_lock(packet->timer_lock);
    if (packet->deleted) {
	/* Packet was deleted while the timer was going off, just
	   delete and return here. */
	ipmi_unlock(packet->timer_lock);
	if (packet->packet)
	    ipmi_mem_free(packet->packet);
	ipmi_destroy_lock(packet->timer_lock);
	packet->os_hnd->free_timer(packet->os_hnd, packet->ack_timer);
	ipmi_mem_free(packet);
	return;
    }
    packet->timer_running = 0;
    ipmi_unlock(packet->timer_lock);

    /* Get a refcount to the connection. */
    conn = find_sol_connection(packet->conn);
    if (!conn)
	return;

    transmitter = &conn->transmitter;

    ipmi_lock(transmitter->packet_lock);

    if (transmitter->transmitted_packet != packet)
	/* OK, the packet was ACKed, it seems... */
	goto out_unlock;

    packet->transmit_attempts_remaining--;
    if (packet->transmit_attempts_remaining == 0) {
	/*
	 * Didn't get a response even after retries... connection is lost.
	 */
	ipmi_sol_set_connection_state(transmitter->sol_conn,
				      ipmi_sol_state_closed,
				      IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));
    } else {
	int rv;

	transmit_outstanding_packet(transmitter);
	rv = setup_ACK_timer(transmitter);
	if (rv) {
	    char buf[50];
	    ipmi_log(IPMI_LOG_WARNING, "ipmi_sol.c(sol_ACK_timer_expired): "
		     "Unable to setup_ACK_timer: %s",
		     ipmi_get_error_string(rv, buf, 50));
	    dispose_of_outstanding_packet(transmitter, rv);
	    /* FIXME: What is the right error value? */
	}
    }
 out_unlock:
    ipmi_unlock(transmitter->packet_lock);
    sol_put_connection(conn);
}


static void transmitter_handle_acknowledge(ipmi_sol_conn_t *conn,
					   int             error,
					   int         cknowledged_char_count);

/**
 * Causes the transmitter to examine its transmit queue and to prepare a packet
 * for transmission if needed.
 *
 * Anything that gives the transmitter something to transmit (data or control)
 * should call this.
 *
 * Must be called with the packet lock held.
 */
static void
transmitter_prod_nolock(ipmi_sol_transmitter_context_t *transmitter)
{
    ipmi_sol_outgoing_packet_record_t *packet;

    /*
     * TODO: If we are awaiting an ACK and we get a data packet from
     * the remote system that doesn't ACK our outstanding packet,
     * perhaps we should be able to send back an ACK (and control)
     * packet immediately???  If so, we should keep going here, and
     * later call transmitter_gather(transmitter, 1) to collect a
     * strictly control-only packet (no BREAKs, either!).
     */
    if (transmitter->transmitted_packet) {
#ifdef IPMI_SOL_DEBUG_TRANSMIT
	ipmi_log(IPMI_LOG_INFO, "ipmi_sol.c(transmitter_prod_nolock): "
		 "exiting early:"
		 " already waiting for an ACK.");
#endif
	return;
    }

#ifdef IPMI_SOL_DEBUG_TRANSMIT
    dump_transmitter_queue_state(transmitter);
#endif

    /* TODO: PREFERABLY this should happen next time we enter the event 
     * loop,  not right away! This will allow for control and character
     * accumulation in a reasonable way. Think Nagling (!TCP_NODELAY). */

    if (! transmitter->transmitted_packet)
	transmitter->transmitted_packet = transmitter_gather(transmitter, 0);
    packet = transmitter->transmitted_packet;

    if (packet) {
	int rv = 0;

	if (packet->expecting_ACK) {
	    os_handler_t *os_hnd = transmitter->sol_conn->ipmi->os_hnd;
    
	    packet->conn = transmitter->sol_conn;
	    rv = ipmi_create_lock_os_hnd(os_hnd, &packet->timer_lock);
	    if (rv)
		goto handle_err;
	    rv = os_hnd->alloc_timer(os_hnd, &packet->ack_timer);
	    if (rv) {
		ipmi_destroy_lock(packet->timer_lock);
		goto handle_err;
	    }
	    packet->timer_running = 0;
	}

	if (!rv)
	    rv = transmit_outstanding_packet(transmitter);

    handle_err:
	if (rv) {
	    dispose_of_outstanding_packet(transmitter, rv);
	    return;
	}

	if (transmitter->transmitted_packet->expecting_ACK) {
	    rv = setup_ACK_timer(transmitter);
	    if (rv) {
		char buf[50];
		ipmi_log(IPMI_LOG_WARNING,
			 "ipmi_sol.c(transmitter_prod_nolock): "
			 "Unable to setup_ACK_timer: %s",
			 ipmi_get_error_string(rv, buf, 50));
		dispose_of_outstanding_packet(transmitter, rv);
		/* FIXME: What is the right error value? */
	    }
	} else {
	    /*
	     * This packet won't get an acknowledgement!  Dispose of
	     * it NOW, and do its callbacks.
	     */
	    int errval = IPMI_SOL_ERR_VAL(IPMI_SOL_UNCONFIRMABLE_OPERATION);
	    transmitter_handle_acknowledge(transmitter->sol_conn, errval, 0);
		 
	    dispose_of_outstanding_packet(transmitter, errval);
	}
    }
}

/**
 * Lock and call transmitter_prod_nolock()
 */
static void
transmitter_prod(ipmi_sol_transmitter_context_t *transmitter)
{
    ipmi_lock(transmitter->packet_lock);
    transmitter_prod_nolock(transmitter);
    ipmi_unlock(transmitter->packet_lock);
}

/**
 * Remove a packet from the head of the queue.  This should be called
 * only after an ACK has been received or it has been determined that
 * the packet will never be ACKed.
 */
static void
dequeue_head(ipmi_sol_transmitter_context_t *transmitter, int error)
{
    ipmi_sol_outgoing_queue_item_t *qitem;

    transmitter->bytes_acked_at_head = 0;
    qitem = transmitter->outgoing_queue.head;

    if (qitem) {
	if (qitem->transmit_complete_callback)
	    (qitem->transmit_complete_callback)(transmitter->sol_conn,
						error, qitem->cb_data);
	
	if (qitem->data)
	    ipmi_mem_free(qitem->data);
	
	transmitter->outgoing_queue.head = qitem->next;
	ipmi_mem_free(qitem);
	
	/* Deleting the last packet in the list? */
	if (NULL == transmitter->outgoing_queue.head)
	    transmitter->outgoing_queue.tail = NULL;
    }
}


/**
 * Remove all outgoing packets queued on the given transmitter.
 *
 * @param [in] transmitter	The transmitter to be flushed.
 */
static void
transmitter_flush_outbound(ipmi_sol_transmitter_context_t *transmitter,
			   int                            error)
{
    dispose_of_outstanding_packet(transmitter, error);

    ipmi_lock(transmitter->queue_lock);
    while (transmitter->outgoing_queue.head)
	dequeue_head(transmitter, error);
    ipmi_unlock(transmitter->queue_lock);
}


/**
 * Handle the acknowledgement of the given number of characters.
 * Note that acknowledged_character_count might be zero, if and only
 * if we have just sent out a packet with a BREAK and no data (in which
 * case, incidentally, "error" will be IPMI_SOL_UNCONFIRMABLE_OPERATION), and
 * we must dequeue the break only.
 */
static void
transmitter_handle_acknowledge(ipmi_sol_conn_t *conn,
			       int             error,
			       int             acknowledged_char_count)
{
    /*
     * Handle the in-band data by iterating through packets, and:
     *	1) Counting off how many bytes of this packet have been ACKed,
     *	2) When a packet is done, calling the IB callbacks, then disposing
     *     of it.
     */
#ifdef IPMI_SOL_DEBUG_RECEIVE
    ipmi_log(IPMI_LOG_INFO, "Received ACK for %d chars",
	     acknowledged_char_count);
#endif

    ipmi_sol_outgoing_queue_item_t *qitem;

    do {
	int avail_this_pkt;
	int this_ack;

	qitem = conn->transmitter.outgoing_queue.head;
	if (!qitem) {
	    if (acknowledged_char_count) {
		/*
		 * The BMC has acknowledged more than we've sent!
		 */
		ipmi_log(IPMI_LOG_WARNING,
			 "ipmi_sol.c(transmitter_handle_acknowledge): "
			 "The BMC has acknowledged more data than we sent."
			 " Ignoring excess ACK.");
	    }
	    return;
	}

	/*
	 * This will also work for BREAKs, stored as a zero-length transmit
	 * request.  They will be dequeued if they are at the start of the
	 * queue for this ACK.  They will also be dequeued if they are mid-
	 * queue for this ACK, but that SHOULD never occur.  They will
	 * NOT be dequeued if they are directly after the last completely
	 * ACKed request.  This also means that should two BREAKs be queued
	 * consecutively, only the first one will be dequeued if
	 * acknowledged_char_count is zero.
	 */

	avail_this_pkt = (qitem->data_len
			  - conn->transmitter.bytes_acked_at_head);
	if (avail_this_pkt < acknowledged_char_count)
	    this_ack = avail_this_pkt;
	else
	    this_ack = acknowledged_char_count;

	conn->transmitter.bytes_acked_at_head += this_ack;
	if (conn->transmitter.bytes_acked_at_head == qitem->data_len) {
	    /*
	     * This packet is DONE.
	     */
	    ipmi_lock(conn->transmitter.queue_lock);
	    dequeue_head(&conn->transmitter, error);
	    ipmi_unlock(conn->transmitter.queue_lock);
	}

	acknowledged_char_count -= this_ack;
    } while (acknowledged_char_count > 0);

    /*
     * Thus endeth the ACKing game.
     */
}


/**
 * Creates a new transmitter tail packet and adds it to the transmit queue.
 *
 * If count > 0, the given data bytes are added to the queue.  If count == 0,
 * this means a serial "break" to the transmitter.
 */
static int
add_to_transmit_queue(ipmi_sol_transmitter_context_t *tx,
		      const void                     *buf,
		      int                            count,
		      unsigned char                  ib_op,
		      ipmi_sol_transmit_complete_cb  cb,
		      void                           *cb_data)
{
    ipmi_sol_outgoing_queue_item_t *new_tail;

#ifdef IPMI_SOL_DEBUG_TRANSMIT
    dump_transmitter_queue_state(tx);
#endif

    new_tail = ipmi_mem_alloc(sizeof(*new_tail));
    if (!new_tail)
	return ENOMEM;

    if (count) {
	new_tail->data = ipmi_mem_alloc(count);
	if (!new_tail->data) {
	    ipmi_mem_free(new_tail);
	    return ENOMEM;
	}
	
	memcpy(new_tail->data, buf, count);
    } else
	new_tail->data = NULL;

    new_tail->data_len = count;
    new_tail->ib_op = ib_op;
    new_tail->transmit_complete_callback = cb;
    new_tail->cb_data = cb_data;
    new_tail->next = NULL;

    ipmi_lock(tx->queue_lock);

    if (tx->outgoing_queue.tail)
	tx->outgoing_queue.tail->next = new_tail;

    tx->outgoing_queue.tail = new_tail;

    /* Adding to a previously empty list? */
    if (!tx->outgoing_queue.head)
	tx->outgoing_queue.head = new_tail;

    ipmi_unlock(tx->queue_lock);

    transmitter_prod_nolock(tx);

    return 0;
}

/*
 * Must be called with oob_op_lock held.
 */
static int
add_op_control_callback(ipmi_sol_transmitter_context_t *tx, 
			ipmi_sol_transmit_complete_cb  cb,
			void                           *cb_data)
{
    callback_list_t *new_entry;
    callback_list_t *iter = tx->op_callback_list;

    new_entry = ipmi_mem_alloc(sizeof(*new_entry));
    if (!new_entry)
	return ENOMEM;

    new_entry->cb = cb;
    new_entry->cb_data = cb_data;
    new_entry->next = NULL;

    if (!iter) {
	tx->op_callback_list = new_entry;
    } else {
	while (NULL != iter->next)
	    iter = iter->next;

	/*
	 * iter points to the end of the list.
	 */
	iter->next = new_entry;
    }
    return 0;
}

static int
transmitter_startup(ipmi_sol_transmitter_context_t *transmitter)
{
    transmitter->scratch_area = ipmi_mem_alloc(transmitter->scratch_area_size);
    if (!transmitter->scratch_area) {
	/* Alloc failed! */
	ipmi_log(IPMI_LOG_SEVERE, "ipmi_sol.c(transmitter_startup): "
		 "Insufficient memory for transmitter scratch area.");
		
	return ENOMEM;
    }

    return 0;
}

static void
transmitter_shutdown(ipmi_sol_transmitter_context_t *transmitter, int error)
{
    transmitter_flush_outbound(transmitter, error);

    /* Free the memory being used by sundry parts */
    if (transmitter->scratch_area) {
	ipmi_mem_free(transmitter->scratch_area);
	transmitter->scratch_area = NULL;
    }
}


/*
 * ipmi_sol_write -
 *
 * Send a sequence of bytes to the remote.
 *	buf - the bytes to send.
 *	count - the number of bytes to send from the buffer.
 * This function (like all the others!) will either return an ERROR
 * and never call the callback, or will return no error and then WILL
 * call the callback, indicating an error later if necessary.  The
 * callback is an indication that the BMC has ACKed *all* of the bytes
 * in this request.  There is no guarantee that the packet will not be
 * fragmented or coalesced in transmission.
 */
int
ipmi_sol_write(ipmi_sol_conn_t               *conn,
	       const void                    *buf,
	       int                           count,
	       ipmi_sol_transmit_complete_cb cb,
	       void                          *cb_data)
{
    int rv;
    if (count <= 0)
	return EINVAL;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_connected)
	|| (conn->state == ipmi_sol_state_connected_ctu))
    {
	rv = add_to_transmit_queue(&conn->transmitter, buf, count, 0,
				   cb, cb_data);
    } else
	rv = EINVAL;
    ipmi_unlock(conn->transmitter.packet_lock);
    return rv;
}


/* 
 * ipmi_sol_release_nack -
 *
 * Remove any pending nacks.
 */
int
ipmi_sol_release_nack(ipmi_sol_conn_t *conn)
{
    int rv = 0;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->transmitter.in_recv_cb) {
	/* Raced with the receive callback, just mark it for the
	   receive callback to handle. */
	conn->transmitter.nack_count--;
	goto out;
    }
    if (! conn->transmitter.nack_count) {
	/* Nothing to NACK. */
	rv = EINVAL;
	goto out;
    }
    conn->transmitter.nack_count--;
    if (! conn->transmitter.nack_count) {
	/* Time to kick things off again. */
	conn->transmitter.oob_transient_op &= ~IPMI_SOL_OPERATION_NACK_PACKET;

	/* This is here just in case we decide that the accepted
	   character count in a NACK packet is the number of bytes
	   nack-ed. */
	conn->transmitter.accepted_character_count = 0;
	transmitter_prod_nolock(&conn->transmitter);
    }
 out:
    ipmi_unlock(conn->transmitter.packet_lock);
    return rv;
}

/* 
 * ipmi_sol_send_break -
 *
 * See ipmi_sol_write, except we're not sending any bytes, just a
 * serial "break".  Callback contract is the same as for
 * ipmi_sol_write.
 */
int
ipmi_sol_send_break(ipmi_sol_conn_t               *conn,
		    ipmi_sol_transmit_complete_cb cb,
		    void                          *cb_data)
{
    int rv;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_connected)
	|| (conn->state == ipmi_sol_state_connected_ctu))
    {
	rv = add_to_transmit_queue(&conn->transmitter, NULL, 0,
				   IPMI_SOL_OPERATION_GENERATE_BREAK,
				   cb, cb_data);
    } else
	rv = EINVAL;
    ipmi_unlock(conn->transmitter.packet_lock);
    return rv;
}


/* 
 * ipmi_sol_set_CTS_assertable -
 *
 * Asserts CTS at the BMC, to request that the system attached to the
 * BMC ceases transmitting characters.  No guarantee is given that the
 * BMC will honour this request.  Further buffered characters might
 * still be received after CTS is asserted.  See ipmi_sol_write,
 * except we're not sending any bytes, just changing control lines.
 * Callback contract is the same as for ipmi_sol_write.
 */
int
ipmi_sol_set_CTS_assertable(ipmi_sol_conn_t               *conn,
			    int                           assertable,
			    ipmi_sol_transmit_complete_cb cb,
			    void                          *cb_data)
{
    int rv;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_connected)
	|| (conn->state == ipmi_sol_state_connected_ctu))
    {
	ipmi_lock(conn->transmitter.oob_op_lock);
	if (assertable)
	    conn->transmitter.oob_persistent_op
		&= ~IPMI_SOL_OPERATION_CTS_PAUSE;
	else
	    conn->transmitter.oob_persistent_op
		|= IPMI_SOL_OPERATION_CTS_PAUSE;

	rv = add_op_control_callback(&conn->transmitter, cb, cb_data);
	ipmi_unlock(conn->transmitter.oob_op_lock);

	if (!rv)
	    transmitter_prod(&conn->transmitter);
    } else
	rv = EINVAL;
    ipmi_unlock(conn->transmitter.packet_lock);

    return rv;
}


/* 
 * ipmi_sol_set_DCD_DSR_asserted -
 *
 * Asserts DCD and DSR, as if we've answered the phone line.
 * 
 * See ipmi_sol_write, except we're not sending any bytes, just
 * changing control lines.  Callback contract is the same as for
 * ipmi_sol_write.
 */
int
ipmi_sol_set_DCD_DSR_asserted(ipmi_sol_conn_t               *conn,
			      int                           asserted,
			      ipmi_sol_transmit_complete_cb cb,
			      void                          *cb_data)
{
    int rv;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_connected)
	|| (conn->state == ipmi_sol_state_connected_ctu))
    {
	ipmi_lock(conn->transmitter.oob_op_lock);
	if (asserted)
	    conn->transmitter.oob_persistent_op
		&= ~IPMI_SOL_OPERATION_DROP_DCD_DSR;
	else
	    conn->transmitter.oob_persistent_op
		|= IPMI_SOL_OPERATION_DROP_DCD_DSR;

	rv = add_op_control_callback(&conn->transmitter, cb, cb_data);
	ipmi_unlock(conn->transmitter.oob_op_lock);

	if (!rv)
	    transmitter_prod(&conn->transmitter);
    } else
	rv = EINVAL;
    ipmi_unlock(conn->transmitter.packet_lock);

    return rv;
}


/* 
 * ipmi_sol_set_RI_asserted -
 *
 * Asserts RI, as if the phone line is ringing.
 * 
 * See ipmi_sol_write, except we're not sending any bytes, just
 * changing control lines.  Callback contract is the same as for
 * ipmi_sol_write.
 */
int
ipmi_sol_set_RI_asserted(ipmi_sol_conn_t               *conn,
			 int                           asserted,
			 ipmi_sol_transmit_complete_cb cb,
			 void                          *cb_data)
{
    int rv;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_connected)
	|| (conn->state == ipmi_sol_state_connected_ctu))
    {
	ipmi_lock(conn->transmitter.oob_op_lock);
	if (asserted)
	    conn->transmitter.oob_persistent_op
		|= IPMI_SOL_OPERATION_RING_REQUEST;
	else
	    conn->transmitter.oob_persistent_op
		&= ~IPMI_SOL_OPERATION_RING_REQUEST;

	rv = add_op_control_callback(&conn->transmitter, cb, cb_data);
	ipmi_unlock(conn->transmitter.oob_op_lock);

	if (!rv)
	    transmitter_prod(&conn->transmitter);
    } else
	rv = EINVAL;
    ipmi_unlock(conn->transmitter.packet_lock);

    return rv;
}


/**
 * Requests a flush of the transmit queue(s) identified by
 * queue_selector, which is a bitwise-OR of the following:
 *
 *	IPMI_SOL_BMC_TRANSMIT_QUEUE
 *	IPMI_SOL_BMC_RECEIVE_QUEUE
 *	IPMI_SOL_MANAGEMENT_CONSOLE_TRANSMIT_QUEUE
 *	IPMI_SOL_MANAGEMENT_CONSOLE_RECEIVE_QUEUE
 *
 * This operation will never use the callback if it returns an error.
 * 
 * If no error is returned, the callback will be called in a
 * synchronous fashion if it does not involve the BMC, asynchronous
 * otherwise.
 */

typedef struct ipmi_sol_flush_data_s {
    ipmi_sol_conn_t *conn;
    int selectors_flushed;
    int selectors_pending;
    ipmi_sol_flush_complete_cb cb;
    void *cb_data;
} ipmi_sol_flush_data_t;


static void
flush_finalize(ipmi_sol_conn_t *conn, int error, void *cb_data)
{
    ipmi_sol_flush_data_t *my = (ipmi_sol_flush_data_t *)cb_data;

    /*
     * Did the remote flush go OK?
     */
    if (!error) {
	/*
	 * Yep, the BMC has confirmed that the data has been flushed (or
	 * at least no error has occurred).
	 */
	my->selectors_flushed |= my->selectors_pending;
    }

    if (my->cb)
	my->cb(conn, error, my->selectors_flushed, my->cb_data);

    ipmi_mem_free(cb_data);
}


int
ipmi_sol_flush(ipmi_sol_conn_t            *conn,
	       int                        queue_selectors,
	       ipmi_sol_flush_complete_cb cb,
	       void                       *cb_data)
{
    int rv = 0;
    int need_callback = 0;

    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state != ipmi_sol_state_connected)
	&& (conn->state != ipmi_sol_state_connected_ctu))
    {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    /*
     * Do we flush the local transmit queue?
     */
    if (!rv
	&& (! (queue_selectors & IPMI_SOL_MANAGEMENT_CONSOLE_TRANSMIT_QUEUE)))
    {
	transmitter_flush_outbound(&conn->transmitter,
				   IPMI_SOL_ERR_VAL(IPMI_SOL_FLUSHED));
    }

    /*
     * Do we flush the local receive queue?
     */
    if (!rv
	&& (! (queue_selectors & IPMI_SOL_MANAGEMENT_CONSOLE_RECEIVE_QUEUE)))
    {
	/* We don't HAVE a local RX queue... */
	/*VOID*/
    }

    ipmi_lock(conn->transmitter.oob_op_lock);
    /*
     * Do we flush the remote transmit queue?
     */
    if (!rv && (! (queue_selectors & IPMI_SOL_BMC_TRANSMIT_QUEUE))) {
	conn->transmitter.oob_transient_op
	    |= IPMI_SOL_OPERATION_FLUSH_BMC_TO_CONSOLE;
	need_callback = 1;
    }

    /*
     * Do we flush the remote receive queue?
     */
    if (!rv && (! (queue_selectors & IPMI_SOL_BMC_RECEIVE_QUEUE))) {
	conn->transmitter.oob_transient_op
	    |= IPMI_SOL_OPERATION_FLUSH_CONSOLE_TO_BMC;
	need_callback = 1;
    }

    if (need_callback) {
	ipmi_sol_flush_data_t *flush_data;

	flush_data = ipmi_mem_alloc(sizeof(*flush_data));

	flush_data->cb = cb;
	flush_data->cb_data = cb_data;

	/* FIXME - the below two had &&, not &.  I assumed that was wrong. */
	flush_data->selectors_flushed
	    = queue_selectors & IPMI_SOL_MANAGEMENT_CONSOLE_QUEUES;
	flush_data->selectors_pending = queue_selectors & IPMI_SOL_BMC_QUEUES;

	rv = add_op_control_callback(&conn->transmitter, flush_finalize,
				     flush_data);
	ipmi_unlock(conn->transmitter.oob_op_lock);

	transmitter_prod(&conn->transmitter);
    } else {
	ipmi_unlock(conn->transmitter.oob_op_lock);
    }

    ipmi_unlock(conn->transmitter.packet_lock);
    return rv;
}


/********************************************************
 ** IPMI SoL API
 *******************************************************/


/**
 * Constructs a handle for managing an SoL session.
 *
 * This function does NOT communicate with the BMC or activate the SoL payload.
 *
 * @param [in] ipmi	the existing IPMI over LAN session.
 * @param [out] sol_conn	the address into which to store the allocated
 *				IPMI SoL connection structure.
 * @return	zero on success, or ENOMEM if memory allocation fails.
 */
int
ipmi_sol_create(ipmi_con_t      *ipmi,
		ipmi_sol_conn_t **sol_conn)
{
    ipmi_sol_conn_t                *new_conn;
    os_handler_t                   *os_hnd = ipmi->os_hnd;
    ipmi_sol_transmitter_context_t *xmitter;
    int                            rv;

    new_conn = ipmi_mem_alloc(sizeof(*new_conn));
    if (!new_conn)
	return ENOMEM;

    memset(new_conn, 0, sizeof(*new_conn));

    new_conn->refcount = 1;

    xmitter = &new_conn->transmitter;

    /* Enable authentication and encryption by default. */
    new_conn->auxiliary_payload_data = (IPMI_SOL_AUX_USE_ENCRYPTION
					| IPMI_SOL_AUX_USE_AUTHENTICATION);

    rv = ipmi_create_lock_os_hnd(os_hnd, &xmitter->packet_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(os_hnd, &xmitter->queue_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(os_hnd, &xmitter->oob_op_lock);
    if (rv)
	goto out_err;

    new_conn->ipmi = ipmi;
    new_conn->data_received_callback_list = locked_list_alloc(os_hnd);
    if (! new_conn->data_received_callback_list) {
	rv = ENOMEM;
	goto out_err;
    }
    new_conn->break_detected_callback_list = locked_list_alloc(os_hnd);
    if (! new_conn->break_detected_callback_list) {
	rv = ENOMEM;
	goto out_err;
    }
    new_conn->bmc_transmit_overrun_callback_list = locked_list_alloc(os_hnd);
    if (! new_conn->bmc_transmit_overrun_callback_list) {
	rv = ENOMEM;
	goto out_err;
    }
    new_conn->connection_state_callback_list = locked_list_alloc(os_hnd);
    if (! new_conn->connection_state_callback_list) {
	rv = ENOMEM;
	goto out_err;
    }

    new_conn->prev_received_seqnr = 0;
    new_conn->prev_character_count = 0;

    new_conn->state = ipmi_sol_state_closed;
    new_conn->try_fast_connect = 1;

    xmitter->sol_conn = new_conn;
    xmitter->transmitted_packet = NULL;
    xmitter->latest_outgoing_seqnr = 1;

    new_conn->ACK_retries = 10;
    new_conn->ACK_timeout_usec = 1000000;

    rv = add_connection(new_conn);
    if (rv)
	goto out_err;

    *sol_conn = new_conn;

    return 0;

 out_err:
    if (xmitter->packet_lock)
	ipmi_destroy_lock(xmitter->packet_lock);
    if (xmitter->queue_lock)
	ipmi_destroy_lock(xmitter->queue_lock);
    if (xmitter->oob_op_lock)
	ipmi_destroy_lock(xmitter->oob_op_lock);
    if (new_conn->data_received_callback_list)
	locked_list_destroy(new_conn->data_received_callback_list);
    if (new_conn->break_detected_callback_list)
	locked_list_destroy(new_conn->break_detected_callback_list);
    if (new_conn->bmc_transmit_overrun_callback_list)
	locked_list_destroy(new_conn->bmc_transmit_overrun_callback_list);
    if (new_conn->connection_state_callback_list)
	locked_list_destroy(new_conn->connection_state_callback_list);
    ipmi_mem_free(new_conn);
    return rv;
}


/**
 * Figure out the "correct" maximum payload size.  This should *never*
 * be larger than 259 (0x0103) due to the constraint of the 8-bit
 * Accepted Character Count field plus the 4-byte payload header.
 * Some manufacturers (who shall remain nameless) have wrong-endianed
 * the maximum payload size fields, so we have to figure out which way
 * around they should be.  b1 and b2 are in the order they are in the
 * packet. They should be little-endian, so we try that first.
 */
static int
get_sane_payload_size(int b1, int b2)
{
    int result = (b2 << 8) + b1;
    if ((result > 0x0103) || (result < 5)) {
	result = (b1 << 8) + b2;
	if ((result > 0x0103) || (result < 5)) {
	    ipmi_log(IPMI_LOG_WARNING, "ipmi_sol.c(get_sane_payload_size): "
		     "BMC did not supply a sensible buffer size"
		     " (0x%02x, 0x%02x). Defaulting to 16.",
		     b1, b2);
	    result = 0x10; /* 16 bytes should be a safe buffer size. */
	} else
	    ipmi_log(IPMI_LOG_INFO, "ipmi_sol.c(get_sane_payload_size): "
		     "BMC sent a byte-swapped buffer size (%d bytes)."
		     " Using %d bytes.", (b2 << 8) + b1, result);
    }
    return result;
}

static void
finish_activate_payload(ipmi_sol_conn_t *conn)
{
    if (conn->max_outbound_payload_size > IPMI_SOL_MAX_DATA_SIZE)
	conn->transmitter.scratch_area_size = IPMI_SOL_MAX_DATA_SIZE;
    else
	conn->transmitter.scratch_area_size = conn->max_outbound_payload_size;

    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_active_payload_response): "
	     "Connected to BMC SoL through port %d.",
	     /*		conn->hostname,*/
	     conn->payload_port_number);

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_active_payload_response): "
	     "BMC requested transmit limit %d bytes, receive limit %d bytes.",
	     conn->max_outbound_payload_size,
	     conn->max_inbound_payload_size);

    if (conn->max_outbound_payload_size > conn->transmitter.scratch_area_size)
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Limiting transmit to %d bytes.",
		 conn->transmitter.scratch_area_size);
#endif

    /*
     * Set the hardware handshaking bits to match the "holdoff" option...
     */
    ipmi_lock(conn->transmitter.oob_op_lock);
    if (conn->auxiliary_payload_data & IPMI_SOL_AUX_DEASSERT_HANDSHAKE)
	conn->transmitter.oob_persistent_op
	    |= (IPMI_SOL_OPERATION_CTS_PAUSE
		| IPMI_SOL_OPERATION_DROP_DCD_DSR);
    else
	conn->transmitter.oob_persistent_op
	    &= ~(IPMI_SOL_OPERATION_CTS_PAUSE
		 | IPMI_SOL_OPERATION_DROP_DCD_DSR);
    ipmi_unlock(conn->transmitter.oob_op_lock);

    /*
     * And officially bring the connection "up"!
     */
    ipmi_sol_set_connection_state(conn, ipmi_sol_state_connected, 0);
}

static void ipmid_changed(ipmi_con_t   *ipmid, 
			  int          err,
			  unsigned int port_num,
			  int          any_port_up,
			  void         *cb_data)
{
    ipmi_sol_conn_t *conn = cb_data;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Error setting up new port: %d", err);
	goto out_err;
    }

    finish_activate_payload(conn);
    return;

 out_err:
    send_close(conn, NULL); 
    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed, err);
}

/*
 * Create a new IPMI connection to the BMC on the port specified in
 * the payload port number.
 */
static int
setup_new_ipmi(ipmi_sol_conn_t *conn)
{
    ipmi_args_t *args;
    int         rv;
    char        pname[20];

    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(setup_new_ipmi): "
	     "Setting up new IPMI connection to port %d.",
	     conn->payload_port_number);

    if (!conn->ipmi->get_startup_args) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Required a new port, but connection doesn't support "
		 "fetching arguments.");
	return ENOSYS;
    }

    args = conn->ipmi->get_startup_args(conn->ipmi);
    if (!args) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Unable to get arguments from the IPMI connection.");
	return ENOMEM;
    }

    snprintf(pname, sizeof(pname), "%d", conn->payload_port_number);
    rv = ipmi_args_set_val(args, -1, "Port", pname);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Error setting port argument: %d.", rv);
	return rv;
    }

    rv = ipmi_args_setup_con(args, conn->ipmi->os_hnd, NULL, &conn->ipmid);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Error setting up new connection: %d.", rv);
	return rv;
    }

    rv = conn->ipmid->add_con_change_handler(conn->ipmid, ipmid_changed, conn);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Error adding connection change handler: %d.", rv);
	return rv;
    }

    rv = conn->ipmid->start_con(conn->ipmid);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Error starting secondary connection: %d.", rv);
	return rv;
    }

    return 0;
}

static void
handle_activate_payload_response(ipmi_sol_conn_t *conn,
				 ipmi_msg_t      *msg_in)
{
    /*
     * Did it work?
     */
    if (msg_in->data_len != 13) {
	if (msg_in->data_len != 1) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "ipmi_sol.c(handle_active_payload_response): "
		     "Received %d bytes... was expecting 13 bytes.\n",
		     msg_in->data_len);
	    dump_hex(msg_in->data, msg_in->data_len);
	}

	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));
	return;
    }

    if (msg_in->data[0] != 0x00) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Activate payload failed.");
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				      IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	return;
    }

    /* Recover payload sizes that might be wrong-endianed... */

    /* outbound from here->BMC */
    conn->max_outbound_payload_size
	= get_sane_payload_size(msg_in->data[5], msg_in->data[6]);

    /* inbound from BMC->here */
    conn->max_inbound_payload_size
	= get_sane_payload_size(msg_in->data[7], msg_in->data[8]);

    conn->payload_port_number = (msg_in->data[10] << 8) + msg_in->data[9];
    if (conn->payload_port_number == 28418) {
	/* Bad byte-swapping */
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(handle_active_payload_response): "
		 "Got a badly byte-swapped UDP port, most likely.  Setting"
		 " it to the proper value.");
	conn->payload_port_number = IPMI_LAN_STD_PORT;
    }

    if (conn->payload_port_number != IPMI_LAN_STD_PORT) {
	int rv = setup_new_ipmi(conn);
	if (rv) {
	    send_close(conn, NULL); 
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed, rv);
	}
    } else {
	conn->ipmid = conn->ipmi;
	finish_activate_payload(conn);
    }
}

static int
send_activate_payload(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[6];
	
    /*
     * Send an Activate Payload command
     */
    msg_out.data_len = 6;
    msg_out.data = data;

    msg_out.data[0] = IPMI_RMCPP_PAYLOAD_TYPE_SOL & 0x3f; /* payload type */
    msg_out.data[1] = conn->payload_instance; /* payload instance number */
    /* NOTE: Can't connect to an Intel AXXIMMADV with the
       "Serial/Modem alerts fail" option, it seems. */

    /* enc, auth, Serial alerts behavior, deassert CTS and DCD/DSR */
    msg_out.data[2] = conn->auxiliary_payload_data;
    msg_out.data[3] = 0x00;
    msg_out.data[4] = 0x00;
    msg_out.data[5] = 0x00;

    msg_out.netfn = IPMI_APP_NETFN;
    msg_out.cmd = IPMI_ACTIVATE_PAYLOAD_CMD;
    return send_message(conn, &msg_out,
			handle_activate_payload_response);
}


static void
handle_set_volatile_bitrate_response(ipmi_sol_conn_t *conn,
				     ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 1) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(handle_set_volatile_bitrate_response): "
		 "Received %d bytes... was expecting 1 byte.\n",
		 msg_in->data_len);
	dump_hex(msg_in->data, msg_in->data_len);

	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));
	return;
    }

    if (msg_in->data[0] != 0x00) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_set_volatile_bitrate_response): "
		 "Set SoL configuration[Volatile bit rate] failed.");
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				      IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	return;
    }

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_set_volatile_bitrate_response): "
	     "Volatile bit rate set.");
#endif
    send_activate_payload(conn);
}

static int
send_set_volatile_bitrate(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[3];
    /*
     * Send a Set SoL Configuration command
     */
    msg_out.data_len = 3;
    msg_out.data = data;
    msg_out.data[0] = IPMI_SELF_CHANNEL; /* own channel, set param */
    msg_out.data[1] = 6; /* parameter selector = SOL volatile bit rate */
    msg_out.data[2] = conn->initial_bit_rate;
	
    msg_out.netfn = IPMI_TRANSPORT_NETFN;
    msg_out.cmd = IPMI_SET_SOL_CONFIGURATION_PARAMETERS;

    return send_message(conn, &msg_out,
			handle_set_volatile_bitrate_response);
}

static void
handle_get_payload_activation_status_response(ipmi_sol_conn_t *conn,
					      ipmi_msg_t      *msg_in)
{
    int count = 0, found, max, byte, index;

    if (msg_in->data_len != 4) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_get_payload_activation_status_response): "
		 "Get Payload Activation Status command failed.");
	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));
	return;
    }

    found = 0;
    for (byte = 0; byte <= 1; byte++) {
	for (index = 0; index < 7; index++) {
	    if (msg_in->data[2 + byte] & (1 << index)) {
		/* This payload instance slot is in use */
		count++;
	    } else if (!found) {
		found = 1;
		conn->payload_instance = 8 * byte + index + 1;
	    }
	}
    }

    max = msg_in->data[1] & 0x0f;

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_get_payload_activation_status_response): "
	     "BMC currently using %d SoL payload instances; limit is %d.",
	     count, max);
#endif

    if (!found || (count >= max)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_get_payload_activation_status_response): "
		 "BMC can't accept any more SoL sessions.");
	ipmi_sol_set_connection_state
	    (conn, ipmi_sol_state_closed,
	     IPMI_RMCPP_ERR_VAL(IPMI_RMCPP_INVALID_PAYLOAD_TYPE));
	return;
    }
#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_get_payload_activation_status_response): "
	     "SoL sessions are available; Using instance slot %d.",
	     conn->payload_instance);
#endif

    if (conn->initial_bit_rate)
	send_set_volatile_bitrate(conn);
    else
	send_activate_payload(conn);
}

static int
send_get_payload_activation_status_command(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[1];

    /*
     * Send a Get Payload Activation Status command
     */
    msg_out.data_len = 1;
    msg_out.data = data;

    msg_out.data[0] = IPMI_RMCPP_PAYLOAD_TYPE_SOL; /* Payload type */

    msg_out.netfn = IPMI_APP_NETFN;
    msg_out.cmd = IPMI_GET_PAYLOAD_ACTIVATION_STATUS_CMD;

    return send_message(conn, &msg_out,
			handle_get_payload_activation_status_response);
}


static void
handle_session_info_response(ipmi_sol_conn_t *conn,
			     ipmi_msg_t      *msg_in)
{
#ifdef IPMI_SOL_VERBOSE
    char *privilege_level[16] = {
	"Unknown", "Callback", "User", "Operator", "Administrator",
	"OEM Proprietary", "Unknown", "Unknown", "Unknown", "Unknown",
	"Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"};
#endif

    if (msg_in->data_len < 7) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_session_info_response): "
		 "Get Session Info command failed.");
	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));

	return;
    }

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_session_info_response): "
	     "This session handle: 0x%02x"
	     "  BMC currently using %d of %d sessions",
	     msg_in->data[1], msg_in->data[3], msg_in->data[2]);
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_session_info_response): "
	     "Current UserID: 0x%02x (%s)  Channel number: 0x%02x",
	     msg_in->data[4] & 0x3f, privilege_level[msg_in->data[5] & 0x0f],
	     msg_in->data[6] & 0x0f);
#endif
    send_get_payload_activation_status_command(conn);
}

static int
send_get_session_info(ipmi_sol_conn_t *conn)
{
    /*
     * Send a Get Session Info command (gives us our User ID, among
     * other things)
     */
    ipmi_msg_t    msg_out;
    unsigned char data[1];

    msg_out.data_len = 1;
    msg_out.data = data;

    msg_out.data[0] = 0x00; /* current session */

    msg_out.netfn = IPMI_APP_NETFN;
    msg_out.cmd = IPMI_GET_SESSION_INFO_CMD;

    return send_message(conn, &msg_out, handle_session_info_response);
}

static void
handle_commit_write_response(ipmi_sol_conn_t *conn,
			     ipmi_msg_t      *msg_in)
{
    send_get_session_info(conn);
}

static int
send_commit_write(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[3];

    msg_out.data_len = 3;
    msg_out.data = data;

    /* own channel, get param (not just version) */
    msg_out.data[0] = IPMI_SELF_CHANNEL;
    msg_out.data[1] = 0; /* parameter selector = Set In Progress */
    msg_out.data[2] = 0; /* Commit write */
	
    msg_out.netfn = IPMI_TRANSPORT_NETFN;
    msg_out.cmd = IPMI_SET_SOL_CONFIGURATION_PARAMETERS;

    return send_message(conn, &msg_out, handle_commit_write_response);
}

static void
handle_set_sol_enabled_response(ipmi_sol_conn_t *conn,
				ipmi_msg_t      *msg_in)
{
#if 0
    if ((msg_in->data_len != 1) || (msg_in->data[0])) {
	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));

	return 0;
    }
#endif

    send_commit_write(conn);
}

static int
send_enable_sol_command(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t msg_out;
    unsigned char data[3];

    /*
     * Send a Set SoL Configuration command
     */
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(send_enable_sol_command): "
	     "Attempting to enable SoL on BMC.");

    msg_out.data_len = 3;
    msg_out.data = data;

    /* own channel, get param (not just version) */
    msg_out.data[0] = IPMI_SELF_CHANNEL;
    msg_out.data[1] = 2; /* parameter selector = SOL Auth */
    msg_out.data[2] = 0x02; /* Enable SoL! */
	
    msg_out.netfn = IPMI_TRANSPORT_NETFN;
    msg_out.cmd = IPMI_SET_SOL_CONFIGURATION_PARAMETERS;

    return send_message(conn, &msg_out,
			handle_set_sol_enabled_response);
}

static void
handle_get_sol_enabled_response(ipmi_sol_conn_t *conn,
				ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 3) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_get_sol_enabled_response): "
		 "Get SoL Configuration[SoL Enabled] failed.");
	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));

	return;
    }

    if ((msg_in->data[2] && 1)) {
#ifdef IPMI_SOL_VERBOSE
	ipmi_log(IPMI_LOG_INFO,
		 "ipmi_sol.c(handle_get_sol_enabled_response): "
		 "BMC says SoL is enabled.");
#endif
	send_get_session_info(conn);
	return;
    }
    ipmi_log(IPMI_LOG_SEVERE,
	     "ipmi_sol.c(handle_get_sol_enabled_response): "
	     "BMC says SoL is disabled.");
	
    if (conn->force_connection_configure)
	send_enable_sol_command(conn);
    else
	ipmi_sol_set_connection_state
	    (conn, ipmi_sol_state_closed,
	     IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));
}

static void
send_get_sol_configuration_command(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[4];

    /*
     * Send a Get SoL Configuration command
     */
    msg_out.data_len = 4;
    msg_out.data = data;

    /* own channel, get param (not just version) */
    msg_out.data[0] = IPMI_SELF_CHANNEL;
    msg_out.data[1] = 1; /* parameter selector, 1 = SOL Enabled */
    msg_out.data[2] = 0; /* set selector */
    msg_out.data[3] = 0; /* block selector */

    msg_out.netfn = IPMI_TRANSPORT_NETFN;
    msg_out.cmd = IPMI_GET_SOL_CONFIGURATION_PARAMETERS;

    send_message(conn, &msg_out, handle_get_sol_enabled_response);
}


static void
handle_get_channel_payload_support_response(ipmi_sol_conn_t *conn,
					    ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 9) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "ipmi_sol.c(handle_get_channel_payload_support_response): "
		 "Get Channel Payload Support command failed.");
	if (msg_in->data_len > 0)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	    ipmi_sol_set_connection_state
		(conn, ipmi_sol_state_closed,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_NOT_AVAILABLE));

	return;
    }

    if (!(msg_in->data[1] && (1 << IPMI_RMCPP_PAYLOAD_TYPE_SOL))) {
	/* SoL is not supported! */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_sol.c(handle_get_channel_payload_support_response): "
		 "BMC says SoL is not supported.");
	ipmi_sol_set_connection_state
	    (conn, ipmi_sol_state_closed,
	     IPMI_RMCPP_ERR_VAL(IPMI_RMCPP_INVALID_PAYLOAD_TYPE));
	return;
    }
#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(handle_get_channel_payload_support_response): "
	     "BMC says SoL is supported.");
#endif
    send_get_sol_configuration_command(conn);
}

static int
send_get_channel_payload_support_command(ipmi_sol_conn_t *conn)
{
    ipmi_msg_t    msg_out;
    unsigned char data[1];

    /*
     * Send a Get Payload Support command
     */
    msg_out.data_len = 1;
    msg_out.data = data;

    msg_out.data[0] = IPMI_SELF_CHANNEL; /* current channel */

    msg_out.netfn = IPMI_APP_NETFN;
    msg_out.cmd = IPMI_GET_CHANNEL_PAYLOAD_SUPPORT_CMD;

    return send_message(conn, &msg_out,
			handle_get_channel_payload_support_response);
}


int
ipmi_sol_open(ipmi_sol_conn_t *conn)
{
    int rv;

    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state != ipmi_sol_state_closed) {
	/* It's an error to try to connect when not in closed state. */
	ipmi_unlock(conn->transmitter.packet_lock);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_sol.c(ipmi_sol_open): "
		 "An attempt was made to open an SoL connection"
		 " that's already open.");
	return EINVAL;
    }

    conn->addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    conn->addr.channel = IPMI_BMC_CHANNEL;
    conn->addr.lun = 0;
    
    /*
     * Note: For SoL over IPMI 1.5, the ipmi_lan code will translate this
     * RMCP+ address into the right packet format over RMCP (instead of
     * RMCP+).
     */
    conn->sol_payload_addr.addr_type = IPMI_RMCPP_ADDR_SOL;

    if (conn->try_fast_connect)
	rv = send_get_payload_activation_status_command(conn);
    else
	rv = send_get_channel_payload_support_command(conn);

    if (!rv)
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_connecting, 0);

    conn->transmitter.nack_count = 0;
    conn->transmitter.packet_to_acknowledge = 0;
    conn->transmitter.accepted_character_count = 0;
    conn->transmitter.bytes_acked_at_head = 0;

    ipmi_unlock(conn->transmitter.packet_lock);
    return rv;
}


static void
handle_deactivate_payload_response(ipmi_sol_conn_t *conn,
				   ipmi_msg_t      *msg_in)
{
    /*
     * We assume that conn hasn't gone away already, since we got the message
     * through the connection table.
     */
    if (conn->state == ipmi_sol_state_closed)
	return;

    /*
     * Did it work?  (Do we care?)
     */
    if (msg_in->data_len != 1)
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				      IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));
    else
	if (msg_in->data[0] != 0x00)
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
					  IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	else
	     /* Success! */
	    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed, 0);

    transmitter_shutdown(&conn->transmitter, 0);

    return;
}

int
ipmi_sol_close(ipmi_sol_conn_t *conn)
{
    ipmi_lock(conn->transmitter.packet_lock);
    if ((conn->state == ipmi_sol_state_closing)
	|| (conn->state == ipmi_sol_state_closed))
    {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }
	
    send_close(conn, handle_deactivate_payload_response);
    ipmi_unlock(conn->transmitter.packet_lock);
    return 0;
}


int
ipmi_sol_force_close(ipmi_sol_conn_t *conn)
{
    ipmi_lock(conn->transmitter.packet_lock);
    if (conn->state == ipmi_sol_state_closed) {
	ipmi_unlock(conn->transmitter.packet_lock);
	return EINVAL;
    }

    if (conn->state != ipmi_sol_state_closing)
	/*
	 * Try to be polite to the BMC. Don't ask for a callback,
	 * cos we'll be gone!
	 */
	send_close(conn, NULL); 

    transmitter_shutdown(&conn->transmitter,
			 IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));

    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				  IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));
    ipmi_unlock(conn->transmitter.packet_lock);

    return 0;
}


int
ipmi_sol_free(ipmi_sol_conn_t *conn)
{
    sol_put_connection(conn);
    return 0;
}


/********************************************************************
 ** IPMI SoL Payload handling           *****************************
 ********************************************************************/

/* Format a message for transmit on this payload.  The address and
   message is the one specified by the user.  The out_data is a
   pointer to where to store the output, out_data_len will point
   to the length of the buffer to store the output and should be
   updatated to be the actual length.  The seq is a 6-bit value
   that should be store somewhere so the that response to this
   message can be identified.  If the netfn is odd, the sequence
   number is not used.  The out_of_session variable is set to zero
   by default; if the message is meant to be sent out of session,
   then the formatter should set this value to 1. */

static int
sol_format_msg(ipmi_con_t        *conn,
	       const ipmi_addr_t *addr,
	       unsigned int      addr_len,
	       const ipmi_msg_t  *msg,
	       unsigned char     *out_data,
	       unsigned int      *out_data_len,
	       int               *out_of_session,
	       unsigned char     seq)
{
    if (*out_data_len < msg->data_len)
	return E2BIG;

    memcpy(out_data, msg->data, msg->data_len);

    *out_data_len = msg->data_len;

    out_of_session = 0;
    return 0;
}


/* Get the recv sequence number from the message.  Return ENOSYS
   if the sequence number is not valid for the message (it is
   asynchronous), zero otherwise */
static int sol_get_recv_seq(ipmi_con_t    *conn,
			unsigned char *data,
			unsigned int  data_len,
			unsigned char *seq)
{
    /*
     * We force the packets to go through to sol_handle_recv_async for
     * our processing.  This is because we can't use the OpenIPMI payload
     * sequence number interface.
     */
    return ENOSYS;
}


/* Fill in the rspi data structure from the given data, responses
   only.  This does *not* deliver the message, that is done by the
   LAN code. */
static int
sol_handle_recv(ipmi_con_t    *conn,
		ipmi_msgi_t   *rspi,
		ipmi_addr_t   *orig_addr,
		unsigned int  orig_addr_len,
		ipmi_msg_t    *orig_msg,
		unsigned char *data,
		unsigned int  data_len)
{
    /*
     * This should NEVER be called.
     */
    return ENOSYS;
}

static void
process_packet(ipmi_sol_conn_t *conn,
	       unsigned char   *packet,
	       unsigned int    data_len)
{
    ipmi_sol_transmitter_context_t *xmitter;
    int                            nack = 0;

    xmitter = &conn->transmitter;

    nack = (packet[PACKET_STATUS] & IPMI_SOL_STATUS_NACK_PACKET) != 0;

    /* If NACK && CTU != prev CTU, do a conn state change */

    if (nack) {
	/* Check CTU */
	int new_state;

	if (packet[PACKET_STATUS]
	    & IPMI_SOL_STATUS_CHARACTER_TRANSFER_UNAVAIL)
	    new_state = ipmi_sol_state_connected_ctu;
	else
	    new_state = ipmi_sol_state_connected;

	ipmi_sol_set_connection_state(conn, new_state, 0);
    }

    if (data_len > 4) {
	data_len -= 4; /* Skip over header */

	if (0 == packet[PACKET_SEQNR]) {
	    /* Can't have data in a packet with zero seqnr: error */
	    ipmi_log(IPMI_LOG_WARNING,
		     "ipmi_sol.c(sol_handle_recv_async): "
		     "Broken BMC: Received a packet with non-empty data"
		     " and a sequence number of zero.");
	} else {
	    int character_count;
	    int do_nack;

	    /* FIXME - validate that the sequence numbers are
	       sequentially increasing. */
	    if (conn->prev_received_seqnr == packet[PACKET_SEQNR]) {
		/* overlapping packets... yummy */
		character_count = data_len - conn->prev_character_count;
	    } else {
		/* This whole packet goes to the client(s) */
		character_count = data_len;
		conn->prev_received_seqnr = packet[PACKET_SEQNR];
	    }
	    if (xmitter->nack_count) {
		/* The user already sent a NACK, no reason to send any
		   more til they release it. */
	    } else {
		xmitter->in_recv_cb = 1;
		ipmi_unlock(xmitter->packet_lock);
		do_nack = do_data_received_callbacks
		    (conn, &packet[PACKET_DATA + data_len - character_count],
		     character_count);
		ipmi_lock(xmitter->packet_lock);
		xmitter->in_recv_cb = 0;

		xmitter->nack_count += do_nack;
		if (xmitter->nack_count < 0) {
		    ipmi_log(IPMI_LOG_WARNING,
			     "ipmi_sol.c(process_packet): "
			     "Too many NACK releases.");
		    xmitter->nack_count = 0;
		}

		if (conn->state == ipmi_sol_state_closed)
		    return;
	    }

	    conn->prev_received_seqnr = packet[PACKET_SEQNR];
	    xmitter->packet_to_acknowledge = packet[PACKET_SEQNR];

	    if (xmitter->nack_count) {
		conn->prev_character_count = 0;
		/* FIXME: It is unclear from the spec whether the
		   accepted character count on a NACK should be 0 or
		   the number of bytes not accepted.  Zero seems more
		   reasonable, but neither works with my machine, it
		   just keeps retransmitting then gives up when it
		   gets a NACK. - Corey */
		xmitter->accepted_character_count = 0;
		ipmi_lock(xmitter->oob_op_lock);
		xmitter->oob_transient_op |= IPMI_SOL_OPERATION_NACK_PACKET;
		ipmi_unlock(xmitter->oob_op_lock);
	    } else {
		conn->prev_character_count = data_len;
		xmitter->accepted_character_count = data_len;
	    }
	}
    }


    if (packet[PACKET_ACK_NACK_SEQNR] &&
	xmitter->transmitted_packet &&
	(packet[PACKET_ACK_NACK_SEQNR]
	 == xmitter->transmitted_packet->packet[PACKET_SEQNR]))
    {
	/*
	 * The op callbacks are always successful if we got an ACK.
	 */
	do_outstanding_op_callbacks(xmitter, 0);

	/* NACK and Char Trans Unavail? */
	if ((packet[PACKET_STATUS] & IPMI_SOL_STATUS_NACK_PACKET)
	    && (packet[PACKET_STATUS] & IPMI_SOL_STATUS_CHARACTER_TRANSFER_UNAVAIL))
	{
	    /*
	     * This will never send CTU error code to a control
	     * callback, cos they have been done-and-destroyed just
	     * above!
	     */
	    transmitter_flush_outbound
		(xmitter,
		 IPMI_SOL_ERR_VAL(IPMI_SOL_CHARACTER_TRANSFER_UNAVAILABLE));
	} else if (packet[PACKET_ACCEPTED_CHARACTER_COUNT] > 0) {
	    /* Accepted chars? */
	    transmitter_handle_acknowledge
		(conn, 0, packet[PACKET_ACCEPTED_CHARACTER_COUNT]);
	} else if (!(packet[PACKET_STATUS] & IPMI_SOL_STATUS_NACK_PACKET)) {
	    /* FIXME: Intel hack */
	    /*
	     * If the packet wasn't NACKed, and the accepted char
	     * count was zero, assume they meant to ACK the whole
	     * packet.
	     */
	    transmitter_handle_acknowledge
		(conn, 0, xmitter->transmitted_packet->packet_size - 4);
	}

	/*
	 * Destroy the packet, reporting success on anything else we've missed.
	 */
	dispose_of_outstanding_packet(xmitter, 0);
    }

    if (packet[PACKET_STATUS] & IPMI_SOL_STATUS_BREAK_DETECTED) {
	ipmi_unlock(xmitter->packet_lock);
	do_break_detected_callbacks(conn);
	ipmi_lock(xmitter->packet_lock);
	if (conn->state == ipmi_sol_state_closed)
	    return;
    }

    if (packet[PACKET_STATUS] & IPMI_SOL_STATUS_BMC_TX_OVERRUN) {
	ipmi_unlock(xmitter->packet_lock);
	do_transmit_overrun_callbacks(conn);
	ipmi_lock(xmitter->packet_lock);
	if (conn->state == ipmi_sol_state_closed)
	    return;
    }

    if (nack && (packet[PACKET_STATUS] & IPMI_SOL_STATUS_DEACTIVATED)) {
	transmitter_shutdown(xmitter, IPMI_SOL_ERR_VAL(IPMI_SOL_DEACTIVATED));
	 /* Success! */
	ipmi_sol_set_connection_state(conn,
				      ipmi_sol_state_closed,
				      IPMI_SOL_ERR_VAL(IPMI_SOL_DEACTIVATED));
    } else {
	transmitter_prod_nolock(xmitter);
    }
}


/* Handle an asynchronous message.  This *should* deliver the
   message, if possible. */
static void
sol_handle_recv_async(ipmi_con_t    *ipmi_conn,
		      unsigned char *packet,
		      unsigned int  data_len)
{
    ipmi_sol_transmitter_context_t *xmitter;
    ipmi_sol_conn_t                *conn;

    conn = find_sol_connection_for_ipmi(ipmi_conn);
    if (!conn) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(sol_handle_recv_async): "
		 "Dropped incoming SoL packet: Unrecognized connection.");
	return;
    }

    xmitter = &conn->transmitter;

    ipmi_lock(xmitter->packet_lock);

    if (data_len < 4) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(sol_handle_recv_async): "
		 "Dropped incoming SoL packet: Too short, at %d bytes.",
		 data_len);
	goto out_unlock;
    }

#ifdef IPMI_SOL_DEBUG_RECEIVE
    ipmi_log(IPMI_LOG_INFO,
	     "ipmi_sol.c(sol_handle_recv_async): "
	     "Received SoL packet, %d bytes", data_len);
    dump_hex(packet, data_len);
#endif

    if ((conn->state != ipmi_sol_state_connected)
	&& (conn->state != ipmi_sol_state_connected_ctu)) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_sol.c(sol_handle_recv_async): "
		 "Dropped incoming SoL packet: connection closed.");
	goto out_unlock;
    }

    if (conn->processing_packet) {
	/* Some other thread is already processing packets.  Tack this
	   packet onto the end of waiting packets for the other thread
	   to handle. */
	sol_in_packet_info_t *packet, *epacket;
	unsigned char        *pdata;

	packet = ipmi_mem_alloc(sizeof(*packet) + data_len);
	if (!packet)
	    goto out_unlock;
	packet->data_len = data_len;
	packet->next = NULL;
	pdata = ((unsigned char *) packet) + sizeof(*packet);
	memcpy(pdata, packet, data_len);

	if (conn->waiting_packets) {
	    conn->waiting_packets = packet;
	} else {
	    epacket = conn->waiting_packets;
	    while (epacket->next)
		epacket = epacket->next;
	    epacket->next = packet;
	}
	goto out_unlock;
    }

    conn->processing_packet = 1;

    /* At this point we are single-threaded.  No other process can be
       running this code but me, even if I release the packet_lock. */

    process_packet(conn, packet, data_len);

    /* See if some other thread stuck some packets in for me to
       process.  Do that now. */
    process_waiting_packets(conn);

    conn->processing_packet = 0;

 out_unlock:
    ipmi_unlock(xmitter->packet_lock);
    sol_put_connection(conn);
}

static ipmi_payload_t ipmi_sol_payload =
{ sol_format_msg, sol_get_recv_seq, sol_handle_recv,
  sol_handle_recv_async, NULL /*sol_get_msg_tag*/ };

int
_ipmi_sol_init()
{
    int rv;

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL,
				     &ipmi_sol_payload);
    if (rv)
	goto out;

    rv = ipmi_create_global_lock(&conn_lock);
    if (rv) {
	ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL, NULL);
	goto out;
    }

 out:
    return rv;
}

void
_ipmi_sol_shutdown(void)
{
    if (conn_lock) {
	ipmi_destroy_lock(conn_lock);
	conn_lock = NULL;
    }
    ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL, NULL);
}
