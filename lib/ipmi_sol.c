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
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/ipmi_sol.h>

/* FIXME - replace callback lists with standard locked lists to avoid
   race conditions and memory leaks. */


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


/**
 * Stores a list of generic callback functions.  Values are to be typecast as
 * they are extracted.
 */
typedef struct callback_list_s callback_list_t;
struct callback_list_s {
    void *cb;
    void *cb_data;
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
    /* The outgoing SoL payload data.  Min 4 bytes long. */
    unsigned char *packet;

    /* The length of the outgoing SoL payload data. */
    int packet_size;

    /* The timer to manage retransmits. */
    os_hnd_timer_id_t *ack_timer;

    /* Nonzero iff we're expecting an ACK for this packet. */
    int expecting_ACK;

    /* Countdown of number of transmission attempts left before we
       declare the packet "lost". */
    int transmit_attempts_remaining;

    /* callbacks for operations in this packet. */
    callback_list_t *op_callback_list;
} ipmi_sol_outgoing_packet_record_t;


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

    /* We have already acked this many chars from the request at the
       head of the tx queue. */
    int bytes_acked_at_head;

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

typedef struct ipmi_sol_transmitter_context_s ipmi_sol_transmitter_context_t;

struct ipmi_sol_conn_s {
    /* The IPMI connection over which this SoL connection operates. */
    ipmi_con_t *ipmi;

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

    /* The current state of the SoL connection. */
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
    callback_list_t *data_received_callback_list;

    /* A list of callbacks that are called when a break is reported by
       the BMC. */
    callback_list_t *break_detected_callback_list;

    /* A list of callbacks that are called when a transmit overrun is
       reported by the BMC. */
    callback_list_t *bmc_transmit_overrun_callback_list;

    /* A list of callbacks that are called when the SoL connection
       changes state. */
    callback_list_t *connection_state_callback_list;
};


static ipmi_payload_t ipmi_sol_payload;


static int transmitter_startup(ipmi_sol_transmitter_context_t *transmitter);
static void transmitter_shutdown(ipmi_sol_transmitter_context_t *transmitter,
				 int error);


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

typedef struct ipmi_sol_conn_list_s ipmi_sol_conn_list_t;

struct ipmi_sol_conn_list_s {
    ipmi_con_t *ipmi;
    ipmi_sol_conn_t *sol;
    ipmi_sol_conn_list_t *next;
};

static ipmi_sol_conn_list_t *conn_list = NULL;


/**
 * Adds the given (ipmi, sol) pairing to the list of connections we're
 * managing.
 */
static void
add_connection(ipmi_con_t *ipmi, ipmi_sol_conn_t *sol)
{
    ipmi_sol_conn_list_t *le = ipmi_mem_alloc(sizeof(ipmi_sol_conn_list_t));

    le->ipmi = ipmi;
    le->sol = sol;

    le->next = conn_list;
    conn_list = le;

    return;
}


/**
 * Removes the given connection from the list of connections we're managing.
 */
static void delete_connection(ipmi_con_t *ipmi, ipmi_sol_conn_t *sol)
{
    ipmi_sol_conn_list_t *le = conn_list;
    ipmi_sol_conn_list_t *prev = NULL;

    while (le) {
	if (le->ipmi == ipmi && le->sol == sol) {
	    /*
	     * Delete me!
	     */
	    if (!prev)
		/* Deleting from head of list... */
		conn_list = conn_list->next;
	    else
		/* Deleting from within list */
		prev->next = le->next;

	    ipmi_mem_free(le);
	    if (!prev)
		le = conn_list;
	    else
		le = prev;
	} else
	    prev = le;

	if (!le)
	    break;

	le = le->next;
    }
}


/**
 * Finds the sol connection for a given ipmi connection.
 */
static ipmi_sol_conn_t *
find_sol_connection_for_ipmi(ipmi_con_t *ipmi)
{
    ipmi_sol_conn_list_t *le = conn_list;
    while (le) {
	if (le->ipmi == ipmi)
	    return le->sol;
	le = le->next;
    }

    return NULL;
}


/***************************************************************************
 ** Shorthand IPMI messaging; used to set up or close an ipmi_sol_conn_t.
 ** This is NOT used for handling the SoL data... for that, see the payload
 ** functions towards the end of this file.
 **/

typedef void (*sol_command_callback)(ipmi_sol_conn_t *conn, ipmi_msg_t *msg);

static int handle_response(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    if (rspi->data2)
	((sol_command_callback)(rspi->data2))
	    ((ipmi_sol_conn_t *)rspi->data1, &rspi->msg);
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
ipmi_sol_send_close(ipmi_sol_conn_t *conn, sol_command_callback cb)
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

static int
add_callback_to_list(callback_list_t **cb_list, void *cb, void *cb_data)
{
    callback_list_t *new_entry = ipmi_mem_alloc(sizeof(*new_entry));
    callback_list_t *iter = *cb_list;

    if (!new_entry)
	return ENOMEM;

    new_entry->cb = cb;
    new_entry->cb_data = cb_data;
    new_entry->next = NULL;

    if (NULL == *cb_list) {
	*cb_list = new_entry;
    } else {
	while (NULL != iter->next)
	    iter = iter->next;

	/*
	 * iter points to the end of the list.
	 */
	iter->next = new_entry;
    }

    *cb_list = new_entry;
    return 0;
}

static int
remove_callback_from_list(callback_list_t **cb_list, void *cb, void *cb_data)
{
    callback_list_t *iter = *cb_list;
    callback_list_t *last = NULL;
    while (NULL != iter) {
	if (iter->cb == cb && iter->cb_data == cb_data) {
	    // remove this node.
	    if (NULL == last)
		*cb_list = iter->next;
	    else
		last->next = iter->next;
	    ipmi_mem_free(iter);
	    return 0;
	}
	last = iter;
	iter = iter->next;
    }
    return ENOENT;
}

static int
do_data_received_callbacks(ipmi_sol_conn_t *conn,
			   const void      *buf,
			   size_t          count)
{
    int nack = 0;
    callback_list_t *iter = conn->data_received_callback_list;

    while (NULL != iter) {
	nack = ((ipmi_sol_data_received_cb)iter->cb)(conn, buf, count,
						     iter->cb_data);
	if (nack)
	    break;
	iter = iter->next;
    }

    return nack;
}

static void
do_break_detected_callbacks(ipmi_sol_conn_t *conn)
{
    callback_list_t *iter = conn->break_detected_callback_list;
    while (NULL != iter) {
	((ipmi_sol_break_detected_cb)iter->cb)(conn, iter->cb_data);
	iter = iter->next;
    }
}

static void
do_transmit_overrun_callbacks(ipmi_sol_conn_t *conn)
{
    callback_list_t *iter = conn->bmc_transmit_overrun_callback_list;
    while (NULL != iter) {
	((ipmi_sol_bmc_transmit_overrun_cb)iter->cb)(conn, iter->cb_data);
	iter = iter->next;
    }
}

static void
do_connection_state_callbacks(ipmi_sol_conn_t *conn, int state, int error)
{
    callback_list_t *iter = conn->connection_state_callback_list;
    while (NULL != iter) {
	((ipmi_sol_connection_state_cb)iter->cb)(conn, state, error,
						 iter->cb_data);
	iter = iter->next;
    }
}


int
ipmi_sol_register_data_received_callback(ipmi_sol_conn_t           *conn,
					 ipmi_sol_data_received_cb cb,
					 void                      *cb_data)
{
    return add_callback_to_list(&conn->data_received_callback_list,
				cb, cb_data);
}

int
ipmi_sol_deregister_data_received_callback(ipmi_sol_conn_t           *conn,
					   ipmi_sol_data_received_cb cb,
					   void                      *cb_data)
{
    return remove_callback_from_list(&conn->data_received_callback_list,
				     cb, cb_data);
}


int
ipmi_sol_register_break_detected_callback(ipmi_sol_conn_t            *conn,
					  ipmi_sol_break_detected_cb cb,
					  void                       *cb_data)
{
    return add_callback_to_list(&conn->break_detected_callback_list,
				cb, cb_data);
}

int
ipmi_sol_deregister_break_detected_callback(ipmi_sol_conn_t            *conn,
					    ipmi_sol_break_detected_cb cb,
					    void                      *cb_data)
{
    return remove_callback_from_list(&conn->break_detected_callback_list,
				     cb, cb_data);
}


int
ipmi_sol_register_bmc_transmit_overrun_callback(ipmi_sol_conn_t *conn,
						ipmi_sol_bmc_transmit_overrun_cb cb,
						void *cb_data)
{
    return add_callback_to_list(&conn->bmc_transmit_overrun_callback_list,
				cb, cb_data);
}

int
ipmi_sol_deregister_bmc_transmit_overrun_callback(ipmi_sol_conn_t *conn,
						  ipmi_sol_bmc_transmit_overrun_cb cb,
						  void *cb_data)
{
    return remove_callback_from_list(&conn->bmc_transmit_overrun_callback_list,
				     cb, cb_data);
}


int
ipmi_sol_register_connection_state_callback(ipmi_sol_conn_t              *conn,
					    ipmi_sol_connection_state_cb cb,
					    void                       *cb_data)
{
    return add_callback_to_list(&conn->connection_state_callback_list,
				cb, cb_data);
}

int
ipmi_sol_deregister_connection_state_callback(ipmi_sol_conn_t         *conn,
					      ipmi_sol_connection_state_cb cb,
					      void                    *cb_data)
{
    return remove_callback_from_list(&conn->connection_state_callback_list,
				     cb, cb_data);
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

    if (conn->state != ipmi_sol_state_closed)
	return EINVAL;

    if (use_authentication)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_USE_AUTHENTICATION;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_USE_AUTHENTICATION;
    
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

    if (conn->state != ipmi_sol_state_closed)
	return EINVAL;

    if (use_encryption)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_USE_ENCRYPTION;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_USE_ENCRYPTION;

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

    if (conn->state != ipmi_sol_state_closed)
	return EINVAL;

    conn->auxiliary_payload_data &= ~(IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_MASK << IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT);
    conn->auxiliary_payload_data |= behavior << IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT;

    return 0;
}


ipmi_sol_serial_alert_behavior
ipmi_sol_get_shared_serial_alert_behavior(ipmi_sol_conn_t *conn)
{
    return (ipmi_sol_serial_alert_behavior)
	((conn->auxiliary_payload_data >> IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_SHIFT) &
	 IPMI_SOL_AUX_SHARED_SERIAL_BEHAVIOR_MASK);
}

int
ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(ipmi_sol_conn_t *conn,
					     int             deassert)
{
    if (!conn)
	return EINVAL;

    if (conn->state != ipmi_sol_state_closed)
	return EINVAL;

    if (deassert)
	conn->auxiliary_payload_data |= IPMI_SOL_AUX_DEASSERT_HANDSHAKE;
    else
	conn->auxiliary_payload_data &= ~IPMI_SOL_AUX_DEASSERT_HANDSHAKE;

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

    if (conn->state != ipmi_sol_state_closed)
	return EINVAL;

    conn->initial_bit_rate = rate;

    return 0;
}

unsigned char
ipmi_sol_get_bit_rate(ipmi_sol_conn_t *conn)
{
    return conn->initial_bit_rate;
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
			      ipmi_sol_state new_state,
			      int error)
{
    if (conn->state == new_state)
	return;

    if ((conn->state == ipmi_sol_state_closed)
	&& (new_state == ipmi_sol_state_connecting))
    {
	/*
	 * Record this connection so we can match up incoming SoL
	 * packets with their SoL connections.
	 */
	add_connection(conn->ipmi, conn);
    } else if (new_state == ipmi_sol_state_closed) {
	transmitter_shutdown(&conn->transmitter, error);
	delete_connection(conn->ipmi, conn);
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

    do_connection_state_callbacks(conn, new_state, error);
}


/*****************************************************************************
 ** IPMI SoL write operations
 **/
 
static void
do_and_destroy_transmit_complete_callbacks(callback_list_t **list,
					   ipmi_sol_conn_t *conn,
					   int             error)
{
    callback_list_t *iter = *list;
    callback_list_t *temp;

    while (NULL != iter) {
	((ipmi_sol_transmit_complete_cb)iter->cb)(conn, error, iter->cb_data);
	temp = iter;
	iter = iter->next;
	ipmi_mem_free(temp);
    }
    *list = NULL;
}


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
	    printf("%p -> %d chars at %p -> [", i, i->data_len, i->data); fflush(stdout);
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
    transmitter->packet_to_acknowledge = 0;

    new_packet_record->packet[PACKET_ACCEPTED_CHARACTER_COUNT]
	= transmitter->accepted_character_count;
    transmitter->accepted_character_count = 0;

    new_packet_record->packet[PACKET_OP]
	= (transmitter->oob_transient_op | transmitter->oob_persistent_op
	   | ib_op);
    transmitter->oob_transient_op = 0;

    new_packet_record->op_callback_list = transmitter->op_callback_list;
    transmitter->op_callback_list = NULL;

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
    new_packet_record->ack_timer = NULL;

    return new_packet_record;
}


static void
do_outstanding_op_callbacks(ipmi_sol_transmitter_context_t *transmitter,
			    int                            error)
{
    do_and_destroy_transmit_complete_callbacks
	(&(transmitter->transmitted_packet->op_callback_list),
	 transmitter->sol_conn, error);
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

    if (!transmitter->transmitted_packet)
	return;
    
    if (transmitter->transmitted_packet->ack_timer) {
	os_hnd = transmitter->sol_conn->ipmi->os_hnd;

	os_hnd->free_timer(os_hnd,
			   transmitter->transmitted_packet->ack_timer);
    }

    do_outstanding_op_callbacks(transmitter, error);

    if (transmitter->transmitted_packet->packet)
	ipmi_mem_free(transmitter->transmitted_packet->packet);

    ipmi_mem_free(transmitter->transmitted_packet);
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
    rv = conn->ipmi->send_command_option
	(conn->ipmi,
	 (ipmi_addr_t *)&transmitter->sol_conn->sol_payload_addr,
	 sizeof(transmitter->sol_conn->sol_payload_addr),
	 &msg,
	 options,
	 NULL, NULL);

    if (rv) {
	char buf[50];
	ipmi_log(IPMI_LOG_WARNING, "ipmi_send_command_addr: [%s]",
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
    timeout.tv_sec = transmitter->sol_conn->ACK_timeout_usec / 1000000;
    timeout.tv_usec = transmitter->sol_conn->ACK_timeout_usec % 1000000;

    return transmitter->sol_conn->ipmi->os_hnd->start_timer
	(transmitter->sol_conn->ipmi->os_hnd,
	 transmitter->transmitted_packet->ack_timer,
	 &timeout,
	 sol_ACK_timer_expired,
	 (void *)transmitter);
}

static void
sol_ACK_timer_expired(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_sol_transmitter_context_t *transmitter = cb_data;

#ifdef SOL_DEBUG_TRANSMIT
    printf("sol_ACK_timer_expired!\n");
#endif

    ipmi_lock(transmitter->packet_lock);

    if (!transmitter->transmitted_packet) {
	/* OK, the packet was ACKed, it seems... */
	ipmi_unlock(transmitter->packet_lock);
	return;
    }

    if (!(--transmitter->transmitted_packet->transmit_attempts_remaining))
	/*
	 * Didn't get a response even after retries... connection is lost.
	 */
	ipmi_sol_set_connection_state(transmitter->sol_conn,
				      ipmi_sol_state_closed,
				      IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));
    else {
	int rv;

	transmit_outstanding_packet(transmitter);
	rv = setup_ACK_timer(transmitter);
	if (rv) {
	    char buf[50];
	    ipmi_log(IPMI_LOG_WARNING, "Unable to setup_ACK_timer: %s", ipmi_get_error_string(rv, buf, 50));
	    dispose_of_outstanding_packet(transmitter, rv);
	    /* FIXME: What is the right error value? */
	}
    }
    ipmi_unlock(transmitter->packet_lock);
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
 */
static void
transmitter_prod(ipmi_sol_transmitter_context_t *transmitter)
{
    ipmi_lock(transmitter->packet_lock);

    /*
     * TODO: If we are awaiting an ACK and we get a data packet from
     * the remote system that doesn't ACK our outstanding packet,
     * perhaps we should be able to send back an ACK (and control)
     * packet immediately???  If so, we should keep going here, and
     * later call transmitter_gather(transmitter, 1) to collect a
     * strictly control-only packet (no BREAKs, either!).
     */
    if (transmitter->transmitted_packet) {
	ipmi_unlock(transmitter->packet_lock);
#ifdef IPMI_SOL_DEBUG_TRANSMIT
	ipmi_log(IPMI_LOG_INFO,
		 "transmitter_prod exiting early:"
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

    if (!transmitter->transmitted_packet)
	transmitter->transmitted_packet = transmitter_gather(transmitter, 0);

    if (transmitter->transmitted_packet) {
	int rv = 0;

	if (transmitter->transmitted_packet->expecting_ACK) {
	    rv = transmitter->sol_conn->ipmi->os_hnd->alloc_timer
		(transmitter->sol_conn->ipmi->os_hnd,
		 &transmitter->transmitted_packet->ack_timer);
	}

	if (!rv)
	    rv = transmit_outstanding_packet(transmitter);

	if (rv) {
	    dispose_of_outstanding_packet(transmitter, rv);
	    ipmi_unlock(transmitter->packet_lock);
	    return;
	}

	if (transmitter->transmitted_packet->expecting_ACK) {
	    rv = setup_ACK_timer(transmitter);
	    if (rv) {
		char buf[50];
		ipmi_log(IPMI_LOG_WARNING,
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
	    transmitter_handle_acknowledge
		(transmitter->sol_conn, errval, 0);
		 
	    dispose_of_outstanding_packet(transmitter, errval);
	}
    }
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

    ipmi_lock(transmitter->queue_lock);

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

    ipmi_unlock(transmitter->queue_lock);
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
    ipmi_lock(transmitter->packet_lock);
    ipmi_lock(transmitter->queue_lock);

    dispose_of_outstanding_packet(transmitter, error);

    while (transmitter->outgoing_queue.head)
	dequeue_head(transmitter, error);

    ipmi_unlock(transmitter->queue_lock);
    ipmi_unlock(transmitter->packet_lock);
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
	    dequeue_head(&conn->transmitter, error);
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

    transmitter_prod(tx);

    return 0;
}

static int
add_op_control_callback(ipmi_sol_transmitter_context_t *tx, 
			ipmi_sol_transmit_complete_cb  cb,
			void                           *cb_data)
{
    return add_callback_to_list(&tx->op_callback_list, cb, cb_data);
}

static int
transmitter_startup(ipmi_sol_transmitter_context_t *transmitter)
{
    transmitter->scratch_area = ipmi_mem_alloc(transmitter->scratch_area_size);
    if (!transmitter->scratch_area) {
	/* Alloc failed! */
	ipmi_log(IPMI_LOG_FATAL,
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
    if (count <= 0)
	return EINVAL;

    return add_to_transmit_queue(&conn->transmitter, buf, count, 0,
				 cb, cb_data);
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
    return add_to_transmit_queue(&conn->transmitter, NULL, 0,
				 IPMI_SOL_OPERATION_GENERATE_BREAK,
				 cb, cb_data);
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

    if (assertable)
	conn->transmitter.oob_persistent_op &= ~IPMI_SOL_OPERATION_CTS_PAUSE;
    else
	conn->transmitter.oob_persistent_op |= IPMI_SOL_OPERATION_CTS_PAUSE;

    rv = add_op_control_callback(&conn->transmitter, cb, cb_data);

    transmitter_prod(&conn->transmitter);

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

    if (asserted)
	conn->transmitter.oob_persistent_op &= ~IPMI_SOL_OPERATION_DROP_DCD_DSR;
    else
	conn->transmitter.oob_persistent_op |= IPMI_SOL_OPERATION_DROP_DCD_DSR;

    rv = add_op_control_callback(&conn->transmitter, cb, cb_data);

    transmitter_prod(&conn->transmitter);

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

    if (asserted)
	conn->transmitter.oob_persistent_op |= IPMI_SOL_OPERATION_RING_REQUEST;
    else
	conn->transmitter.oob_persistent_op &= ~IPMI_SOL_OPERATION_RING_REQUEST;

    rv = add_op_control_callback(&conn->transmitter, cb, cb_data);

    transmitter_prod(&conn->transmitter);

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

	transmitter_prod(&conn->transmitter);
    }
    return rv;
}



static int
register_ipmi_payload(void)
{
    int rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL,
					 &ipmi_sol_payload);
    if (rv == EINVAL) {
	/*
	 * The payload is already registered... try to unregister the
	 * old payload handler.
	 */
	rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL, NULL);

	if (rv == EAGAIN) {
	    /*
	     * Unable to unregister it!
	     */
	    ipmi_log(IPMI_LOG_FATAL,
		     "Unable to unregister existing SoL payload.");
	    /* FIXME - NO EXITs! */
	    exit(1);
	} else if (rv != EINVAL) {
	    /*
	     * Unregistered, now do our registration again.
	     */
	    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL,
					     &ipmi_sol_payload);
	}
    }

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
    ipmi_sol_conn_t *new_conn;
    int rv = register_ipmi_payload();
    if (rv)
	return rv;

    new_conn = ipmi_mem_alloc(sizeof(*new_conn));
    if (!new_conn)
	return ENOMEM;

    memset(new_conn, 0, sizeof(*new_conn));

    /* Enable authentication and encryption by default. */
    new_conn->auxiliary_payload_data = (IPMI_SOL_AUX_USE_ENCRYPTION
					| IPMI_SOL_AUX_USE_AUTHENTICATION);

    rv = ipmi_create_lock_os_hnd(ipmi->os_hnd,
				 &new_conn->transmitter.packet_lock);
    if (rv) {
	ipmi_mem_free(new_conn);
	return rv;
    }

    rv = ipmi_create_lock_os_hnd(ipmi->os_hnd,
				 &new_conn->transmitter.queue_lock);
    if (rv) {
	ipmi_destroy_lock(new_conn->transmitter.packet_lock);
	ipmi_mem_free(new_conn);
	return rv;
    }

    new_conn->ipmi = ipmi;
    new_conn->data_received_callback_list = NULL;
    new_conn->break_detected_callback_list = NULL;
    new_conn->bmc_transmit_overrun_callback_list = NULL;
    new_conn->connection_state_callback_list = NULL;

    new_conn->prev_received_seqnr = 0;
    new_conn->prev_character_count = 0;

    new_conn->state = ipmi_sol_state_closed;
    new_conn->try_fast_connect = 1;

    new_conn->transmitter.sol_conn = new_conn;
    new_conn->transmitter.transmitted_packet = NULL;
    new_conn->transmitter.latest_outgoing_seqnr = 1;
    new_conn->transmitter.packet_to_acknowledge = 0;
    new_conn->transmitter.accepted_character_count = 0;
    new_conn->transmitter.bytes_acked_at_head = 0;

    new_conn->ACK_retries = 10;
    new_conn->ACK_timeout_usec = 1000000;

    *sol_conn = new_conn;

    return 0;
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
	    ipmi_log(IPMI_LOG_WARNING,
		     "BMC did not supply a sensible buffer size"
		     " (0x%02x, 0x%02x). Defaulting to 16.",
		     b1, b2);
	    result = 0x10; /* 16 bytes should be a safe buffer size. */
	} else
	    ipmi_log(IPMI_LOG_INFO,
		     "BMC sent a byte-swapped buffer size (%d bytes)."
		     " Using %d bytes.", (b2 << 8) + b1, result);
    }
    return result;
}

static void
ipmi_sol_handle_activate_payload_response(ipmi_sol_conn_t *conn,
					  ipmi_msg_t      *msg_in)
{
    /*
     * Did it work?
     */
    if (msg_in->data_len != 13) {
	if (msg_in->data_len != 1) {
	    ipmi_log(IPMI_LOG_WARNING,
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
	ipmi_log(IPMI_LOG_FATAL, "Activate payload failed.");
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

    if (conn->payload_port_number != IPMI_LAN_STD_PORT) {
	/* TODO: Currently don't handle ports other than the standard one! */
	ipmi_log(IPMI_LOG_FATAL,
		 "BMC requested connection through port %d."
		 " Ports other than %d are not currently supported.",
		 conn->payload_port_number, IPMI_LAN_STD_PORT);

	ipmi_sol_send_close(conn, NULL); 
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed, ENOSYS);
	return;
    }

    if (conn->max_outbound_payload_size > IPMI_SOL_MAX_DATA_SIZE)
	conn->transmitter.scratch_area_size = IPMI_SOL_MAX_DATA_SIZE;
    else
	conn->transmitter.scratch_area_size = conn->max_outbound_payload_size;

    ipmi_log(IPMI_LOG_INFO, "Connected to BMC SoL through port %d.",
	     /*		conn->hostname,*/
	     conn->payload_port_number);

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
	     "BMC requested transmit limit %d bytes, receive limit %d bytes.",
	     conn->max_outbound_payload_size,
	     conn->max_inbound_payload_size);

    if (conn->max_outbound_payload_size > conn->transmitter.scratch_area_size)
	ipmi_log(IPMI_LOG_WARNING, "Limiting transmit to %d bytes.",
		 conn->transmitter.scratch_area_size);
#endif

    /*
     * Set the hardware handshaking bits to match the "holdoff" option...
     */
    if (conn->auxiliary_payload_data & IPMI_SOL_AUX_DEASSERT_HANDSHAKE)
	conn->transmitter.oob_persistent_op
	    |= (IPMI_SOL_OPERATION_CTS_PAUSE
		| IPMI_SOL_OPERATION_DROP_DCD_DSR);
    else
	conn->transmitter.oob_persistent_op
	    &= ~(IPMI_SOL_OPERATION_CTS_PAUSE
		 | IPMI_SOL_OPERATION_DROP_DCD_DSR);

    /*
     * And officially bring the connection "up"!
     */
    ipmi_sol_set_connection_state(conn, ipmi_sol_state_connected, 0);
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
			ipmi_sol_handle_activate_payload_response);
}


static void
ipmi_sol_handle_set_volatile_bitrate_response(ipmi_sol_conn_t *conn,
					      ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 1) {
	ipmi_log(IPMI_LOG_WARNING,
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
	ipmi_log(IPMI_LOG_FATAL,
		 "Set SoL configuration[Volatile bit rate] failed.");
	ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				      IPMI_IPMI_ERR_VAL(msg_in->data[0]));
	return;
    }

#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO, "Volatile bit rate set.");
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
			ipmi_sol_handle_set_volatile_bitrate_response);
}

static void
ipmi_sol_handle_get_payload_activation_status_response(ipmi_sol_conn_t *conn,
						       ipmi_msg_t      *msg_in)
{
    int count = 0, found, max, byte, index;

    if (msg_in->data_len != 4) {
	ipmi_log(IPMI_LOG_FATAL,
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
	     "BMC currently using %d SoL payload instances; limit is %d.",
	     count, max);
#endif

    if (!found || (count >= max)) {
	ipmi_log(IPMI_LOG_FATAL, "BMC can't accept any more SoL sessions.");
	ipmi_sol_set_connection_state
	    (conn, ipmi_sol_state_closed,
	     IPMI_RMCPP_ERR_VAL(IPMI_RMCPP_INVALID_PAYLOAD_TYPE));
	return;
    }
#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO,
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
			ipmi_sol_handle_get_payload_activation_status_response);
}


static void
ipmi_sol_handle_session_info_response(ipmi_sol_conn_t *conn,
				      ipmi_msg_t      *msg_in)
{
#ifdef IPMI_SOL_VERBOSE
    char *privilege_level[16] = {
	"Unknown", "Callback", "User", "Operator", "Administrator",
	"OEM Proprietary", "Unknown", "Unknown", "Unknown", "Unknown",
	"Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"};
#endif

    if (msg_in->data_len < 7) {
	ipmi_log(IPMI_LOG_FATAL, "Get Session Info command failed.");
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
    ipmi_log(IPMI_LOG_INFO, "This session handle: 0x%02x"
	     "  BMC currently using %d of %d sessions",
	     msg_in->data[1], msg_in->data[3], msg_in->data[2]);
    ipmi_log(IPMI_LOG_INFO, "Current UserID: 0x%02x (%s)"
	     "  Channel number: 0x%02x",
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

    return send_message(conn, &msg_out, ipmi_sol_handle_session_info_response);
}

static void
ipmi_sol_handle_commit_write_response(ipmi_sol_conn_t *conn,
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

    return send_message(conn, &msg_out, ipmi_sol_handle_commit_write_response);
}

static void
ipmi_sol_handle_set_sol_enabled_response(ipmi_sol_conn_t *conn,
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
    ipmi_log(IPMI_LOG_INFO, "Attempting to enable SoL on BMC.");

    msg_out.data_len = 3;
    msg_out.data = data;

    /* own channel, get param (not just version) */
    msg_out.data[0] = IPMI_SELF_CHANNEL;
    msg_out.data[1] = 2; /* parameter selector = SOL Auth */
    msg_out.data[2] = 0x02; /* Enable SoL! */
	
    msg_out.netfn = IPMI_TRANSPORT_NETFN;
    msg_out.cmd = IPMI_SET_SOL_CONFIGURATION_PARAMETERS;

    return send_message(conn, &msg_out,
			ipmi_sol_handle_set_sol_enabled_response);
}

static void
ipmi_sol_handle_get_sol_enabled_response(ipmi_sol_conn_t *conn,
					 ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 3) {
	ipmi_log(IPMI_LOG_FATAL, "Get SoL Configuration[SoL Enabled] failed.");
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
	ipmi_log(IPMI_LOG_INFO, "BMC says SoL is enabled.");
#endif
	send_get_session_info(conn);
	return;
    }
    ipmi_log(IPMI_LOG_SEVERE, "BMC says SoL is disabled.");
	
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

    send_message(conn, &msg_out, ipmi_sol_handle_get_sol_enabled_response);
}


static void
ipmi_sol_handle_get_channel_payload_support_response(ipmi_sol_conn_t *conn,
						     ipmi_msg_t      *msg_in)
{
    if (msg_in->data_len != 9) {
	ipmi_log(IPMI_LOG_FATAL,
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
	ipmi_log(IPMI_LOG_ERR_INFO, "BMC says SoL is not supported.");
	ipmi_sol_set_connection_state
	    (conn, ipmi_sol_state_closed,
	     IPMI_RMCPP_ERR_VAL(IPMI_RMCPP_INVALID_PAYLOAD_TYPE));
	return;
    }
#ifdef IPMI_SOL_VERBOSE
    ipmi_log(IPMI_LOG_INFO, "BMC says SoL is supported.");
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
			ipmi_sol_handle_get_channel_payload_support_response);
}


int
ipmi_sol_open(ipmi_sol_conn_t *conn)
{
    /*
     * IPMI Get Channel Payload Support
     */
    if (conn->state != ipmi_sol_state_closed) {
	/* It's an error to try to connect when not in closed state. */
	ipmi_log(IPMI_LOG_WARNING,
		 "An attempt was made to open an SoL connection"
		 " that's already open.");
	return EINVAL;
    }

    ipmi_sol_set_connection_state(conn, ipmi_sol_state_connecting, 0);

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
	return send_get_payload_activation_status_command(conn);
    else
	return send_get_channel_payload_support_command(conn);
}


static void
ipmi_sol_handle_deactivate_payload_response(ipmi_sol_conn_t *conn,
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
    if ((conn->state == ipmi_sol_state_closing)
	|| (conn->state == ipmi_sol_state_closed))
	return EINVAL;
	
    ipmi_sol_send_close(conn, ipmi_sol_handle_deactivate_payload_response);
    return 0;
}


int
ipmi_sol_force_close(ipmi_sol_conn_t *conn)
{
    if (conn->state == ipmi_sol_state_closed)
	return EINVAL;

    if (conn->state != ipmi_sol_state_closing)
	/*
	 * Try to be polite to the BMC. Don't ask for a callback,
	 * cos we'll be gone!
	 */
	ipmi_sol_send_close(conn, NULL); 

    transmitter_shutdown(&conn->transmitter,
			 IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));

    ipmi_sol_set_connection_state(conn, ipmi_sol_state_closed,
				  IPMI_SOL_ERR_VAL(IPMI_SOL_DISCONNECTED));

    return 0;
}


int
ipmi_sol_free(ipmi_sol_conn_t *conn)
{
    if (conn->state != ipmi_sol_state_closed)
	ipmi_sol_force_close(conn);
	
    conn->ipmi->close_connection(conn->ipmi);
    ipmi_destroy_lock(conn->transmitter.queue_lock);
    ipmi_destroy_lock(conn->transmitter.packet_lock);
    ipmi_mem_free(conn);
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

/* Handle an asynchronous message.  This *should* deliver the
   message, if possible. */
static void
sol_handle_recv_async(ipmi_con_t    *ipmi_conn,
		      unsigned char *packet,
		      unsigned int  data_len)
{
    ipmi_sol_conn_t                *conn;
    ipmi_sol_transmitter_context_t *xmitter;
    int                            nack = 0;

    conn = find_sol_connection_for_ipmi(ipmi_conn);
    if (!conn) {
	ipmi_log(IPMI_LOG_WARNING,
		 "Dropped incoming SoL packet: Unrecognized connection.");
	return;
    }

    if (data_len < 4) {
	ipmi_log(IPMI_LOG_WARNING,
		 "Dropped incoming SoL packet: Too short, at %d bytes.",
		 data_len);
	return;
    }

#ifdef IPMI_SOL_DEBUG_RECEIVE
    ipmi_log(IPMI_LOG_INFO, "Received SoL packet, %d bytes", data_len);
    dump_hex(packet, data_len);
#endif

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

    xmitter = &conn->transmitter;

    ipmi_lock(xmitter->packet_lock);

    if (data_len > 4) {
	data_len -= 4; /* Skip over header */

	if (0 == packet[PACKET_SEQNR]) {
	    /* Can't have data in a packet with zero seqnr: error */
	    ipmi_log(IPMI_LOG_WARNING,
		     "Broken BMC: Received a packet with non-empty data"
		     " and a sequence number of zero.");
	} else {
	    int character_count;
	    int send_nack;

	    if (conn->prev_received_seqnr == packet[PACKET_SEQNR]) {
		/* overlapping packets... yummy */
		character_count = data_len - conn->prev_character_count;
	    } else {
		/* This whole packet goes to the client(s) */
		character_count = data_len;
		conn->prev_received_seqnr = packet[PACKET_SEQNR];
	    }
	    send_nack = do_data_received_callbacks
		(conn, &packet[PACKET_DATA + data_len - character_count],
		 character_count);

	    conn->prev_received_seqnr = packet[PACKET_SEQNR];
	    xmitter->packet_to_acknowledge = packet[PACKET_SEQNR];

	    if (send_nack) {
		xmitter->oob_transient_op |= IPMI_SOL_OPERATION_NACK_PACKET;
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

    if (packet[PACKET_STATUS] & IPMI_SOL_STATUS_BREAK_DETECTED)
	do_break_detected_callbacks(conn);

    if (packet[PACKET_STATUS] & IPMI_SOL_STATUS_BMC_TX_OVERRUN)
	do_transmit_overrun_callbacks(conn);

    if (nack && (packet[PACKET_STATUS] & IPMI_SOL_STATUS_DEACTIVATED)) {
	transmitter_shutdown(xmitter, IPMI_SOL_ERR_VAL(IPMI_SOL_DEACTIVATED));
	 /* Success! */
	ipmi_sol_set_connection_state(conn,
				      ipmi_sol_state_closed,
				      IPMI_SOL_ERR_VAL(IPMI_SOL_DEACTIVATED));
	ipmi_unlock(xmitter->packet_lock);
    } else {
	ipmi_unlock(xmitter->packet_lock);
	transmitter_prod(xmitter);
    }
}

static ipmi_payload_t ipmi_sol_payload =
{ sol_format_msg, sol_get_recv_seq, sol_handle_recv,
  sol_handle_recv_async, NULL /*sol_get_msg_tag*/ };

