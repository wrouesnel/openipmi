#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/ipmi.h>
#include <stdio.h>

#define MY_NETFN        0x32
#define MY_CMD          0x01

int
main(int argc, char *argv)
{
  int                 fd;
  int                 rv;
  int                 i;
  struct ipmi_cmdspec cmdspec;
  unsigned char       data[IPMI_MAX_MSG_LENGTH];
  struct ipmi_addr    addr;
  struct ipmi_recv    recv;
  struct ipmi_req     req;
  fd_set              rset;
  int                 count;
  int                 got_one;

  fd = open("/dev/ipmi0", O_RDWR);
  if (fd == -1) {
    fd = open("/dev/ipmidev/0", O_RDWR);
    if (fd == -1) {
      perror("open");
      exit(1);
    }
  }

  /* Register to get the command */
  cmdspec.netfn = MY_NETFN;
  cmdspec.cmd = MY_CMD;
  rv = ioctl(fd, IPMICTL_REGISTER_FOR_CMD, &cmdspec);
  if (rv == -1) {
      perror("ioctl register_for_cmd");
      exit(1);
  }
  count = 0;
  got_one = 0;

  while (count || !got_one) {
    /* Wait for a message. */
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    rv = select(fd+1, &rset, NULL, NULL, NULL);
    if (rv == -1) {
      if (errno == EINTR)
        continue;
      perror("select");
      exit(1);
    }

    /* Get the message. */
    recv.msg.data = data;
    recv.msg.data_len = sizeof(data);
    recv.addr = (unsigned char *) &addr;
    recv.addr_len = sizeof(addr);
    rv = ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv);
    if (rv == -1) {
      perror("ioctl recv_msg_trunc");
      exit(1);
    }
    
    if ((recv.recv_type == IPMI_CMD_RECV_TYPE)
        && (recv.msg.netfn == MY_NETFN)
        && (recv.msg.cmd == MY_CMD))
    {
      /* We got a command, send a response. */
      data[0] = 0; /* No error */
      for (i=1; i<10; i++)
        data[i] = i;
      req.addr = (void *) recv.addr;
      req.addr_len = recv.addr_len;
      req.msgid = recv.msgid;
      req.msg.netfn = recv.msg.netfn | 1; /* Make it a response */
      req.msg.cmd = recv.msg.cmd;
      req.msg.data = data;
      req.msg.data_len = 10;
      rv = ioctl(fd, IPMICTL_SEND_COMMAND, &req);
      if (rv == -1) {
          perror("ioctl send_cmd");
          exit(1);
      }
      count++;
      got_one = 1;
    }
    else if ((recv.recv_type == IPMI_RESPONSE_RESPONSE_TYPE)
             && (recv.msg.netfn == MY_NETFN | 1)
             && (recv.msg.cmd == MY_CMD))
    {
      /* We got a response to our response send, done. */
      count--;
    }
    else
    {
      printf("Got wrong msg type %d, netfn %x, cmd %x\n",
             recv.recv_type, recv.msg.netfn, recv.msg.cmd);
    }
  }

  /* Remove our command registration. */
  rv = ioctl(fd, IPMICTL_UNREGISTER_FOR_CMD, &cmdspec);
  if (rv == -1) {
      perror("ioctl unregister_for_cmd");
      exit(1);
  }

  exit(0);
}
