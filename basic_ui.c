
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ipmi/selector.h>
#include <ipmi/ipmi_ui.h>
#include <ipmi/ipmi_auth.h>
#include <ipmi/ipmi_smi.h>
#include <ipmi/ipmi_lan.h>

int
main(int argc, char *argv[])
{
    int        rv;
    selector_t *selector;

#if 0
    __ipmi_log_mask = DEBUG_MSG_BIT;
#endif

    if (argc < 2) {
	fprintf(stderr, "Not enough arguments\n");
	exit(1);
    }

    rv = ipmi_ui_init(&selector);

    if (strcmp(argv[1], "smi") == 0) {
	int smi_intf;

	if (argc < 3) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}

	smi_intf = atoi(argv[2]);
	rv = ipmi_smi_setup_con(smi_intf,
				&ipmi_ui_cb_handlers, selector,
				ipmi_ui_setup_done, NULL);
	if (rv) {
	    fprintf(stderr, "ipmi_smi_setup_con: %s\n", strerror(rv));
	    exit(1);
	}

    } else if (strcmp(argv[1], "lan") == 0) {
	struct hostent *ent;
	struct in_addr lan_addr;
	int            lan_port;
	int            authtype = 0;
	int            privilege = 0;
	char           username[17];
	char           password[17];

	if (argc < 8) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}

	ent = gethostbyname(argv[2]);
	if (!ent)
	    fprintf(stderr, "gethostbyname failed: %s\n", strerror(h_errno));

	memcpy(&lan_addr, ent->h_addr_list[0], ent->h_length);
	lan_port = atoi(argv[3]);

	if (strcmp(argv[4], "none") == 0) {
	    authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[4], "md2") == 0) {
	    authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[4], "md5") == 0) {
	    authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[4], "straight") == 0) {
	    authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else {
	    fprintf(stderr, "Invalid authtype: %s\n", argv[4]);
	    rv = EINVAL;
	    goto out;
	}

	if (strcmp(argv[5], "callback") == 0) {
	    privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[5], "user") == 0) {
	    privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[5], "operator") == 0) {
	    privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[5], "admin") == 0) {
	    privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    fprintf(stderr, "Invalid privilege: %s\n", argv[5]);
	    rv = EINVAL;
	    goto out;
	}

	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
	strncpy(username, argv[6], 16);
	username[16] = '\0';
	strncpy(password, argv[7], 16);
	password[16] = '\0';

	rv = ipmi_lan_setup_con(lan_addr, lan_port,
				authtype, privilege,
				username, strlen(username),
				password, strlen(password),
				&ipmi_ui_cb_handlers, selector,
				ipmi_ui_setup_done, NULL);
	if (rv) {
	    fprintf(stderr, "ipmi_lan_setup_con: %s", strerror(rv));
	    rv = EINVAL;
	    goto out;
	}
    } else {
	fprintf(stderr, "Invalid mode\n");
	rv = EINVAL;
	goto out;
    }

    sel_select_loop(selector);

 out:
    ipmi_ui_shutdown();

    if (rv)
	return 1;
    return 0;
}
