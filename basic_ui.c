
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_ui.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_int.h>

int
main(int argc, char *argv[])
{
    int        rv;
    selector_t *selector;
    int        curr_arg = 1;
    char       *arg;
    int        full_screen = 1;

    while ((argc > 1) && (argv[curr_arg][0] == '-')) {
	arg = argv[curr_arg];
	curr_arg++;
	argc--;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if (strcmp(arg, "-c") == 0) {
	    full_screen = 0;
	} else if (strcmp(arg, "-dmem") == 0) {
	    DEBUG_MALLOC_ENABLE();
	} else if (strcmp(arg, "-dmsg") == 0) {
	    DEBUG_MSG_ENABLE();
	} else {
	    fprintf(stderr, "Unknown option: %s\n", arg);
	    return 1;
	}
    }

    if (argc < 2) {
	fprintf(stderr, "Not enough arguments\n");
	exit(1);
    }

    rv = ipmi_ui_init(&selector, full_screen);

    if (strcmp(argv[curr_arg], "smi") == 0) {
	int smi_intf;

	if (argc < 3) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}

	smi_intf = atoi(argv[curr_arg+1]);
	rv = ipmi_smi_setup_con(smi_intf,
				&ipmi_ui_cb_handlers, selector,
				ipmi_ui_setup_done, NULL);
	if (rv) {
	    fprintf(stderr, "ipmi_smi_setup_con: %s\n", strerror(rv));
	    exit(1);
	}

    } else if (strcmp(argv[curr_arg], "lan") == 0) {
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

	ent = gethostbyname(argv[curr_arg+1]);
	if (!ent)
	    fprintf(stderr, "gethostbyname failed: %s\n", strerror(h_errno));

	memcpy(&lan_addr, ent->h_addr_list[0], ent->h_length);
	lan_port = atoi(argv[curr_arg+2]);

	if (strcmp(argv[curr_arg+3], "none") == 0) {
	    authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[curr_arg+3], "md2") == 0) {
	    authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[curr_arg+3], "md5") == 0) {
	    authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[curr_arg+3], "straight") == 0) {
	    authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else {
	    fprintf(stderr, "Invalid authtype: %s\n", argv[curr_arg+3]);
	    rv = EINVAL;
	    goto out;
	}

	if (strcmp(argv[curr_arg+4], "callback") == 0) {
	    privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[curr_arg+4], "user") == 0) {
	    privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[curr_arg+4], "operator") == 0) {
	    privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[curr_arg+4], "admin") == 0) {
	    privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    fprintf(stderr, "Invalid privilege: %s\n", argv[curr_arg+4]);
	    rv = EINVAL;
	    goto out;
	}

	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
	strncpy(username, argv[curr_arg+5], 16);
	username[16] = '\0';
	strncpy(password, argv[curr_arg+6], 16);
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

    sel_select_loop(selector, NULL, 0, NULL);

 out:
    ipmi_ui_shutdown();

    if (rv)
	return 1;
    return 0;
}
