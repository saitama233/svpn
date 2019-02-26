#include <stdio.h>
#include <string.h>
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

int setconf_main(int argc, char *argv[])
{
    struct config_ctx   ctx;
    struct svpn_config  *config;
    FILE                *configfile = NULL;
    char                *config_buffer = NULL;
    size_t              config_buffer_len = 0;
    int                 ret = -1;

    dbg_lprintf("in setconf_main\n");
    if (argc != 3) {
        lprintf("Usage: %s %s <interface> <configuration filename>\n", PROG_NAME, argv[0]);
        goto out;
    }

    configfile = f_open(argv[2], "r");
    if (!configfile) {
        lprintf("Open file %s error\n", argv[2]);
        goto out;
    }

    if (!config_read_init(&ctx, !strcmp(argv[0], "addconf"))) {
        lprintf("Configuration init error\n");
        goto out;
    }

    while (getline(&config_buffer, &config_buffer_len, configfile) >= 0) {
        if (!config_read_line(&ctx, config_buffer)) {
            lprintf("Configuration parsing error\n");
            goto out;
        }
    }

    config = config_read_finish(&ctx);
    if (!config) {
        lprintf("Configuration failed: %s\n", argv[2]);
        goto out;
    }
    strncpy(config->local.device_name, argv[1], IFNAMSIZ - 1);
    config->local.device_name[IFNAMSIZ - 1] = '\0';

    ipc_setconf(config);
    
    ret = 0;
out:
    if (configfile)
        fclose(configfile);
    return ret;
}
