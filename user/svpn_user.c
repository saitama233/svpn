/* SPDX-License-Identifier: GPL-2.0 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "subcommands.h"

const char *PROG_NAME;

static const struct {
	const char *subcommand;
	int (*function)(int, char**);
	const char *description;
} subcommands[] = {
	{"setconf", setconf_main, "Applies a configuration file to a svpn interface"},
};

static void show_usage(FILE *file)
{
	fprintf(file, "Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available subcommands:\n");
	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i)
		fprintf(file, "  %s: %s\n", subcommands[i].subcommand, subcommands[i].description);
	fprintf(file, "You may pass `--help' to any of these subcommands to view usage.\n");
}

int main(int argc, char *argv[])
{
	PROG_NAME = argv[0];
    
    if (argc < 2)
        show_usage(stdout);

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) {
		show_usage(stdout);
		return 0;
	}

	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i) {
		if (!strcmp(argv[1], subcommands[i].subcommand))
			return subcommands[i].function(argc - 1, argv + 1);
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	show_usage(stderr);
	return -1;
}
