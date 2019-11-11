/*
   Command line processing

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_CMDLINE_H__
#define __CTDB_CMDLINE_H__

#include <popt.h>
#include <talloc.h>

/**
 * @file cmdline.h
 *
 * @brief Command-line handling with options and commands
 *
 * This abstraction encapsulates the boiler-plate for parsing options,
 * commands and arguments on command-line.
 *
 * Options handling is done using popt.
 */

/**
 * @brief Abstract data structure holding command-line configuration
 */
struct cmdline_context;

/**
 * @brief A command definition structure
 *
 * @name is the name of the command
 * @fn is the implementation of the command
 * @msg_help is the help message describing command
 * @msg_args is the help message describing arguments
 *
 * A command name can be a single word or multiple words separated with spaces.
 *
 * An implementation function should return 0 on success and non-zero value
 * on failure.  This value is returned as result in @cmdline_run.
 */
struct cmdline_command {
	const char *name;
	int (*fn)(TALLOC_CTX *mem_ctx,
		  int argc,
		  const char **argv,
		  void *private_data);
	const char *msg_help;
	const char *msg_args;
};

/**
 * @brief convinience macro to define the end of commands list
 *
 * Here is an example of defining commands list.
 *
 * struct cmdline_command commands[] = {
 *	{ "command1", command1_func, "Run command1", NULL },
 *	{ "command2", command2_func, "Run command2", "<filename>" },
 *	CMDLINE_TABLEEND
 * };
 */
#define CMDLINE_TABLEEND  { NULL, NULL, NULL, NULL }

/**
 * @brief Initialize cmdline abstraction
 *
 * If there are no options, options can be NULL.
 *
 * Help options (--help, -h) are automatically added to the options.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] prog Program name
 * @param[in] options Command-line options
 * @param[in] section Name of section grouping specified commands
 * @param[in] commands Commands array
 * @param[out] result New cmdline context
 * @return 0 on success, errno on failure
 *
 * Freeing cmdline context will free up all the resources.
 */
int cmdline_init(TALLOC_CTX *mem_ctx,
		 const char *prog,
		 struct poptOption *options,
		 const char *section,
		 struct cmdline_command *commands,
		 struct cmdline_context **result);


/**
 * @brief Add command line section/commands
 *
 * @param[in] cmdline Cmdline context
 * @param[in] section Name of section grouping specified commands
 * @param[in] commands Commands array
 * @return 0 on success, errno on failure
 */
int cmdline_add(struct cmdline_context *cmdline,
		const char *section,
		struct cmdline_command *commands);

/**
 * @brief Parse command line options and commands/arguments
 *
 * This function parses the arguments to process options and commands.
 *
 * This function should be passed the arguments to main() and parse_options
 * should be set to true.  If cmdline is used for handling second-level
 * commands, then parse_options should be set to false.
 *
 * If argv does not match any command, then ENOENT is returned.
 *
 * @param[in] cmdline Cmdline context
 * @param[in] argc Number of arguments
 * @param[in] argv Arguments array
 * @param[in] parse_options Whether to parse for options
 * @return 0 on success, errno on failure
 */
int cmdline_parse(struct cmdline_context *cmdline,
		  int argc,
		  const char **argv,
		  bool parse_options);

/**
 * @brief Excecute the function for the command matched by @cmdline_parse
 *
 * @param[in] cmdline Cmdline context
 * @param[in] private_data Private data for implementation function
 * @param[out] result Return value from the implementation function
 * @return 0 on success, errno on failure
 *
 * If help options are specified, then detailed help will be printed and
 * the return value will be EAGAIN.
 */
int cmdline_run(struct cmdline_context *cmdline,
		void *private_data,
		int *result);

/**
 * @brief Print usage help message to stdout
 *
 * @param[in] cmdline Cmdline context
 * @param[in] command Command string
 *
 * If command is NULL, then full help is printed.
 * If command is specified, then compact help is printed.
 */
void cmdline_usage(struct cmdline_context *cmdline, const char *command);

#endif /* __CTDB_CMDLINE_H__ */
