/**
 * @file rsvp_cli.h
 * @brief Command Line Interface (CLI) for RSVP-TE.
 * @details Provides functions to process user input from the console for debugging and operational commands.
 */

#ifndef RSVP_CLI_H
#define RSVP_CLI_H

/**
 * @brief Handle input from the CLI (stdin).
 * @details Reads a command from the provided file descriptor, parses it, and invokes the corresponding subsystem functions.
 * @param [in] fd The file descriptor to read input from (typically STDIN_FILENO).
 */
int rsvp_cli_handle_input(int fd);

#endif /* RSVP_CLI_H */