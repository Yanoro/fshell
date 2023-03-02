#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <assert.h>

#define MAX_COMMAND_SIZE 1024
#define MAX_ARGS 40

// Modify command_buf so that it becomes a null separated string and make args point to every
// single string
size_t parse_args(char *command_buf, char *args[MAX_ARGS]) {
  int args_index, start, curr;
  size_t command_size = strlen(command_buf);
  for (args_index = 0, start = 0 , curr = 0; curr < command_size; curr++) {
    if (command_buf[curr] == ' ') {
      args[args_index++] = command_buf + start;
      command_buf[curr++] = '\0';
      start = curr;
      while (command_buf[curr] == ' ') {
        curr++;
        start++;
      }
    }
  }

  args[args_index++] = command_buf + start;
  args[args_index] = NULL;

  return args_index;
}

// Remove first member of the array and place everyone after it one position behind
void remove_from_args(char **args) {
  int i;
  for (i = 1; args + i != NULL; i++) {
    *(args + i - 1) = *(args + i);
  }

  *(args + i - 1) = NULL;
}

int main(void) {
  char command_buf[MAX_COMMAND_SIZE];
  char history_buffer[MAX_COMMAND_SIZE]; /* Holds previous command */
  char *args[MAX_ARGS];

  memset(history_buffer, '\0', MAX_COMMAND_SIZE);

  int pid;
  int should_run = 1;
  size_t args_size = sizeof(char *) * 40;

  // Allocating MAX_COMMAND_SIZE bytes is a little overkill but ensures that our buffers will never overflow
  char output_redirect_filename[MAX_COMMAND_SIZE];
  char input_redirect_filename[MAX_COMMAND_SIZE];

  while (should_run) {
  loop_start:
    int args_index, i;
    int foreground = 0;

    memset(output_redirect_filename, '\0', MAX_COMMAND_SIZE);
    memset(input_redirect_filename, '\0', MAX_COMMAND_SIZE);

    printf("fsh>");

    fflush(stdout);

    fgets(command_buf, MAX_COMMAND_SIZE, stdin);

    // Just reset and go to next iteration if the user just presses enter
    if (command_buf[0] == '\n') {
      memset(command_buf, 0, MAX_COMMAND_SIZE);
      continue;
    }

    command_buf[strcspn(command_buf, "\n")] = '\0'; // Remove newline

    // If command was "!!" we must look use the previously stored history buffer to execute the previous
    // command, notice that in this case we don't need to parse our arguments since they've already been parsed
    if (strncmp(command_buf, "!!", 2) == 0) {
      // If history_buffer wasn't initialized then we just reset and go to next iteration
      if (history_buffer[0] == '\0') {
        printf("No commands in history\n");
        continue;
      }
      // Something important to note is that we can only get here if we iterate through this loop at least
      // once, which means that args and args_size are already properly set (Since we are using the command buf
      // used in their iteration)
      memcpy(command_buf, history_buffer, MAX_COMMAND_SIZE);
    }
    else
      args_index = parse_args(command_buf, args);

    // Store this command in case we need it in the future (: !! command)
    memcpy(history_buffer, command_buf, MAX_COMMAND_SIZE);

    // Parse arguments for special characters such as &, >, < and |
    // Beware that after parsing > and < we don't take into account anything after the following rediction
    // destination, i.e: ls > test cat passwd is equivalent to ls > test
    for (i = 0; i < args_index; i++) {
      // Handle Foregrounding
      if (strncmp(args[i], "&", 1) == 0) {
        foreground = 1;
        args[i] = NULL;
        break;
      } // Handle output redirection
      else if (strncmp(args[i], ">", 1) == 0) {
        if (i + 1 == args_index) {
          printf("Output redirection needs a file to redirect to\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          goto loop_start;
        }

        strncpy(output_redirect_filename, args[i+1], strlen(args[i+1]));

        args[i] = NULL;
        break;
      } // Handle input redirection
      else if (strncmp(args[i], "<", 1) == 0) {
        if (i + 1 == args_index) {
          printf("Input redirection needs a file to redirect to\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          goto loop_start;
        }

        strncpy(input_redirect_filename, args[i+1], strlen(args[i+1]));
        args[i] = NULL;
        break;
      }


      
    }

    pid = fork();

    if (pid == 0) { // Child process
      FILE *file;
      // Handle IO redirection
      if (output_redirect_filename[0] != '\0') {
        if ((file = fopen(output_redirect_filename, "w")) == 0) {
          fprintf(stderr, "Failed to open output redirection file\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          continue;
        }

        dup2(fileno(file), STDOUT_FILENO);
        close(fileno(file));
      }
      else if (input_redirect_filename[0] != '\0') {
        if ((file = fopen(input_redirect_filename, "r")) == 0) {
          fprintf(stderr, "Failed to open input redirection file\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          continue;
        }
        dup2(fileno(file), STDIN_FILENO);
        close(fileno(file));
      }
      execvp(args[0], args);
      perror("fsh");
      return -1;
    }

    if (!foreground)
      wait(&pid);

    memset(command_buf, 0, MAX_COMMAND_SIZE);
  }

  return 0;
}
