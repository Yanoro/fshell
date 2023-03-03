#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <assert.h>

//TODO:
// Refactor eval function into smaller functions
// Allows multiple special operators in a single line
// Implement ;

#define MAX_COMMAND_SIZE 1024
#define MAX_ARGS 40
#define READ_END 0
#define WRITE_END 1

struct command_history {
  char history_buffer[MAX_COMMAND_SIZE];
  char *args[MAX_ARGS];
  size_t args_index;
};

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
      while (command_buf[curr] == ' ' && curr < command_size) {
        curr++;
        start++;
      }
    }
  }

  // Make sure that we are pointing at an actual string instead of a bunch of spaces
  if (!(start == command_size))
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

void eval(char command_buf[MAX_COMMAND_SIZE], struct command_history *history) {
  int args_index, i, foreground, pid;


  char *args[MAX_ARGS];

  // Allocating MAX_COMMAND_SIZE bytes is a little overkill but ensures that our buffers will never overflow
  char output_redirect_filename[MAX_COMMAND_SIZE];
  char input_redirect_filename[MAX_COMMAND_SIZE];

  // Holds the command that is supposed to be piped to
  // i.e: in "ls | sort -u", piped_command = ["sort", "-u"]
  char **piped_command = NULL;

  char *history_buffer = history->history_buffer;

  size_t args_size = sizeof(char *) * MAX_ARGS;

  memset(output_redirect_filename, '\0', MAX_COMMAND_SIZE);
  memset(input_redirect_filename, '\0', MAX_COMMAND_SIZE);

  fgets(command_buf, MAX_COMMAND_SIZE, stdin);

  // Just reset and go to next iteration if the user just presses enter
  if (command_buf[0] == '\n') {
    memset(command_buf, 0, MAX_COMMAND_SIZE);
    return;
  }

  command_buf[strcspn(command_buf, "\n")] = '\0'; // Remove newline

  // If command was "!!" we must look use the previously stored history buffer to execute the previous
  // command, notice that in this case we don't need to parse our arguments since they've already been parsed
  if (strncmp(command_buf, "!!", 2) == 0) {
    // If history_buffer wasn't initialized then we just reset and go to next iteration
    if (history_buffer[0] == '\0') {
      printf("No commands in history\n");
      return;
    }
    // If we got here then we can safely use the data stored in our command history
    memcpy(command_buf, history_buffer, MAX_COMMAND_SIZE);
    memcpy(args, history->args, args_size);
    args_index = history->args_index;
  }
  else
    args_index = parse_args(command_buf, args);

  // Store this command in case we need it in the future (: !! command)
  memcpy(history_buffer, command_buf, MAX_COMMAND_SIZE);
  memcpy(history->args, args, args_size);
  history->args_index = args_index;

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
        return;
      }

      strncpy(output_redirect_filename, args[i+1], strlen(args[i+1]));

      args[i] = NULL;
      break;
    } // Handle input redirection
    else if (strncmp(args[i], "<", 1) == 0) {
      if (i + 1 == args_index) {
        printf("Input redirection needs a file to redirect to\n");
        memset(command_buf, 0, MAX_COMMAND_SIZE);
        return;
      }

      strncpy(input_redirect_filename, args[i+1], strlen(args[i+1]));
      args[i] = NULL;
      break;
    }
    else if (strncmp(args[i], "|", 1) == 0) {
      if (i + 1 == args_index) {
        printf("Pipe needs a command following it to redirect to\n");
        memset(command_buf, 0, MAX_COMMAND_SIZE);
        return;
      }

      // Need to set the pipe to NULL so that when we only evaluate the first part of the command
      args[i] = NULL;
      piped_command = &args[i + 1];
    }

  }

  pid = fork();

  if (pid == 0) { // Child process
    FILE *file;
    // Handle IO redirection
    // Notice that to make our life easier we are assuming that we are only using one special operator for
    // each command
      if (output_redirect_filename[0] != '\0') {
        if ((file = fopen(output_redirect_filename, "w")) == 0) {
          fprintf(stderr, "Failed to open output redirection file\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          return;
        }

        dup2(fileno(file), STDOUT_FILENO);
        close(fileno(file));
      }
      else if (input_redirect_filename[0] != '\0') {
        if ((file = fopen(input_redirect_filename, "r")) == 0) {
          fprintf(stderr, "Failed to open input redirection file\n");
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          return;
        }

        dup2(fileno(file), STDIN_FILENO);
        close(fileno(file));
      }
      else if (piped_command != NULL) {
        int first_fork_pid = fork();

        if (first_fork_pid < 0) {
          fprintf(stderr, "Failed to fork pipe command\n");
          return;
        }

        if (first_fork_pid == 0) {// Child process
          int fd[2];
          if (pipe(fd) == -1) {
            fprintf(stderr, "Failed to create pipe\n");
            return;
          }

          int second_fork_pid = fork();

          if (second_fork_pid < 0) {
            fprintf(stderr, "Failed to fork pipe command\n");
            return;
          }
          if (second_fork_pid == 0) { // Child process
            close(fd[READ_END]);
            dup2(fd[WRITE_END], STDOUT_FILENO);
            close(fd[WRITE_END]);
            execvp(args[0], args);
            perror("fsh");
            exit(-1);
          }
          else { // Parent process
            wait(&second_fork_pid);
            close(fd[WRITE_END]);
            dup2(fd[READ_END], STDIN_FILENO);
            close(fd[READ_END]);
            execvp(*piped_command, piped_command);
            perror("fsh");
            exit(-1);
          }
        }
        else { // parent process
          wait(&first_fork_pid);
          memset(command_buf, 0, MAX_COMMAND_SIZE);
          return;
        }
      }

      execvp(args[0], args);
      perror("fsh");
      exit(-1);
  }

  if (!foreground)
    wait(&pid);

  memset(command_buf, 0, MAX_COMMAND_SIZE);

}

int main(void) {
  char command_buf[MAX_COMMAND_SIZE];
  struct command_history history;

  char *args[MAX_ARGS];

  int pid;
  int should_run = 1;
  size_t args_size = sizeof(char *) * 40;

  memset(history.history_buffer, 0, MAX_COMMAND_SIZE); // We want to make sure that in the first iteration of the loop our history buffer is properly initialized to that we can know wether it stores data or not

  while (should_run) {
    memset(command_buf, 0, MAX_COMMAND_SIZE);

    printf("fsh>");

    fflush(stdout);

    eval(command_buf, &history);
  }

  return 0;
}
