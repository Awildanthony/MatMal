#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdarg.h>


#define STACK_SIZE (1024 * 1024)    // Stack size for clone() - 1MB
#define MAX_PROCESSES 3


// =================================== { NETWORKING } ===================================

// Helper function to check if an IP address is in the 127.0.0.* range.
int is_localhost(struct sockaddr_in *addr) {
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    int result = (ip >> 24) == 127 && 
                 ((ip >> 16) & 0xFF) == 0 && 
                 ((ip >> 8) & 0xFF) == 0;
    return result;
}


// Function to read sockaddr from process memory.
int check_connect_addr(pid_t pid, unsigned long addr_ptr) {
    struct sockaddr_in addr;
    
    // Read the sockaddr_in struct piece-by-piece.
    for(size_t i = 0; i < sizeof(struct sockaddr_in); i += sizeof(long)) {
        errno = 0;
        unsigned long data = ptrace(PTRACE_PEEKDATA, pid, addr_ptr + i, NULL);
        if (errno != 0) {
            return 0;  // Disallow if read fails
        }

        // Copy the bytes we just read into our local struct.
        size_t bytes_to_copy = (i + sizeof(long) > sizeof(struct sockaddr_in)) ? 
                              sizeof(struct sockaddr_in) - i : 
                              sizeof(long);
        memcpy((char*)&addr + i, &data, bytes_to_copy);
    }
    
    // Only allow localhost connections.
    return is_localhost(&addr);
}


// =================================== { PROCESSES } ====================================

// Type definition for process.
struct proc;
typedef struct proc {
    pid_t pid;
    int is_entry;       // 1 if we expect syscall entry, 0 if we expect syscall exit
    int to_kill;        // 1 if process should be killed on entry
    int block_connect;  // 1 if current connect() syscall should be blocked
    struct proc* next;
} proc;

// Process metadata.
proc *ptable = NULL;
int live_procs = 0;

// Function to create and add a new process to the ptable.
proc *add_process(pid_t pid) {
    // Create new process.
    proc *new_proc = malloc(sizeof(proc));

    // Assign attributes.
    new_proc->pid = pid;
    new_proc->is_entry = 1;

    // Add process to ptable.
    if (ptable) {
        new_proc->next = ptable;
    }
    ptable = new_proc;

    // Increment process count and return upon success.
    live_procs++;
    return new_proc;
}

// Function to remove existing process from the ptable.
void remove_process(pid_t pid) {
    proc *prev = NULL;
    proc *curr = ptable;

    while (curr != NULL) {
        if (curr->pid == pid) {
            if (prev == NULL) {
                ptable = curr->next;
            } else {
                prev->next = curr->next;
            }
            // Free the removed process and update proc count.
            free(curr);
            --live_procs;
            break;
        }

        // ...
        prev = curr;
        curr = curr->next;
    }
}

// Function to return the pointer to the process with `pid`.
proc *get_proc_ptr(pid_t pid) {
    proc *curr = ptable;
    proc *prev = NULL;
    
    while (curr != NULL) {
        if (curr->pid == pid){
            return curr;
        }

        // ...
        prev = curr;
        curr = curr->next;
    }
    if (pid == -1) {
        return prev;
    }
    return NULL;
}


// =================================== { SANDBOXING } ===================================

// Function to sandbox a child process.
int sandbox_child(void *arg) {
    // Retrieve arguments.
    char **argv = (char **)arg;
    char *guest_dir = argv[1];
    uid_t uid = atoi(argv[2]);

    // ptrace the child process.
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace TRACEME failed");
        return EXIT_FAILURE;
    }

    // Change to specified directory.
    if (chdir(guest_dir) == -1) {
        perror("chdir failed");
        return EXIT_FAILURE;
    }

    // Drop privileges by setting the UID.
    if (setuid(uid) == -1) {
        perror("setuid failed");
        return EXIT_FAILURE;
    }

    // Execute the guest Python script with reduced privileges.
    char *exec_args[] = {"python3", "guest.pyc", NULL};
    execvp(exec_args[0], exec_args);

    // If execvp fails:
    perror("execvp failed");
    return EXIT_FAILURE;
}


// Sandbox monitoring loop.
void monitor_guest(pid_t child_pid) {
    int status;
    struct user_regs_struct regs;

    // Track guest process; add it to the ptable.
    if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_EXITKILL) == -1) {
        perror("ptrace SETOPTIONS failed");
        exit(EXIT_FAILURE);
    }
    add_process(child_pid);

    // Until guest process exits or is killed ...
    while (1) {
        // Wait for (any) process to die.
        pid_t event_pid = waitpid(-1, &status, __WALL);
        if (event_pid == -1) {
            return;  // error
        }

        // Check for if that process exited; if so, remove it from the ptable.
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_process(event_pid);
            if (event_pid == child_pid && live_procs == 0) {
                break;  // Main guest exited - stop monitoring.
            }
            continue;
        }

        // Check for signal other than TRAP.
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            int sig = WSTOPSIG(status);
            ptrace(PTRACE_SYSCALL, event_pid, 0, sig);  // Replay the signal
            continue;
        }

        // Check for process creation events (fork(), vfork(), clone()).
        if (WIFSTOPPED(status) &&
            ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
             (status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
             (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))) {
        
            // Retrieve the new PID created by fork(), vfork(), or clone().
            pid_t new_pid;
            if (ptrace(PTRACE_GETEVENTMSG, event_pid, NULL, &new_pid) == -1) {
                perror("ptrace GETEVENTMSG failed");
                exit(EXIT_FAILURE);
            }

            // Send stop signal to the new process.
            if (kill(new_pid, SIGSTOP) == -1) {
                perror("kill SIGSTOP failed");
                exit(EXIT_FAILURE);
            }

            // Wait for the new process to stop.
            int new_status;
            if (waitpid(new_pid, &new_status, __WALL) == -1) {
                perror("waitpid on new_pid failed");
                exit(EXIT_FAILURE);
            }

            // If the new process has not exited, add it to the table and trace it.
            if (WIFSTOPPED(new_status)) {
                proc *new_proc = add_process(new_pid);
                if (live_procs > MAX_PROCESSES) {
                    new_proc->to_kill = 1;  // Addition exceeds maximum proc #.
                }
                if (ptrace(PTRACE_SYSCALL, new_pid, NULL, NULL) == -1) {
                    perror("ptrace SYSCALL on new_pid failed");
                    exit(EXIT_FAILURE);
                }
            }
        }

        // Handle syscall entry / syscall exit.
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            // Fetch process regs and ptr to proc.
            if (ptrace(PTRACE_GETREGS, event_pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS failed");
                exit(EXIT_FAILURE);
            }
            proc *proc_info = get_proc_ptr(event_pid);

            // Handle syscall entry:
            if (proc_info->is_entry) {
                // Expecting syscall exit next.
                proc_info->is_entry = 0;

                // If exceeds proc # limit, kill & remove it on its 1st syscall entry.
                if (proc_info->to_kill) {
                    kill(event_pid, SIGKILL);
                    remove_process(event_pid);
                    continue;
                }

                // Check if this is a connect() syscall
                if (regs.orig_rax == SYS_connect) {
                    // Block non-permitted connections.
                    if (!check_connect_addr(event_pid, regs.rsi)) {
                        proc_info->block_connect = 1;
                        regs.orig_rax = -1;  // Prevent the syscall
                        regs.rax = -EPERM;
                        if (ptrace(PTRACE_SETREGS, event_pid, NULL, &regs) == -1) {
                            perror("ptrace SETREGS failed");
                            exit(EXIT_FAILURE);
                        }
                    }
                }

            // Handle syscall exit:
            } else {
                // Expecting syscall entry next.
                proc_info->is_entry = 1;

                // If this was a blocked connect(), set error return value.
                if (proc_info->block_connect) {
                    regs.rax = -EPERM;  // Operation not permitted
                    if (ptrace(PTRACE_SETREGS, event_pid, NULL, &regs) == -1) {
                        perror("ptrace SETREGS failed");
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }

        // Continue running the traced process with PTRACE_SYSCALL.
        if (ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL) == -1) {
            perror("ptrace SYSCALL failed");
            exit(EXIT_FAILURE);
        }
    }
}


// ====================================== { MAIN } ======================================

int main(int argc, char *argv[]) {
    // Verify # of args.
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <guest_dir> <unprivileged_uid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Allocate stack for clone.
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("Failed to allocate stack");
        return EXIT_FAILURE;
    }

    // Create new process in a PID namespace.
    pid_t child_pid = clone(sandbox_child, stack + STACK_SIZE,
                            CLONE_NEWPID | SIGCHLD, argv);
    if (child_pid == -1) {
        perror("clone failed");
        free(stack);
        return EXIT_FAILURE;
    }

    // Sleep to ensure the child process is initialized.
    sleep(1);

    // Wait for the child process to complete (enter sandbox monitoring loop).
    monitor_guest(child_pid);

    // Free allocated stack upon successful child process completion.
    free(stack);
    return EXIT_SUCCESS;
}
