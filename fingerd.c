#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <netdb.h>
#include <utmp.h>
#include <ctype.h>
#include <limits.h>
#include <sys/time.h>
#include <grp.h>
#include <paths.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>

#define MAX_QUERY 256
#define MAX_PATH 1024
#define TIMEOUT_SECONDS 30
#define MAX_CONNECTIONS 100
#define MAX_USERNAMES 10
#define UNPRIVILEGED_USER "nobody"

volatile sig_atomic_t running = 1;
volatile sig_atomic_t child_count = 0;

void sig_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        running = 0;
        sd_journal_print(LOG_INFO, "Received termination signal %d, shutting down", signo);
    } else if (signo == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
            if (child_count > 0) child_count--;
        }
    }
}

int validate_path(const char *path, const char *homedir) {
    // String-based check for bad sequences
    if (strstr(path, "..") || strstr(path, "/./") || strstr(path, "//") || strstr(path, "/../")) {
        return 0;
    }
    // Check prefix
    size_t len = strlen(homedir);
    if (strncmp(path, homedir, len) != 0 || (path[len] != '/' && path[len] != '\0')) {
        return 0;
    }
    return 1;
}

int validate_username(const char *username) {
    size_t len = strlen(username);
    if (len == 0 || len > 32) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(username[i]) && username[i] != '_' && username[i] != '-') {
            return 0;
        }
    }
    return 1;
}

void sanitize_output(const char *input, char *output, size_t outlen) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < outlen - 1; i++) {
        if (isprint((unsigned char)input[i]) && input[i] != '\r' && input[i] != '\n') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

void process_query(char *query, FILE *out, int verbose) {
    char *username = query;
    while (*username == ' ' || *username == '\t') username++;
    char *end = username + strlen(username) - 1;
    while (end >= username && (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t')) {
        *end-- = '\0';
    }

    if (*username == '\0') {
        FILE *utmp_file = fopen(_PATH_UTMP, "r");
        if (!utmp_file) {
            fprintf(out, "Error accessing user database\r\n");
            if (fflush(out) != 0) {
                sd_journal_print(LOG_ERR, "fflush failed: %s", strerror(errno));
            }
            return;
        }
        struct utmp ut;
        fprintf(out, "Login\tTTY\tWhen\tHost\r\n");
        while (fread(&ut, sizeof(ut), 1, utmp_file)) {
            if (ut.ut_type == USER_PROCESS && ut.ut_user[0] != '\0') {
                time_t t;
#ifdef __linux__
                t = ut.ut_tv.tv_sec;
#else
                t = ut.ut_time;
#endif
                char *tstr = ctime(&t);
                char time_buf[32];
                if (tstr) {
                    strncpy(time_buf, tstr, sizeof(time_buf) - 1);
                    time_buf[sizeof(time_buf) - 1] = '\0';
                    time_buf[strcspn(time_buf, "\n")] = '\0';
                } else {
                    strcpy(time_buf, "unknown");
                }
                char clean_user[UT_NAMESIZE + 1], clean_line[UT_LINESIZE + 1], clean_host[UT_HOSTSIZE + 1];
                sanitize_output(ut.ut_user, clean_user, sizeof(clean_user));
                sanitize_output(ut.ut_line, clean_line, sizeof(clean_line));
                sanitize_output(ut.ut_host, clean_host, sizeof(clean_host));
                fprintf(out, "%s\t%s\t%s\t%s\r\n", clean_user, clean_line, time_buf, clean_host);
            }
        }
        if (fclose(utmp_file) != 0) {
            sd_journal_print(LOG_ERR, "Failed to close utmp file: %s", strerror(errno));
        }
        if (fflush(out) != 0) {
            sd_journal_print(LOG_ERR, "fflush failed: %s", strerror(errno));
        }
        return;
    }

    // Create a copy of the query for tokenization
    char query_copy[MAX_QUERY];
    strncpy(query_copy, username, sizeof(query_copy) - 1);
    query_copy[sizeof(query_copy) - 1] = '\0';

    // Tokenize query for multi-user support with a limit
    char *token = strtok(query_copy, " \t");
    int user_count = 0;
    int first_user = 1;
    while (token && user_count < MAX_USERNAMES) {
        if (strlen(token) == 0) {
            token = strtok(NULL, " \t");
            continue; // Skip empty tokens
        }
        if (!first_user) {
            fprintf(out, "\r\n"); // Separate multiple user outputs
        }
        first_user = 0;
        user_count++;

        if (!validate_username(token)) {
            fprintf(out, "No such user: %s\r\n", token);
        } else {
            struct passwd *pw = getpwnam(token);
            if (pw == NULL) {
                fprintf(out, "No such user: %s\r\n", token);
            } else {
                char gecos_buf[256];
                sanitize_output(pw->pw_gecos, gecos_buf, sizeof(gecos_buf));
                fprintf(out, "Login: %s\t\t\tName: %s\r\n", pw->pw_name, gecos_buf);
                fprintf(out, "Directory: %s\t\t\tShell: %s\r\n", pw->pw_dir, pw->pw_shell);

                if (verbose) {
                    char projectpath[MAX_PATH];
                    if (snprintf(projectpath, sizeof(projectpath), "%s/.project", pw->pw_dir) >= sizeof(projectpath)) {
                        fprintf(out, "\r\nProject: Path too long\r\n");
                    } else if (!validate_path(projectpath, pw->pw_dir)) {
                        fprintf(out, "\r\nProject: Invalid path\r\n");
                    } else {
                        struct stat st;
                        if (stat(projectpath, &st) == 0 && S_ISREG(st.st_mode)) {
                            FILE *project = fopen(projectpath, "r");
                            if (project) {
                                char buf[1024];
                                fprintf(out, "\r\nProject:\r\n");
                                while (fgets(buf, sizeof(buf), project)) {
                                    char clean_buf[1024];
                                    sanitize_output(buf, clean_buf, sizeof(clean_buf));
                                    fprintf(out, "%s\r\n", clean_buf);
                                }
                                if (fclose(project) != 0) {
                                    sd_journal_print(LOG_ERR, "Failed to close .project: %s", strerror(errno));
                               }
                            } else {
                                fprintf(out, "\r\nProject: (exists but cannot read: %s)\r\n", strerror(errno));
                            }
                        } else {
                            fprintf(out, "\r\nNo Project.\r\n");
                        }
                    }

                    char planpath[MAX_PATH];
                    if (snprintf(planpath, sizeof(planpath), "%s/.plan", pw->pw_dir) >= sizeof(planpath)) {
                        fprintf(out, "\r\nPlan: Path too long\r\n");
                    } else if (!validate_path(planpath, pw->pw_dir)) {
                        fprintf(out, "\r\nPlan: Invalid path\r\n");
                    } else {
                        struct stat st;
                        if (stat(planpath, &st) == 0 && S_ISREG(st.st_mode)) {
                            FILE *plan = fopen(planpath, "r");
                            if (plan) {
                                char buf[1024];
                                fprintf(out, "\r\nPlan:\r\n");
                                while (fgets(buf, sizeof(buf), plan)) {
                                    char clean_buf[1024];
                                    sanitize_output(buf, clean_buf, sizeof(clean_buf));
                                    fprintf(out, "%s\r\n", clean_buf);
                                }
                                if (fclose(plan) != 0) {
                                    sd_journal_print(LOG_ERR, "Failed to close .plan: %s", strerror(errno));
                                }
                            } else {
                                fprintf(out, "\r\nPlan: (exists but cannot read: %s)\r\n", strerror(errno));
                            }
                        } else {
                            fprintf(out, "\r\nNo Plan.\r\n");
                        }
                    }
                }
            }
        }
        token = strtok(NULL, " \t");
    }
    if (token) {
        fprintf(out, "\r\nError: Too many usernames (max %d)\r\n", MAX_USERNAMES);
    }
    if (fflush(out) != 0) {
        sd_journal_print(LOG_ERR, "fflush failed: %s", strerror(errno));
    }
}

void drop_privileges() {
    struct passwd *nobody = getpwnam(UNPRIVILEGED_USER);
    if (nobody == NULL) {
        sd_journal_print(LOG_ERR, "Cannot find user '%s'", UNPRIVILEGED_USER);
        exit(1);
    }
    if (setgroups(0, NULL) < 0) {
        sd_journal_print(LOG_ERR, "setgroups failed: %s", strerror(errno));
        exit(1);
    }
    if (setgid(nobody->pw_gid) < 0 || setuid(nobody->pw_uid) < 0) {
        sd_journal_print(LOG_ERR, "drop_privileges failed: %s", strerror(errno));
        exit(1);
    }
    
    // Verify we can't regain root privileges
    if (setuid(0) == 0) {
        sd_journal_print(LOG_ERR, "Failed to drop privileges permanently");
        exit(1);
    }
}

void log_request(const char *client_ip, const char *query, int verbose) {
    char clean_query[256];
    sanitize_output(query, clean_query, sizeof(clean_query));
    sd_journal_print(LOG_INFO, "Request from %s: %s%s", 
                     client_ip, verbose ? "/W " : "", clean_query);
}

int get_systemd_socket() {
    int n = sd_listen_fds(0);
    if (n < 0) {
        sd_journal_print(LOG_ERR, "sd_listen_fds failed: %s", strerror(-n));
        return -1;
    }
    if (n == 0) {
        sd_journal_print(LOG_INFO, "No systemd sockets received, creating our own");
        return -1;  // Will create our own socket
    }
    if (n > 1) {
        sd_journal_print(LOG_WARNING, "More than one socket received from systemd, using first");
    }
    
    int fd = SD_LISTEN_FDS_START;
    if (sd_is_socket_inet(fd, AF_UNSPEC, SOCK_STREAM, 1, 79) > 0) {
        sd_journal_print(LOG_INFO, "Using systemd socket activation");
        return fd;
    }
    
    sd_journal_print(LOG_ERR, "Systemd socket is not a TCP socket on port 79");
    return -1;
}

int create_socket() {
    int server_sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_sock < 0) {
        sd_journal_print(LOG_ERR, "socket failed: %s", strerror(errno));
        return -1;
    }

    int on = 0;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(79);
    addr.sin6_addr = in6addr_any;

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        sd_journal_print(LOG_ERR, "setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sd_journal_print(LOG_ERR, "bind failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        sd_journal_print(LOG_ERR, "listen failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    return server_sock;
}

void handle_client(int client_sock, struct sockaddr_in6 *client_addr) {
    char client_ip[INET6_ADDRSTRLEN];
    const void *ipaddr = &client_addr->sin6_addr;
    int family = AF_INET6;
    if (IN6_IS_ADDR_V4MAPPED(&client_addr->sin6_addr)) {
        family = AF_INET;
        ipaddr = &client_addr->sin6_addr.s6_addr[12];
    }
    if (inet_ntop(family, ipaddr, client_ip, sizeof(client_ip)) == NULL) {
        strcpy(client_ip, "unknown");
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    FILE *fp = fdopen(client_sock, "r+");
    if (fp == NULL) {
        sd_journal_print(LOG_ERR, "fdopen failed: %s", strerror(errno));
        close(client_sock);
        return;
    }

    char buf[MAX_QUERY];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        if (ferror(fp)) {
            sd_journal_print(LOG_ERR, "fgets failed: %s", strerror(errno));
        } else {
            sd_journal_print(LOG_DEBUG, "Connection closed by %s", client_ip);
        }
    } else if (strlen(buf) == sizeof(buf) - 1 && buf[sizeof(buf) - 2] != '\n') {
        sd_journal_print(LOG_WARNING, "Input too long from %s", client_ip);
        fprintf(fp, "Error: Input too long\r\n");
    } else {
        char *q = buf;
        while (isspace((unsigned char)*q)) q++;

        int verbose = 0;
        if (q[0] == '/' && tolower((unsigned char)q[1]) == 'w' && isspace((unsigned char)q[2])) {
            verbose = 1;
            q += 2;
            while (isspace((unsigned char)*q)) q++;
        }

        char query[MAX_QUERY];
        strncpy(query, q, sizeof(query) - 1);
        query[sizeof(query) - 1] = '\0';

        char *end = query + strlen(query) - 1;
        while (end >= query && (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        process_query(query, fp, verbose);
        log_request(client_ip, query, verbose);
    }

    if (fflush(fp) != 0) {
        sd_journal_print(LOG_ERR, "fflush failed: %s", strerror(errno));
    }
    if (fclose(fp) != 0) {
        sd_journal_print(LOG_ERR, "fclose failed: %s", strerror(errno));
    }
}

int main() {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGCHLD, sig_handler);

    sd_journal_print(LOG_INFO, "fingerd starting up");

    // Try to get socket from systemd first
    int server_sock = get_systemd_socket();
    if (server_sock < 0) {
        server_sock = create_socket();
        if (server_sock < 0) {
            exit(1);
        }
    }

    drop_privileges();

    // Notify systemd that we're ready
    sd_notify(0, "READY=1\nSTATUS=Ready to accept connections");

    while (running) {
        if (child_count >= MAX_CONNECTIONS) {
            sd_journal_print(LOG_WARNING, "Max connections reached, waiting...");
            sleep(1);
            continue;
        }

        struct sockaddr_in6 client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept4(server_sock, (struct sockaddr *)&client_addr, &len, SOCK_CLOEXEC);
        if (client_sock < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            sd_journal_print(LOG_ERR, "accept failed: %s", strerror(errno));
            continue;
        }

        // Update systemd with current status
        sd_notifyf(0, "STATUS=Active connections: %d", (int)child_count + 1);

        pid_t pid = fork();
        if (pid < 0) {
            sd_journal_print(LOG_ERR, "fork failed: %s", strerror(errno));
            close(client_sock);
            continue;
        }

        if (pid == 0) {
            // Child process
            close(server_sock);
            handle_client(client_sock, &client_addr);
            exit(0);
        } else {
            // Parent process
            child_count++;
            close(client_sock);
        }
    }

    // Graceful shutdown
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
    sd_journal_print(LOG_INFO, "Waiting for %d child processes to finish", (int)child_count);
    
    while (child_count > 0) {
        sleep(1);
    }
    
    close(server_sock);
    sd_journal_print(LOG_INFO, "fingerd shutdown complete");
    return 0;
}