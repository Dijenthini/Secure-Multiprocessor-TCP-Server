#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define PORT 50158
#define SID "1041"
#define BUFFER_SIZE 4096
#define MAX_PAYLOAD 4096
#define TOKEN_EXPIRY 300
#define MAX_LOGIN_ATTEMPTS 3
#define LOCKOUT_TIME 60
#define SALT_SIZE 16
#define TOKEN_SIZE 16
#define MAX_USERNAME 32
#define MAX_PASSWORD 64
#define MAX_REQUESTS_PER_MIN 10
#define COLOR_RESET "\033[0m"
#define COLOR_PINK "\033[38;5;206m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define DATA_PATH "/srv/ie2102/IT24104158"

typedef struct {
    char username[MAX_USERNAME];
    char salt[SALT_SIZE * 2 + 1];
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    int failed_attempts;
    time_t lockout_until;
} User;

typedef struct {
    char username[MAX_USERNAME];
    char token[TOKEN_SIZE * 2 + 1];
    time_t created;
    time_t last_active;
    int active;
} Session;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int request_count;
    time_t first_request;
    int limited;
} RateLimit;

FILE *log_fp = NULL;
User *users = NULL;
int user_count = 0;
Session *sessions = NULL;
int session_count = 0;
RateLimit *rate_limits = NULL;
int rate_limit_count = 0;

void log_write(const char *ip, int port, pid_t pid, const char *user, const char *cmd, const char *result) {
    time_t now = time(NULL);
    char ts[32];
    struct tm *tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(log_fp, "[%s] IP:%s:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            ts, ip, port, pid, user ? user : "-", cmd, result);
    fflush(log_fp);
}

void sigchld_handler(int sig) {
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

void make_dirs(const char *username) {
    char path[512];
    mkdir("/srv", 0755);
    mkdir("/srv/ie2102", 0755);
    mkdir("/srv/ie2102/IT24104158", 0755);
    snprintf(path, sizeof(path), "%s/%s", DATA_PATH, username);
    mkdir(path, 0755);
}

int valid_username(const char *u) {
    int len = strlen(u);
    if (len < 3 || len >= MAX_USERNAME) return 0;
    for (int i = 0; u[i]; i++) {
        if (!((u[i] >= 'a' && u[i] <= 'z') ||
              (u[i] >= 'A' && u[i] <= 'Z') ||
              (u[i] >= '0' && u[i] <= '9') || u[i] == '_'))
            return 0;
    }
    return 1;
}

void hash_pw(const char *pw, const char *salt, char *out) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", salt, pw);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined, strlen(combined), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out + i*2, "%02x", hash[i]);
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

void gen_salt(char *salt) {
    unsigned char raw[SALT_SIZE];
    RAND_bytes(raw, SALT_SIZE);
    for (int i = 0; i < SALT_SIZE; i++)
        sprintf(salt + i*2, "%02x", raw[i]);
    salt[SALT_SIZE * 2] = '\0';
}

void gen_token(char *token) {
    unsigned char raw[TOKEN_SIZE];
    RAND_bytes(raw, TOKEN_SIZE);
    for (int i = 0; i < TOKEN_SIZE; i++)
        sprintf(token + i*2, "%02x", raw[i]);
    token[TOKEN_SIZE * 2] = '\0';
}

void load_users() {
    FILE *fp = fopen("users.db", "rb");
    if (!fp) { user_count = 0; users = NULL; return; }
    fseek(fp, 0, SEEK_END);
    user_count = ftell(fp) / sizeof(User);
    rewind(fp);
    if (users) free(users);
    users = malloc(user_count * sizeof(User));
    fread(users, sizeof(User), user_count, fp);
    fclose(fp);
}

void save_users() {
    FILE *fp = fopen("users.db", "wb");
    if (!fp) return;
    fwrite(users, sizeof(User), user_count, fp);
    fclose(fp);
}

User* find_user(const char *u) {
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].username, u) == 0)
            return &users[i];
    return NULL;
}

int register_user(const char *u, const char *p) {
    if (!valid_username(u)) return -1;
    if (find_user(u)) return -2;
    users = realloc(users, (user_count + 1) * sizeof(User));
    User *new_u = &users[user_count];
    strcpy(new_u->username, u);
    gen_salt(new_u->salt);
    hash_pw(p, new_u->salt, new_u->hash);
    new_u->failed_attempts = 0;
    new_u->lockout_until = 0;
    user_count++;
    save_users();
    make_dirs(u);
    return 0;
}

Session* create_session(const char *u) {
    for (int i = 0; i < session_count; i++)
        if (sessions[i].active && strcmp(sessions[i].username, u) == 0)
            sessions[i].active = 0;
    sessions = realloc(sessions, (session_count + 1) * sizeof(Session));
    Session *s = &sessions[session_count];
    strcpy(s->username, u);
    gen_token(s->token);
    s->created = s->last_active = time(NULL);
    s->active = 1;
    session_count++;
    return s;
}

Session* find_session(const char *token) {
    time_t now = time(NULL);
    for (int i = 0; i < session_count; i++) {
        if (sessions[i].active && strcmp(sessions[i].token, token) == 0) {
            if (now - sessions[i].last_active > TOKEN_EXPIRY) {
                sessions[i].active = 0;
                return NULL;
            }
            sessions[i].last_active = now;
            return &sessions[i];
        }
    }
    return NULL;
}

int check_rate_limit(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            if (now - rate_limits[i].first_request > 60) {
                rate_limits[i].request_count = 0;
                rate_limits[i].first_request = now;
                rate_limits[i].limited = 0;
            }
            if (rate_limits[i].limited) return -1;
            rate_limits[i].request_count++;
            if (rate_limits[i].request_count > MAX_REQUESTS_PER_MIN) {
                rate_limits[i].limited = 1;
                return -1;
            }
            return 0;
        }
    }
    rate_limits = realloc(rate_limits, (rate_limit_count + 1) * sizeof(RateLimit));
    strcpy(rate_limits[rate_limit_count].ip, ip);
    rate_limits[rate_limit_count].request_count = 1;
    rate_limits[rate_limit_count].first_request = now;
    rate_limits[rate_limit_count].limited = 0;
    rate_limit_count++;
    return 0;
}

int read_frame(int fd, char *buf, size_t max) {
    char c;
    int pos = 0;
    while (pos < 15) {
        if (read(fd, &c, 1) <= 0) return -1;
        buf[pos++] = c;
        buf[pos] = '\0';
        if (strstr(buf, "LEN:")) break;
    }
    if (!strstr(buf, "LEN:")) return -1;
    int len = atoi(strstr(buf, "LEN:") + 4);
    if (len <= 0 || len > (int)max) return -2;
    if (read(fd, &c, 1) <= 0 || c != ' ') return -1;
    int total = 0;
    while (total < len) {
        int n = read(fd, buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    buf[len] = '\0';
    return len;
}

void send_resp(int fd, int ok, int code, const char *msg) {
    char resp[BUFFER_SIZE];
    snprintf(resp, sizeof(resp), "%s %d SID:%s %s\r\n",
             ok ? "OK" : "ERR", code, SID, msg);
    write(fd, resp, strlen(resp));
}

void handle_client(int fd, struct sockaddr_in *addr) {
    char buf[BUFFER_SIZE];
    char ip[INET_ADDRSTRLEN];
    int port = ntohs(addr->sin_port);
    pid_t pid = getpid();
    Session *sess = NULL;
    
    inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
    
    if (check_rate_limit(ip) < 0) {
        send_resp(fd, 0, 429, "Rate limit exceeded. Try later.");
        log_write(ip, port, pid, "-", "CONNECT", "RATE_LIMITED");
        close(fd);
        exit(0);
    }
    
    printf(COLOR_PINK "[%d] Connected: %s:%d\n" COLOR_RESET, pid, ip, port);
    
    while (1) {
        memset(buf, 0, sizeof(buf));
        int n = read_frame(fd, buf, MAX_PAYLOAD);
        if (n <= 0) {
            if (n == 0) printf("[%d] Disconnected\n", pid);
            break;
        }
        buf[strcspn(buf, "\r\n")] = '\0';
        printf("[%d] Received: %s\n", pid, buf);
        
        char cmd[BUFFER_SIZE], a1[BUFFER_SIZE], a2[BUFFER_SIZE];
        int args = sscanf(buf, "%s %s %s", cmd, a1, a2);
        
        if (strcmp(cmd, "REGISTER") == 0 && args == 3) {
            int r = register_user(a1, a2);
            if (r == 0) {
                send_resp(fd, 1, 200, "Registration successful");
                log_write(ip, port, pid, a1, "REGISTER", "SUCCESS");
            } else if (r == -1) {
                send_resp(fd, 0, 400, "Invalid username format");
                log_write(ip, port, pid, a1, "REGISTER", "INVALID_USERNAME");
            } else {
                send_resp(fd, 0, 409, "Username already exists");
                log_write(ip, port, pid, a1, "REGISTER", "EXISTS");
            }
        }
        else if (strcmp(cmd, "LOGIN") == 0 && args == 3) {
            load_users();
            User *u = find_user(a1);
            if (!u) {
                send_resp(fd, 0, 401, "Invalid credentials");
                log_write(ip, port, pid, a1, "LOGIN", "USER_NOT_FOUND");
                continue;
            }
            if (u->lockout_until > time(NULL)) {
                send_resp(fd, 0, 423, "Account locked - try later");
                log_write(ip, port, pid, a1, "LOGIN", "LOCKED");
                continue;
            }
            char hash[SHA256_DIGEST_LENGTH * 2 + 1];
            hash_pw(a2, u->salt, hash);
            if (strcmp(hash, u->hash) == 0) {
                u->failed_attempts = 0;
                u->lockout_until = 0;
                save_users();
                sess = create_session(a1);
                char msg[BUFFER_SIZE];
                snprintf(msg, sizeof(msg), "Login successful. Token: %s", sess->token);
                send_resp(fd, 1, 200, msg);
                log_write(ip, port, pid, a1, "LOGIN", "SUCCESS");
            } else {
                u->failed_attempts++;
                if (u->failed_attempts >= MAX_LOGIN_ATTEMPTS)
                    u->lockout_until = time(NULL) + LOCKOUT_TIME;
                save_users();
                send_resp(fd, 0, 401, "Invalid credentials");
                log_write(ip, port, pid, a1, "LOGIN", "FAILED");
            }
        }
        else if (strcmp(cmd, "LOGOUT") == 0) {
            if (sess) {
                sess->active = 0;
                log_write(ip, port, pid, sess->username, "LOGOUT", "SUCCESS");
                sess = NULL;
            }
            send_resp(fd, 1, 200, "Logged out");
            break;
        }
        else {
            char *tok = strstr(buf, "TOKEN:");
            if (tok) {
                char token[TOKEN_SIZE * 2 + 1];
                sscanf(tok, "TOKEN:%s", token);
                Session *s = find_session(token);
                if (!s) {
                    send_resp(fd, 0, 401, "Invalid or expired token");
                    continue;
                }
                sess = s;
                send_resp(fd, 0, 400, "Unknown command");
                log_write(ip, port, pid, sess->username, buf, "UNKNOWN");
            } else {
                send_resp(fd, 0, 400, "Missing token for protected command");
            }
        }
    }
    close(fd);
    exit(0);
}

int main() {
    int srv_fd, cli_fd;
    struct sockaddr_in srv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    
    RAND_poll();
    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);
    
    log_fp = fopen("server_IT24104158.log", "a");
    if (!log_fp) { perror("log"); return 1; }
    
    load_users();
    
    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }
    
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port = htons(PORT);
    
    if (bind(srv_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind"); return 1;
    }
    
    if (listen(srv_fd, 10) < 0) {
        perror("listen"); return 1;
    }
    
    printf(COLOR_PINK "=== IE2102 Assignment Server ===\n" COLOR_RESET);
    printf("Student: IT24104158\nPort: %d\nSID: %s\nPID: %d\n", PORT, SID, getpid());
    printf(COLOR_PINK "================================\n" COLOR_RESET);
    
    log_write("0.0.0.0", PORT, getpid(), "SYSTEM", "START", "SUCCESS");
    
    while (1) {
        cli_fd = accept(srv_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(cli_fd);
            continue;
        }
        if (pid == 0) {
            close(srv_fd);
            handle_client(cli_fd, &cli_addr);
            exit(0);
        } else {
            close(cli_fd);
            printf(COLOR_GREEN "[PARENT] Spawned child PID=%d\n" COLOR_RESET, pid);
        }
    }
    fclose(log_fp);
    return 0;
}