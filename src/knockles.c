#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "knockles_event.h"
#include "knockles.skel.h"
#define  HMAC_DURATION          30
#define  LISTENING_DURATION     30
static char  SECRET[] =           "MY_SECRET_KEY";
static int   SECRET_SIZE = sizeof(SECRET);

/****************************************************/
/*!
 *  \brief  Use to maintain state when the program
 *          is use in interactive mode
 */
static volatile sig_atomic_t exiting;

/****************************************************/
/*!
 *  \brief  Signal hanlder
 */
void sig_int(int signo){
    exiting = 1;
}

/****************************************************/
/*!
 *  \brief  Display LibBPF logs
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    return vfprintf(stderr, format, args);
}

/****************************************************/
/*!
 *  \brief  HMAC generation and comparison
 */
static uint16_t hmac_cmp(event_t *e){
    unsigned char clear[sizeof(uint64_t)], enc[16];
    unsigned int l_enc;
    uint64_t timestamp = time(NULL)/HMAC_DURATION;
    for(int i=0;i<sizeof(timestamp);i++){
        clear[i] = timestamp&0xFF;
        timestamp >>= 8;
    }
    
    HMAC(EVP_md5(), SECRET, SECRET_SIZE, clear, sizeof(clear), enc, &l_enc);
    
    unsigned char rcv[8];
    uint16_t id  = e->id;
    uint32_t seq = e->seq;
    uint16_t win = e->win;
    for(int i=0;i<sizeof(rcv);i++){
        if(i<2){
            rcv[i] = id&0xFF;
            id >>= 8;
        }
        else if(i<6){
            rcv[i] = seq&0xFF;
            seq >>= 8;
        }
        else{
            rcv[i] = win&0xFF;
            win >>= 8;
        }
    }
    if(memcmp((char *)enc, (char *)rcv, sizeof(rcv))) return 1;
    
    uint16_t port = (((uint16_t)(enc[9]))<<8)|enc[8];
    
    return port;
}

/****************************************************/
/*!
 *  \brief  Socket handler
 */
static int sock_handler(uint16_t port){
    int s, c;
    struct sockaddr_in serv, client;
    struct timeval timeout = {
        .tv_sec = LISTENING_DURATION
    };
    fd_set readfds;
    
    socklen_t l_client = sizeof(client);
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == -1) return 1;
    
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(port);
    
    if ((bind(s, (struct sockaddr *)&serv, sizeof(serv))) != 0) return 1;
    if ((listen(s, 1)) != 0) return 1;
    
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);
    
    if(!select(s+1, &readfds, 0, 0, &timeout)){
        close(s);
        return 1;
    }
    c = accept(s, (struct sockaddr *)&client, &l_client);
    close(s);
    if(c<0)return 1;
    
    return 0;
}

/****************************************************/
/*!
 *  \brief  Event handler, debugging mode
 */
static int handle_event_dbg(void *ctx, void *data, size_t data_sz){
    event_t *e = data;
    uint16_t port = hmac_cmp(e);
    
    printf("%-15u | %-15u | %-15u | ", (unsigned int)e->id, (unsigned int)e->seq, (unsigned int)e->win);
    
    if(port<=1024){
        printf("%-15s | %-15s | %-15s\n","FAIL","N/A","N/A");
        return 0;
    };
    
    printf("%-15s | %-15u | %-15s\n", "VALID", (unsigned int)port, "OPEN");
    
    if(sock_handler(port)){
        printf("%-15u | %-15u | %-15u | %-15s | %-15u | %-15s\n", (unsigned int)e->id, (unsigned int)e->seq, (unsigned int)e->win, "VALID", (unsigned int)port, "CLOSED");
    }
    else{
        printf("%-15u | %-15u | %-15u | %-15s | %-15u | %-15s\n", (unsigned int)e->id, (unsigned int)e->seq, (unsigned int)e->win, "VALID", (unsigned int)port, "CONNECTED");
    }
    
    return 0;
}

/****************************************************/
/*!
 *  \brief  Event handler
 */
static int handle_event(void *ctx, void *data, size_t data_sz){
    event_t *e = data;
    uint16_t port = hmac_cmp(e);
    
    if(port<=1024)return 0;
    if(sock_handler(port)) return 0;
    
    return 0;
}

/****************************************************/
/*!
 *  \brief  Continue the program as a daemon
 */
static void start_daemon(void){
    pid_t child = fork();
    if (child < 0) exit(child);
    if (child > 0) exit(0);
    
    setsid();
    
    child = fork();
    if (child < 0) exit(child);
    if (child > 0) exit(0);
    
    umask(0);
    
    close(0);
    close(1);
    close(2);
    
    int fd_0 = open("/dev/null", O_RDWR);
    if (fd_0 != 0) exit(1);
    int fd_1 = dup(fd_0);
    if (fd_1 != 1) exit(1);
    int fd_2 = dup(fd_0);
    if (fd_2 != 2) exit(1);
}

/****************************************************/
int main(int argc, char *argv[]){
    struct ring_buffer *rb = NULL;
    struct knockles_bpf *skel;
    int err;
    
    char dmn_flag[] = "--daemon";
    char hlp_flag[] = "--help";
    int dmn_mode    = 0;
    
    // Parse arguments
    if(argc>1){
        for(int i=1;i<argc;i++){
            if(strncmp(argv[i], dmn_flag, sizeof(dmn_flag)) == 0) dmn_mode = 1;
            if(strncmp(argv[i], hlp_flag, sizeof(hlp_flag)) == 0){
            printf("Usage: ./knockles [OPTION]...\n");
            printf("eBPF port knocking tool - Server.\n");
            printf("      --help             display this help and exit\n");
            printf("      --daemon           run program as daemon\n\n");
            exit(0);
            }
        }
    }
    
    if(!dmn_mode) libbpf_set_print(libbpf_print_fn);
    
    
    struct rlimit rlim = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
    
    // Open BPF application
    skel = knockles_bpf__open();
    if (!skel){
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }
    
    // Attach tracepoint handler
    err = knockles_bpf__load(skel);
    if (err){
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Attach tracepoint handler
    err = knockles_bpf__attach(skel);
    if (err){
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    
    // Set up ring buffer
    if(dmn_mode){
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    }
    else{
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_dbg, NULL, NULL);
    }
    if (!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    // Display user readable events
    if(!dmn_mode){
        printf("\n\e[1meBPF Port Knocking Tool.\e[0m\n\n");
        printf("%-15s | %-15s | %-15s | %-15s | %-15s | %-15s\n", "ID", "SEQ", "WIN", "HMAC", "PORT", "STATUS");
        printf("%-15s | %-15s | %-15s | %-15s | %-15s | %-15s\n", "-", "-", "-", "-", "-", "-");
    }
    if(dmn_mode){
        start_daemon();
    }
    
    while (!exiting){
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR){
            err = 0;
            break;
        }
        if (err < 0){
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
    
    cleanup:
    knockles_bpf__destroy(skel);
    return -err;
}
