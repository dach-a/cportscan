#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

// ANSI color codes (fixed escape sequences)
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define BLUE "\x1b[34m"
#define RESET "\x1b[0m"

// Function prototypes (to fix implicit declaration warnings)
void scan_port_range(const char* hostname, int start_port, int end_port);
int resolve_hostname(const char* hostname, struct sockaddr_in* sa);
void display_results(int open_count, int total_ports, double scan_time);

int main(int argc, char **argv) {
    char hostname[100];
    int start, end;

    printf(BLUE "=== SIMPLE PORT SCANNER ===\n" RESET);
    printf("Enter the hostname or IP address to scan: ");
    fgets(hostname, sizeof(hostname), stdin);
    hostname[strcspn(hostname, "\n")] = 0;
    printf("Enter the start port: ");
    scanf("%d", &start);
    printf("Enter the end port: ");
    scanf("%d", &end);

    scan_port_range(hostname, start, end);
    return 0;
}

void scan_port_range(const char* hostname, int start_port, int end_port) {
    struct sockaddr_in sa;
    int sock, i;
    int open_count = 0;
    clock_t begin, end_time;
    double scan_time;
    struct timeval timeout;

    begin = clock();

    if(!resolve_hostname(hostname, &sa)) {
        fprintf(stderr, RED "Error: Unable to resolve hostname %s\n" RESET, hostname);
        exit(2);
    }
    printf(BLUE "\nScanning %s from port %d to %d...\n\n" RESET, hostname, start_port, end_port);

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 0.1 seconds timeout

    for(i = start_port; i <= end_port; i++) {
        printf("Scanning port %d...", i);
        fflush(stdout);

        sa.sin_port = htons(i);
        if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation failed");
            continue;
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        if(connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            printf("\r" GREEN "Port %5d is open        \n" RESET, i);
            open_count++;
        } else {
            printf("\r%79s\r", ""); // Clear line
        }
        close(sock);
    }
    
    end_time = clock();
    scan_time = (double)(end_time - begin) / CLOCKS_PER_SEC;
    display_results(open_count, end_port - start_port + 1, scan_time);
}

int resolve_hostname(const char* hostname, struct sockaddr_in* sa) {
    struct hostent *host;
    memset(sa, 0, sizeof(struct sockaddr_in));
    sa->sin_family = AF_INET;

    // Check if input is IP address
    if(inet_pton(AF_INET, hostname, &sa->sin_addr) == 1) {
        return 1;
    }
    
    // Resolve hostname
    if((host = gethostbyname(hostname)) != NULL) {
        memcpy(&sa->sin_addr, host->h_addr_list[0], host->h_length);
        return 1;
    }
    
    return 0;
}

void display_results(int open_count, int total_ports, double scan_time) {
    printf(BLUE "\nScan completed in %.2f seconds!\n" RESET, scan_time);
    printf("Result: " GREEN "%d/%d ports open" RESET " | " RED "%d closed" RESET " ports found\n",
           open_count, total_ports, total_ports - open_count);
}
