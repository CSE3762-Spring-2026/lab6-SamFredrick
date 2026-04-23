#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cjson/cJSON.h>

#define BUFFER_SIZE 65536
#define MAXPEERS 100

// struct to hold info about each file
typedef struct FileInfo {
    char filename[100];
    long long fileSize;
    char fullFileHash[65];
    int numberOfChunks;
    char clientIP[MAXPEERS][INET_ADDRSTRLEN];
    int clientPort[MAXPEERS];
    int numberOfPeers;
    struct FileInfo *next;
} FileInfo;

// head of our linked list
static FileInfo *file_list_head = NULL;

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// search for a file using its hash
static FileInfo *find_file_by_hash(const char *hash) {
    FileInfo *curr = file_list_head;
    while (curr != NULL) {
        if (strcmp(curr->fullFileHash, hash) == 0) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

// check if we already have this peer for this file
static int peer_exists(const FileInfo *file, const char *ip, int port) {
    for (int i = 0; i < file->numberOfPeers; i++) {
        if (strcmp(file->clientIP[i], ip) == 0 &&
            file->clientPort[i] == port) {
            return 1;
        }
    }
    return 0;
}

// create a new file entry
static FileInfo *create_file_node(const char *filename,
                                  long long fileSize,
                                  const char *hash,
                                  int numberOfChunks) {
    FileInfo *node = malloc(sizeof(FileInfo));
    if (!node) die("malloc");

    memset(node, 0, sizeof(FileInfo));
    strncpy(node->filename, filename, sizeof(node->filename) - 1);
    node->fileSize = fileSize;
    strncpy(node->fullFileHash, hash, sizeof(node->fullFileHash) - 1);
    node->numberOfChunks = numberOfChunks;
    node->numberOfPeers = 0;
    node->next = NULL;

    return node;
}

// add file to the end of the list
static void append_file_node(FileInfo *node) {
    if (file_list_head == NULL) {
        file_list_head = node;
        return;
    }

    // walk to the end of the list
    FileInfo *curr = file_list_head;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = node;
}

// add a peer to a file's peer list
static void add_peer_to_file(FileInfo *file, const char *ip, int port) {
    // don't add duplicates
    if (peer_exists(file, ip, port)) {
        return;
    }

    if (file->numberOfPeers >= MAXPEERS) {
        fprintf(stderr, "Maximum peers reached for file %s\n", file->filename);
        return;
    }

    strncpy(file->clientIP[file->numberOfPeers], ip, INET_ADDRSTRLEN - 1);
    file->clientIP[file->numberOfPeers][INET_ADDRSTRLEN - 1] = '\0';
    file->clientPort[file->numberOfPeers] = port;
    file->numberOfPeers++;
}

// register a file - either create new or add peer to existing
static void register_file(const char *filename,
                          long long fileSize,
                          const char *hash,
                          int numberOfChunks,
                          const char *client_ip,
                          int client_port) {
    FileInfo *file = find_file_by_hash(hash);

    if (file == NULL) {
        // new file, haven't seen it before
        file = create_file_node(filename, fileSize, hash, numberOfChunks);
        append_file_node(file);
    }

    add_peer_to_file(file, client_ip, client_port);
}

// print out all the files we're storing
static void print_stored_files(void) {
    printf("Stored File Information:\n");

    FileInfo *curr = file_list_head;
    while (curr != NULL) {
        printf("Filename: %s, Full Hash: %s\n", curr->filename, curr->fullFileHash);
        for (int i = 0; i < curr->numberOfPeers; i++) {
            printf("Client IP: %s, Client Port: %d\n",
                   curr->clientIP[i], curr->clientPort[i]);
        }
        curr = curr->next;
    }
    printf("**********\n");
}

// handle one JSON object and register it
static void register_one_json_object(const cJSON *obj,
                                     const char *sender_ip,
                                     int sender_port) {
    const cJSON *filename = cJSON_GetObjectItemCaseSensitive(obj, "filename");
    const cJSON *fileSize = cJSON_GetObjectItemCaseSensitive(obj, "fileSize");
    const cJSON *fullFileHash = cJSON_GetObjectItemCaseSensitive(obj, "fullFileHash");
    const cJSON *numberOfChunks = cJSON_GetObjectItemCaseSensitive(obj, "numberOfChunks");

    // make sure all fields are there
    if (!cJSON_IsString(filename) || filename->valuestring == NULL ||
        !cJSON_IsNumber(fileSize) ||
        !cJSON_IsString(fullFileHash) || fullFileHash->valuestring == NULL ||
        !cJSON_IsNumber(numberOfChunks)) {
        fprintf(stderr, "Missing required JSON fields.\n");
        return;
    }

    register_file(filename->valuestring,
                  (long long)fileSize->valuedouble,
                  fullFileHash->valuestring,
                  (int)numberOfChunks->valuedouble,
                  sender_ip,
                  sender_port);
}

// process the registration data from JSON
static void handle_registration_payload(const cJSON *root,
                                        const char *sender_ip,
                                        int sender_port) {
    if (cJSON_IsObject(root)) {
        // single file object
        register_one_json_object(root, sender_ip, sender_port);
    } else if (cJSON_IsArray(root)) {
        // array of multiple files
        int count = cJSON_GetArraySize(root);
        for (int i = 0; i < count; i++) {
            cJSON *obj = cJSON_GetArrayItem(root, i);
            if (cJSON_IsObject(obj)) {
                register_one_json_object(obj, sender_ip, sender_port);
            }
        }
    } else {
        fprintf(stderr, "JSON was not an object or array.\n");
        return;
    }

    print_stored_files();
}

// send back a list of all our files when client asks
static void send_query_response(int sock, const struct sockaddr_in *dest) {
    cJSON *root = cJSON_CreateObject();
    if (!root) die("cJSON_CreateObject");

    cJSON_AddStringToObject(root, "requestType", "queryResponse");
    cJSON *files = cJSON_AddArrayToObject(root, "files");
    if (!files) die("cJSON_AddArrayToObject");

    // go through all files and add them to the array
    FileInfo *curr = file_list_head;
    while (curr != NULL) {
        cJSON *fileObj = cJSON_CreateObject();
        if (!fileObj) die("cJSON_CreateObject");

        cJSON_AddStringToObject(fileObj, "filename", curr->filename);
        cJSON_AddNumberToObject(fileObj, "fileSize", (double)curr->fileSize);
        cJSON_AddStringToObject(fileObj, "fullFileHash", curr->fullFileHash);
        cJSON_AddItemToArray(files, fileObj);

        curr = curr->next;
    }

    char *json_text = cJSON_PrintUnformatted(root);
    if (!json_text) die("cJSON_PrintUnformatted");

    ssize_t sent = sendto(sock, json_text, strlen(json_text), 0,
                          (const struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) die("sendto");

    free(json_text);
    cJSON_Delete(root);
}

// figure out what kind of message we got and handle it
static void handle_message(int sock,
                           const char *buffer,
                           const char *sender_ip,
                           int sender_port,
                           const struct sockaddr_in *sender_addr) {
    cJSON *root = cJSON_Parse(buffer);
    if (!root) {
        fprintf(stderr, "Invalid JSON received.\n");
        return;
    }

    cJSON *requestType = NULL;
    if (cJSON_IsObject(root)) {
        requestType = cJSON_GetObjectItemCaseSensitive(root, "requestType");
    }

    // check if it's a query request
    if (cJSON_IsObject(root) &&
        cJSON_IsString(requestType) &&
        requestType->valuestring != NULL &&
        strcmp(requestType->valuestring, "query") == 0) {
        send_query_response(sock, sender_addr);
        cJSON_Delete(root);
        return;
    }

    // check if it's a register request
    if (cJSON_IsObject(root) &&
        cJSON_IsString(requestType) &&
        requestType->valuestring != NULL &&
        strcmp(requestType->valuestring, "register") == 0) {
        register_one_json_object(root, sender_ip, sender_port);
        print_stored_files();
        cJSON_Delete(root);
        return;
    }

    // otherwise treat it as registration data
    handle_registration_payload(root, sender_ip, sender_port);
    cJSON_Delete(root);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <multicast_ip> <port>\n", argv[0]);
        fprintf(stderr, "Example: %s 239.0.0.1 5000\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *multicast_ip = argv[1];
    int port = atoi(argv[2]);

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    // create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) die("socket");

    // let multiple servers use the same port
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        die("setsockopt(SO_REUSEADDR)");

#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
        die("setsockopt(SO_REUSEPORT)");
#endif

    // set up address structure
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind");

    // join the multicast group
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));

    if (inet_pton(AF_INET, multicast_ip, &mreq.imr_multiaddr) != 1) {
        fprintf(stderr, "Bad multicast address: %s\n", multicast_ip);
        close(sock);
        return EXIT_FAILURE;
    }

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        die("setsockopt(IP_ADD_MEMBERSHIP)");

    printf("Server listening on multicast %s:%d\n\n", multicast_ip, port);

    // main loop - keep receiving messages
    for (;;) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);

        ssize_t nbytes = recvfrom(sock, buffer, sizeof(buffer) - 1,
                                  0, (struct sockaddr *)&sender, &slen);
        if (nbytes < 0) die("recvfrom");

        buffer[nbytes] = '\0';

        // convert sender IP to string
        char sender_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sender.sin_addr, sender_ip, sizeof(sender_ip)) == NULL) {
            perror("inet_ntop");
            continue;
        }

        int sender_port = ntohs(sender.sin_port);

        handle_message(sock, buffer, sender_ip, sender_port, &sender);
        fflush(stdout);
    }

    close(sock);
    return EXIT_SUCCESS;
}