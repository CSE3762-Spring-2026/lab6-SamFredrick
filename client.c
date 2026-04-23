#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <cjson/cJSON.h>

// max UDP packet size
#define MAX_JSON_SIZE 65507
// 500KB chunks
#define CHUNK_SIZE (500u * 1024u)
// wait 2 seconds for responses
#define RESPONSE_TIMEOUT_SEC 2

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// don't process . or .. directories
static int is_dot_entry(const char *name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

// dynamic array for strings
typedef struct {
    char **items;
    size_t len;
    size_t cap;
} str_list;

// struct to hold file info from query responses
typedef struct {
    char filename[256];
    long long fileSize;
    char fullFileHash[65];
} QueryFile;

// dynamic array for query results
typedef struct {
    QueryFile *items;
    size_t len;
    size_t cap;
} QueryFileList;

static void str_list_init(str_list *l) {
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

// add string to list
static void str_list_push(str_list *l, const char *s) {
    if (l->len == l->cap) {
        size_t newcap = (l->cap == 0) ? 8 : l->cap * 2;
        char **tmp = realloc(l->items, newcap * sizeof(char *));
        if (!tmp) die("realloc");
        l->items = tmp;
        l->cap = newcap;
    }

    l->items[l->len] = strdup(s);
    if (!l->items[l->len]) die("strdup");
    l->len++;
}

// cleanup string list
static void str_list_free(str_list *l) {
    for (size_t i = 0; i < l->len; i++) {
        free(l->items[i]);
    }
    free(l->items);
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

static void query_file_list_init(QueryFileList *l) {
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

// check if we already have this file in our results
static int query_file_exists(const QueryFileList *l, const char *hash) {
    for (size_t i = 0; i < l->len; i++) {
        if (strcmp(l->items[i].fullFileHash, hash) == 0) {
            return 1;
        }
    }
    return 0;
}

// add file to results if we don't already have it
static void query_file_list_push_unique(QueryFileList *l,
                                        const char *filename,
                                        long long fileSize,
                                        const char *fullFileHash) {
    if (query_file_exists(l, fullFileHash)) {
        return;
    }

    if (l->len == l->cap) {
        size_t newcap = (l->cap == 0) ? 8 : l->cap * 2;
        QueryFile *tmp = realloc(l->items, newcap * sizeof(QueryFile));
        if (!tmp) die("realloc");
        l->items = tmp;
        l->cap = newcap;
    }

    memset(&l->items[l->len], 0, sizeof(QueryFile));
    strncpy(l->items[l->len].filename, filename, sizeof(l->items[l->len].filename) - 1);
    l->items[l->len].fileSize = fileSize;
    strncpy(l->items[l->len].fullFileHash, fullFileHash, sizeof(l->items[l->len].fullFileHash) - 1);
    l->len++;
}

// free the query results list
static void query_file_list_free(QueryFileList *l) {
    free(l->items);
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

// convert hash bytes to hex string
static void digest_to_hex(const unsigned char *digest, unsigned int dlen, char out[65]) {
    static const char *hex_chars = "0123456789abcdef";

    if (dlen != 32) {
        fprintf(stderr, "unexpected SHA-256 length: %u\n", dlen);
        exit(EXIT_FAILURE);
    }

    for (unsigned int i = 0; i < dlen; i++) {
        out[i * 2] = hex_chars[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[digest[i] & 0xF];
    }
    out[64] = '\0';
}

// hash data and return hex string
static void sha256_hex(const unsigned char *data, size_t n, char out[65]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("EVP_MD_CTX_new");

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hlen = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) die("EVP_DigestInit_ex");
    if (EVP_DigestUpdate(ctx, data, n) != 1) die("EVP_DigestUpdate");
    if (EVP_DigestFinal_ex(ctx, hash, &hlen) != 1) die("EVP_DigestFinal_ex");

    EVP_MD_CTX_free(ctx);
    digest_to_hex(hash, hlen, out);
}

// create UDP socket with multicast settings
static int make_udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");

    // set TTL to 1 so it stays local
    unsigned char ttl = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
        die("setsockopt(IP_MULTICAST_TTL)");

    // set timeout for receiving
    struct timeval tv;
    tv.tv_sec = RESPONSE_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        die("setsockopt(SO_RCVTIMEO)");

    return fd;
}

// helper to send JSON text
static void send_json_text(int sock, const struct sockaddr_in *dest, const char *json_text) {
    ssize_t sent = sendto(sock, json_text, strlen(json_text), 0,
                          (const struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) die("sendto");
}

// process one file and send its JSON to the server
static void send_file_json(int sock, const struct sockaddr_in *dest,
                           const char *dir, const char *fname) {
    // build full path
    char fpath[4096];
    size_t dlen = strlen(dir);
    int need_slash = (dlen > 0 && dir[dlen - 1] != '/');

    if (snprintf(fpath, sizeof(fpath), "%s%s%s",
                 dir, need_slash ? "/" : "", fname) >= (int)sizeof(fpath)) {
        fprintf(stderr, "path too long: %s/%s\n", dir, fname);
        exit(EXIT_FAILURE);
    }

    // make sure it's a regular file
    struct stat st;
    if (stat(fpath, &st) != 0) die("stat");
    if (!S_ISREG(st.st_mode)) return;

    FILE *fp = fopen(fpath, "rb");
    if (!fp) die("fopen");

    unsigned char *chunk_buf = malloc(CHUNK_SIZE);
    if (!chunk_buf) die("malloc");

    // setup context for full file hash
    EVP_MD_CTX *file_ctx = EVP_MD_CTX_new();
    if (!file_ctx) die("EVP_MD_CTX_new");
    if (EVP_DigestInit_ex(file_ctx, EVP_sha256(), NULL) != 1)
        die("EVP_DigestInit_ex");

    str_list hashes;
    str_list_init(&hashes);

    // read file chunk by chunk
    size_t n;
    while ((n = fread(chunk_buf, 1, CHUNK_SIZE, fp)) > 0) {
        // add to full file hash
        if (EVP_DigestUpdate(file_ctx, chunk_buf, n) != 1)
            die("EVP_DigestUpdate");

        // hash this specific chunk
        char chunk_hex[65];
        sha256_hex(chunk_buf, n, chunk_hex);
        str_list_push(&hashes, chunk_hex);
    }

    if (ferror(fp)) die("fread");

    // empty files still need a hash
    if (st.st_size == 0) {
        char empty_hex[65];
        sha256_hex((const unsigned char *)"", 0, empty_hex);
        str_list_push(&hashes, empty_hex);
    }

    // finalize the full file hash
    unsigned char full_hash[EVP_MAX_MD_SIZE];
    unsigned int full_len = 0;
    if (EVP_DigestFinal_ex(file_ctx, full_hash, &full_len) != 1)
        die("EVP_DigestFinal_ex");
    EVP_MD_CTX_free(file_ctx);

    char full_hex[65];
    digest_to_hex(full_hash, full_len, full_hex);

    // build JSON using cJSON
    cJSON *root = cJSON_CreateObject();
    if (!root) die("cJSON_CreateObject");

    cJSON_AddStringToObject(root, "requestType", "register");
    cJSON_AddStringToObject(root, "filename", fname);
    cJSON_AddNumberToObject(root, "fileSize", (double)st.st_size);
    cJSON_AddNumberToObject(root, "numberOfChunks", (double)hashes.len);

    cJSON *hash_array = cJSON_AddArrayToObject(root, "chunk_hashes");
    if (!hash_array) die("cJSON_AddArrayToObject");

    for (size_t i = 0; i < hashes.len; i++) {
        cJSON_AddItemToArray(hash_array, cJSON_CreateString(hashes.items[i]));
    }

    cJSON_AddStringToObject(root, "fullFileHash", full_hex);

    char *json_text = cJSON_PrintUnformatted(root);
    if (!json_text) die("cJSON_PrintUnformatted");

    // make sure it's not too big
    if (strlen(json_text) > MAX_JSON_SIZE) {
        fprintf(stderr, "JSON too large for UDP datagram: %s\n", fname);
        free(json_text);
        cJSON_Delete(root);
        str_list_free(&hashes);
        free(chunk_buf);
        fclose(fp);
        return;
    }

    send_json_text(sock, dest, json_text);

    printf("Sent JSON for file: %s\n", fname);
    printf("%s\n\n", json_text);

    free(json_text);
    cJSON_Delete(root);
    str_list_free(&hashes);
    free(chunk_buf);
    fclose(fp);
}

// register all files in the directory with the server
static void register_local_files(int sock, const struct sockaddr_in *dest, const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) die("opendir");

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (is_dot_entry(de->d_name)) continue;
        send_file_json(sock, dest, dir, de->d_name);
    }

    closedir(dp);
}

// send a query request to get file list from servers
static void send_query_request(int sock, const struct sockaddr_in *dest) {
    cJSON *root = cJSON_CreateObject();
    if (!root) die("cJSON_CreateObject");

    cJSON_AddStringToObject(root, "requestType", "query");

    char *json_text = cJSON_PrintUnformatted(root);
    if (!json_text) die("cJSON_PrintUnformatted");

    send_json_text(sock, dest, json_text);

    free(json_text);
    cJSON_Delete(root);
}

// parse a query response and add files to our list
static void collect_query_response(const char *buffer, QueryFileList *results) {
    cJSON *root = cJSON_Parse(buffer);
    if (!root) {
        return;
    }

    // make sure it's actually a query response
    const cJSON *requestType = cJSON_GetObjectItemCaseSensitive(root, "requestType");
    if (!cJSON_IsString(requestType) || requestType->valuestring == NULL ||
        strcmp(requestType->valuestring, "queryResponse") != 0) {
        cJSON_Delete(root);
        return;
    }

    const cJSON *files = cJSON_GetObjectItemCaseSensitive(root, "files");
    if (!cJSON_IsArray(files)) {
        cJSON_Delete(root);
        return;
    }

    // go through each file in the array
    int count = cJSON_GetArraySize(files);
    for (int i = 0; i < count; i++) {
        cJSON *obj = cJSON_GetArrayItem(files, i);
        if (!cJSON_IsObject(obj)) continue;

        cJSON *filename = cJSON_GetObjectItemCaseSensitive(obj, "filename");
        cJSON *fileSize = cJSON_GetObjectItemCaseSensitive(obj, "fileSize");
        cJSON *fullFileHash = cJSON_GetObjectItemCaseSensitive(obj, "fullFileHash");

        if (cJSON_IsString(filename) && filename->valuestring &&
            cJSON_IsNumber(fileSize) &&
            cJSON_IsString(fullFileHash) && fullFileHash->valuestring) {
            query_file_list_push_unique(results,
                                        filename->valuestring,
                                        (long long)fileSize->valuedouble,
                                        fullFileHash->valuestring);
        }
    }

    cJSON_Delete(root);
}

// print the results in a nice table format
static void print_query_results(const QueryFileList *results) {
    printf("Stored File Information:\n");
    printf("--------------------------------------------------------------------------------------------\n");
    printf("Choice | %-24s | %-10s | %-64s\n", "File Name", "Size", "Full Hash");
    printf("--------------------------------------------------------------------------------------------\n");

    if (results->len == 0) {
        printf("No files received from servers.\n");
        return;
    }

    for (size_t i = 0; i < results->len; i++) {
        printf("%-6zu | %-24s | %-10lld | %-64s\n",
               i + 1,
               results->items[i].filename,
               results->items[i].fileSize,
               results->items[i].fullFileHash);
    }
}

// send query and collect responses from all servers
static void request_and_print_files(int sock, const struct sockaddr_in *dest) {
    QueryFileList results;
    query_file_list_init(&results);

    send_query_request(sock, dest);

    // keep receiving until timeout
    for (;;) {
        char buffer[MAX_JSON_SIZE + 1];
        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);

        ssize_t nbytes = recvfrom(sock, buffer, sizeof(buffer) - 1,
                                  0, (struct sockaddr *)&sender, &slen);

        if (nbytes < 0) {
            // timeout means we're done
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            perror("recvfrom");
            break;
        }

        buffer[nbytes] = '\0';
        collect_query_response(buffer, &results);
    }

    print_query_results(&results);
    query_file_list_free(&results);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <directory> <multicast_ip> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *dir = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return EXIT_FAILURE;
    }

    // make sure directory exists
    struct stat st;
    if (stat(dir, &st) != 0) die("stat");
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a directory\n", dir);
        return EXIT_FAILURE;
    }

    int sock = make_udp_socket();

    // setup destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &dest_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid multicast address: %s\n", ip);
        close(sock);
        return EXIT_FAILURE;
    }

    // register our local files with the server
    register_local_files(sock, &dest_addr, dir);

    // main menu loop
    for (;;) {
        int choice;

        printf("Select an option:\n");
        printf("1. Request JSON of files from servers\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");

        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Invalid input.\n");
            break;
        }

        if (choice == 1) {
            request_and_print_files(sock, &dest_addr);
        } else if (choice == 3) {
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}