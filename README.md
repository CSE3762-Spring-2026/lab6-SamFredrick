# Lab 6 – Multicast File Sharing with Query Support

> Extends Lab 5 with query functionality: clients can request file metadata from multiple servers, and servers respond with a list of tracked files.

---

## Files

| File | Description |
|------|-------------|
| `client.c` | Registers local files and queries servers for available files |
| `server.c` | Receives registrations, tracks peers, and responds to queries |
| `makefile` | Builds both client and server |

---

## Dependencies

- **OpenSSL** — SHA-256 hashing
- **cJSON** — JSON parsing and creation

```bash
sudo apt install libssl-dev libcjson-dev
```

---

## Build

```bash
make
```

---

## Usage

### Start Servers
Run on multiple terminals or machines:

```bash
./server <multicast_ip> <port>

# Example
./server 239.0.0.1 5000
```

### Start Clients

```bash
./client <directory> <multicast_ip> <port>

# Example
./client Photos 239.0.0.1 5000
```

### Client Menu

After starting, the client will register all files in the given directory, then show:

```
1. Request JSON of files from servers
2. Exit
```

Select **1** to query all servers for their tracked file lists.

---

## How It Works

### Client

1. Reads all files in the specified directory
2. Splits each file into **500 KB chunks**
3. Computes SHA-256 hashes for each chunk and the full file
4. Sends a `register` message to the multicast group:

```json
{
  "requestType": "register",
  "filename": "example.jpg",
  "fileSize": 2674338,
  "numberOfChunks": 6,
  "chunk_hashes": ["a1b2c3...", "..."],
  "fullFileHash": "e416f5c..."
}
```

5. On option **1**, sends a `query` request:

```json
{ "requestType": "query" }
```

6. Waits up to **2 seconds** for responses, then collects and displays results

---

### Server

Joins the multicast group and handles two message types:

#### `register`
- Stores file info in a linked list
- Tracks multiple clients per file
- Deduplicates peers automatically

#### `query`
- Responds with a `queryResponse` JSON:

```json
{
  "requestType": "queryResponse",
  "files": [
    {
      "filename": "example.jpg",
      "fileSize": 2674338,
      "fullFileHash": "e416f5c..."
    }
  ]
}
```

---

## Sample Output

```
Stored File Information:
Choice | File Name               | Size      | Full Hash
---------------------------------------------------------------
1      | Agora.jpeg              | 2674338   | e416f5c...
2      | BangkokTemple.jpeg      | 3973590   | f8a39ca...
```

---

## Example Test Setup

Open 4 terminals:

```bash
# Terminal 1 — Server
./server 239.0.0.1 5000

# Terminal 2 — Server
./server 239.0.0.1 5000

# Terminal 3 — Client
./client Photos 239.0.0.1 5000

# Terminal 4 — Client
./client Photos 239.0.0.1 5000
```

Then on each client, enter `1` to query all servers.

---

## Lab Requirements

- [x] Multiple servers run simultaneously via multicast + `SO_REUSEADDR`
- [x] Servers track multiple clients per file
- [x] Same file from multiple clients is merged using `fullFileHash`
- [x] All servers receive and process multicast messages
- [x] Clients retrieve file lists from all active servers
- [x] Output displays correct full file hash values

---

## Notes

- UDP multicast is used — **no guaranteed delivery**
- Max UDP payload: **65,507 bytes**
- Query response timeout: **2 seconds**
- Duplicate files are filtered client-side using `fullFileHash`
