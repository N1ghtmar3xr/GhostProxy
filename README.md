# 👻 GhostProxy

GhostProxy is a powerful and simple reverse SOCKS5 proxy that tunnels
traffic over a secure WebSocket (wss://) connection. It allows you to
securely access services within a private network from anywhere, using a
single Go binary.

The connection is initiated from a Linux client inside the private network to
a public server, making it highly effective at bypassing restrictive
firewalls as it masquerades as standard HTTPS web traffic.

## How It Works

The architecture is simple and consists of two components running the
same binary in different modes:

-   **The Server**: Runs on a publicly accessible machine (e.g., a VPS).
    It listens for a WebSocket connection from the linux client (May be Victim) and also
    listens for incoming SOCKS5 connections from the user (Attacker).

-   **The Client (Linux Only) (In Victim)**: Runs on a Linux machine inside the
    target private network. It establishes a persistent, outbound wss://
    connection to the public server.

When the user connects to the server's (e.g., a VPS) SOCKS5 port, the server
seamlessly forwards that traffic through the WebSocket tunnel to the
client. The client then makes the request to the final destination
within its private network and sends the response back along the same
path.

``` mermaid
sequenceDiagram
    participant UserPC as Your PC
    participant GhostProxy_Server as Server (Public)
    participant GhostProxy_Client as Client (Private Network)
    participant Target_Service as Target Service (Private Network)

    Note over GhostProxy_Client, GhostProxy_Server: Initial Setup
    GhostProxy_Client->>+GhostProxy_Server: Establish persistent WSS tunnel
    GhostProxy_Server-->>-GhostProxy_Client: Tunnel established

    Note over UserPC, GhostProxy_Server: User Access
    UserPC->>+GhostProxy_Server: SOCKS5 request for Target_Service
    GhostProxy_Server->>+GhostProxy_Client: Forward request via WSS tunnel
    GhostProxy_Client->>+Target_Service: Access internal service
    Target_Service-->>-GhostProxy_Client: Response
    GhostProxy_Client-->>-GhostProxy_Server: Forward response via WSS tunnel
    GhostProxy_Server-->>-UserPC: Final response
```

## Features

-   SOCKS5 Proxy: Provides a standard SOCKS5 interface for compatibility
    with a wide range of applications.
-   Secure WebSocket Tunneling: Encapsulates traffic in wss://
    (WebSocket over TLS), making it look like standard encrypted web
    traffic.
-   Single Binary: The entire project compiles to a single,
    dependency-free executable for easy deployment on Linux.
-   Reverse Connection: Bypasses firewalls by initiating connections
    from the private Linux client to the public server.
-   Default Client Mode: Runs as a pre-configured client if no arguments
    are provided, ideal for simple deployment scenarios.
-   Self-Signed Certificate Support: Easily works with self-signed
    certificates for private setups.

## Installation

You must have Go installed to compile the project.

Clone the repository:

``` bash
git clone https://github.com/N1ghtmar3xr/GhostProxy.git
cd GhostProxy
```

Ensure dependencies are up to date:

``` bash
go mod tidy
```

Compile the binary for Linux:

``` bash
GOOS=linux GOARCH=amd64 go build -o GhostProxy .
```

This will create a single executable file named `GhostProxy`.

## Usage

The binary can be run in server or client mode.

### Server Setup

Run this on your publicly accessible server with a domain name pointing
to it.

Generate a SSL Certificate or Self-Signed SSL Certificate:

``` bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=proxy.yourdomain.com"
```

Run the Server:

``` bash
./GhostProxy -mode server -secure -ws-port 443 -user-port 1080 -cert-file ./cert.pem -key-file ./key.pem
```

The server is now listening for a client on port 443 and for your SOCKS
traffic on port 1080.

### Client Setup (Linux Only)

Run this on the Linux machine inside the private network you want to
access.

#### Default Mode (Easiest)

If you compiled the binary with the default server www.test.com, you can
run it with no arguments. Change the target domain name is source code before compilation to run in default mode.

``` bash
./GhostProxy
```

It will automatically attempt to connect to `wss://www.test.com`.

#### Manual Mode

To specify a server, run the command with arguments.

``` bash
./GhostProxy -mode client -secure -server proxy.yourdomain.com
```

The client will connect to the server, and the tunnel is now active.

## Command-Line Flags (When executing on server)
```
  ---------------------------------------------------------------
  Flag          Description                             Default
  ------------  ----------------------------------      ---------
  -mode         Run in server mode                      client
                                                  
  -secure       Use secure WebSocket (wss://).          false
                                               
  -ws-port      Port for the WebSocket listener.        443
                                               
  -user-port    Port for the user-facing SOCKS          1080
                listener.
                                         
  -cert-file    Path to the TLS certificate file        ""
                (required when -secure flag is used).                   

  -key-file     Path to the TLS key file (required      ""
                when -secure flag is used).   
                                 
  ---------------------------------------------------------------
```


## Command-Line Flags (When executing on Client)
```
  ---------------------------------------------------------------
  Flag          Description                             Default
  ------------  ----------------------------------      ---------
  -mode         Run in server mode                      client
                                                  
  -secure       Use secure WebSocket (wss://).          false
                                               
  -server       The address of the server to            www.test.com
                connect to.                                           
                            
  *** In Client default mode, -secure flag is used. It means if you just run ./GhostProxy, it will start the binaey in client mode with -secure flag which will use wss(443).
  *** In Client mannual mode, you have to provide -secure flag to use wss(443) otherwise it will use ws(80). Same for server mode too.
  -----------------------------------------------------------------
```

## Example: Accessing an Internal Web Server

Set up the server and client as described above.

Configure your local PC's browser to use a SOCKS5 proxy.

SOCKS Host: `proxy.yourdomain.com`\
Port: `1080`\
Version: `SOCKSv5`

Navigate to the internal IP of a web server in the client's network
(e.g., `http://192.168.1.50`). Your request will be securely proxied.

*** Proxychains set up can be implemented too for access service other than web like ssh,  rdp and many nore.

## License

This project is licensed under the MIT License.
