package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Message defines the structure for communication over the WebSocket.
type Message struct {
	Type    string `json:"type"`
	ConnID  string `json:"connId"`
	Payload string `json:"payload,omitempty"`
}

const (
	MsgNewConnection   = "NEW_CONNECTION"
	MsgData            = "DATA"
	MsgCloseConnection = "CLOSE_CONNECTION"
)

// --- Server Code ---

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// connMap stores the user's TCP connection, keyed by a unique connection ID.
var connMap = make(map[string]net.Conn)
var connMapMutex = &sync.Mutex{}

// The single WebSocket connection to our client.
var wsConn *websocket.Conn
var wsConnMutex = &sync.Mutex{}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var err error

	wsConnMutex.Lock()
	if wsConn != nil {
		wsConn.Close()
	}
	wsConn, err = upgrader.Upgrade(w, r, nil)
	wsConnMutex.Unlock()

	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer wsConn.Close()
	log.Println("Client connected via WebSocket.")

	// Listen for messages from the client
	for {
		_, messageBytes, err := wsConn.ReadMessage()
		if err != nil {
			log.Println("Read error from client:", err)
			break // Exit loop on error (e.g., client disconnects)
		}

		var msg Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			log.Println("JSON unmarshal error:", err)
			continue
		}

		connMapMutex.Lock()
		userConn, ok := connMap[msg.ConnID]
		connMapMutex.Unlock()

		if !ok {
			// It's possible for a message to arrive after a connection is closed, so don't log as an error.
			continue
		}

		switch msg.Type {
		case MsgData:
			data, err := base64.StdEncoding.DecodeString(msg.Payload)
			if err != nil {
				log.Println("Base64 decode error:", err)
				continue
			}
			_, err = userConn.Write(data)
			if err != nil {
				log.Printf("Error writing to user connection %s: %v", msg.ConnID, err)
			}
		case MsgCloseConnection:
			// log.Printf("Client closed connection for ConnID: %s", msg.ConnID)
			userConn.Close()
			connMapMutex.Lock()
			delete(connMap, msg.ConnID)
			connMapMutex.Unlock()
		}
	}
	log.Println("Client disconnected.")
	// Clean up all connections if the client disconnects
	connMapMutex.Lock()
	for id, conn := range connMap {
		conn.Close()
		delete(connMap, id)
	}
	connMapMutex.Unlock()

	wsConnMutex.Lock()
	wsConn = nil
	wsConnMutex.Unlock()
}

func handleUserConnection(userConn net.Conn) {
	wsConnMutex.Lock()
	if wsConn == nil {
		wsConnMutex.Unlock()
		log.Println("No client connected, dropping user connection.")
		userConn.Close()
		return
	}
	wsConnMutex.Unlock()

	connID := uuid.New().String()
	// log.Printf("New user connection with ConnID: %s", connID)

	connMapMutex.Lock()
	connMap[connID] = userConn
	connMapMutex.Unlock()

	// Tell the client to open a new connection
	msg := Message{Type: MsgNewConnection, ConnID: connID}
	msgBytes, _ := json.Marshal(msg)

	wsConnMutex.Lock()
	err := wsConn.WriteMessage(websocket.TextMessage, msgBytes)
	wsConnMutex.Unlock()
	if err != nil {
		log.Println("Write error to client:", err)
		userConn.Close()
		return
	}

	// Read from user connection and forward to client
	buffer := make([]byte, 8192) // Increased buffer size
	for {
		n, err := userConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error from user connection %s: %v", connID, err)
			}
			break
		}

		payload := base64.StdEncoding.EncodeToString(buffer[:n])
		dataMsg := Message{Type: MsgData, ConnID: connID, Payload: payload}
		msgBytes, _ := json.Marshal(dataMsg)

		wsConnMutex.Lock()
		if wsConn != nil {
			err = wsConn.WriteMessage(websocket.TextMessage, msgBytes)
		} else {
			err = errors.New("websocket connection is nil")
		}
		wsConnMutex.Unlock()

		if err != nil {
			log.Println("Write error to client:", err)
			break
		}
	}

	// Cleanup
	userConn.Close()
	// log.Printf("User connection closed: %s", connID)

	connMapMutex.Lock()
	delete(connMap, connID)
	connMapMutex.Unlock()

	// Notify client that connection is closed
	closeMsg := Message{Type: MsgCloseConnection, ConnID: connID}
	msgBytes, _ = json.Marshal(closeMsg)

	wsConnMutex.Lock()
	if wsConn != nil {
		wsConn.WriteMessage(websocket.TextMessage, msgBytes)
	}
	wsConnMutex.Unlock()
}

func runServer(wsPort, userPort string, secure bool, certFile, keyFile string) {
	http.HandleFunc("/ws", handleWebSocket)
	go func() {
		addr := ":" + wsPort
		if secure {
			if certFile == "" || keyFile == "" {
				log.Fatal("For secure mode (-secure), --cert-file and --key-file are required.")
			}
			log.Printf("Secure WebSocket server (wss) listening on %s", addr)
			if err := http.ListenAndServeTLS(addr, certFile, keyFile, nil); err != nil {
				log.Fatal("ListenAndServeTLS (WebSocket): ", err)
			}
		} else {
			log.Printf("WebSocket server (ws) listening on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Fatal("ListenAndServe (WebSocket): ", err)
			}
		}
	}()

	listener, err := net.Listen("tcp", ":"+userPort)
	if err != nil {
		log.Fatal("Listen (User Port): ", err)
	}
	defer listener.Close()
	log.Printf("User-facing SOCKS listener on :%s", userPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleUserConnection(conn)
	}
}

// --- Client Code ---

// ProxySession manages the state for a single SOCKS connection.
type ProxySession struct {
	connID       string
	wsConn       *websocket.Conn
	incomingData chan []byte
	closeOnce    sync.Once
}

func newProxySession(connID string, wsConn *websocket.Conn) *ProxySession {
	return &ProxySession{
		connID:       connID,
		wsConn:       wsConn,
		incomingData: make(chan []byte, 10), // Buffered channel
	}
}

// readFromProxy reads data that has been forwarded from the user.
func (s *ProxySession) readFromProxy() ([]byte, error) {
	data, ok := <-s.incomingData
	if !ok {
		return nil, io.EOF
	}
	return data, nil
}

// writeToProxy sends data back to the user.
func (s *ProxySession) writeToProxy(data []byte) error {
	payload := base64.StdEncoding.EncodeToString(data)
	msg := Message{Type: MsgData, ConnID: s.connID, Payload: payload}
	msgBytes, _ := json.Marshal(msg)
	return s.wsConn.WriteMessage(websocket.TextMessage, msgBytes)
}

// close signals the end of this session.
func (s *ProxySession) close() {
	s.closeOnce.Do(func() {
		close(s.incomingData)
		// Notify the server that we are closing this connection
		closeMsg := Message{Type: MsgCloseConnection, ConnID: s.connID}
		msgBytes, _ := json.Marshal(closeMsg)
		s.wsConn.WriteMessage(websocket.TextMessage, msgBytes)
	})
}

// Full SOCKS5 implementation
func handleSocksProxy(session *ProxySession) {
	defer session.close()
	// log.Printf("[%s] Starting SOCKS5 proxy session", session.connID)

	// 1. SOCKS Greeting
	greeting, err := session.readFromProxy()
	if err != nil {
		log.Printf("[%s] Error reading SOCKS greeting: %v", session.connID, err)
		return
	}
	if greeting[0] != 0x05 {
		log.Printf("[%s] Unsupported SOCKS version: %x", session.connID, greeting[0])
		return
	}
	if err := session.writeToProxy([]byte{0x05, 0x00}); err != nil {
		log.Printf("[%s] Error writing SOCKS greeting reply: %v", session.connID, err)
		return
	}

	// 2. SOCKS Request
	request, err := session.readFromProxy()
	if err != nil {
		log.Printf("[%s] Error reading SOCKS request: %v", session.connID, err)
		return
	}
	if len(request) < 4 || request[0] != 0x05 || request[1] != 0x01 { // VER=5, CMD=CONNECT
		log.Printf("[%s] Invalid SOCKS request", session.connID)
		session.writeToProxy([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host, port string
	addrType := request[3]
	switch addrType {
	case 0x01: // IPv4
		host = net.IP(request[4 : 4+net.IPv4len]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(request[4+net.IPv4len : 4+net.IPv4len+2])))
	case 0x03: // Domain name
		domainLen := int(request[4])
		host = string(request[5 : 5+domainLen])
		port = strconv.Itoa(int(binary.BigEndian.Uint16(request[5+domainLen : 5+domainLen+2])))
	case 0x04: // IPv6
		host = net.IP(request[4 : 4+net.IPv6len]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(request[4+net.IPv6len : 4+net.IPv6len+2])))
	default:
		log.Printf("[%s] Unsupported address type: %x", session.connID, addrType)
		session.writeToProxy([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	destAddr := net.JoinHostPort(host, port)
	// log.Printf("[%s] Connecting to destination: %s", session.connID, destAddr)

	// 3. Connect to destination
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		//log.Printf("[%s] Failed to connect to destination: %v", session.connID, err)
		session.writeToProxy([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destConn.Close()

	// 4. Send SOCKS success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if err := session.writeToProxy(reply); err != nil {
		log.Printf("[%s] Error writing SOCKS success reply: %v", session.connID, err)
		return
	}

	// 5. Relay data
	// log.Printf("[%s] Connection established, relaying data.", session.connID)
	go func() {
		io.Copy(writerFunc(func(p []byte) (int, error) {
			err := session.writeToProxy(p)
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}), destConn)
		session.close()
	}()

	for {
		data, err := session.readFromProxy()
		if err != nil {
			break
		}
		if _, err := destConn.Write(data); err != nil {
			log.Printf("[%s] Error writing to destination: %v", session.connID, err)
			break
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func handleServerMessages(serverWsConn *websocket.Conn) {
	var sessionMap sync.Map
	defer func() {
		sessionMap.Range(func(key, value interface{}) bool {
			if session, ok := value.(*ProxySession); ok {
				session.close()
			}
			return true
		})
	}()

	for {
		_, messageBytes, err := serverWsConn.ReadMessage()
		if err != nil {
			//log.Println("Read error from server:", err)
			return
		}

		var msg Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			log.Println("JSON unmarshal error:", err)
			continue
		}

		switch msg.Type {
		case MsgNewConnection:
			session := newProxySession(msg.ConnID, serverWsConn)
			sessionMap.Store(msg.ConnID, session)
			go handleSocksProxy(session)
		case MsgData:
			if val, ok := sessionMap.Load(msg.ConnID); ok {
				session := val.(*ProxySession)
				data, err := base64.StdEncoding.DecodeString(msg.Payload)
				if err != nil {
					log.Printf("[%s] Base64 decode error: %v", msg.ConnID, err)
					continue
				}
				select {
				case session.incomingData <- data:
				default:
					log.Printf("[%s] Dropping data, channel is full.", msg.ConnID)
				}
			}
		case MsgCloseConnection:
			// log.Printf("[%s] Server closed connection.", msg.ConnID)
			if val, ok := sessionMap.LoadAndDelete(msg.ConnID); ok {
				session := val.(*ProxySession)
				session.close()
			}
		}
	}
}

func runClient(serverAddr string, secure bool) {
	scheme := "ws"
	if secure {
		scheme = "wss"
	}
	url := scheme + "://" + serverAddr + "/ws"

	// Create a custom dialer to skip TLS certificate verification for self-signed certs
	dialer := websocket.DefaultDialer
	if secure {
		dialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}
	}

	for {
		//log.Printf("Connecting to server at %s", url)
		c, _, err := dialer.Dial(url, nil)
		if err != nil {
			//log.Println("Dial error:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		//log.Println("Connected to server.")

		handleServerMessages(c)

		c.Close()
		//log.Println("Disconnected from server. Retrying...")
		time.Sleep(5 * time.Second)
	}
}

func main() {
	// If no command-line arguments are provided, run in default client mode.
	if len(os.Args) == 1 {
		//log.Println("No arguments provided, running in default client mode...")
		// Default settings
		serverAddr := "www.test.com"
		secure := true

		// Logic to append port 443 if missing
		addr := serverAddr
		if secure {
			_, _, err := net.SplitHostPort(addr)
			if err != nil { // This error means no port was found
				addr = net.JoinHostPort(addr, "443")
			}
		}
		runClient(addr, secure)
		return
	}

	// If arguments are provided, parse them.
	mode := flag.String("mode", "Client", "Run in 'server' or 'client' mode")
	wsPort := flag.String("ws-port", "443", "Port for WebSocket server (e.g., 443 for wss, 8080 for ws)")
	userPort := flag.String("user-port", "1080", "Port for user-facing SOCKS listener")
	serverAddr := flag.String("server", "www.test.com", "Server address (domain or IP) for client to connect to")
	secure := flag.Bool("secure", false, "Use secure WebSocket (wss://)")
	certFile := flag.String("cert-file", "", "Path to TLS certificate file (server mode, required for -secure)")
	keyFile := flag.String("key-file", "", "Path to TLS key file (server mode, required for -secure)")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*wsPort, *userPort, *secure, *certFile, *keyFile)
	case "client":
		// Automatically append port 443 to server address if it's missing and in secure mode
		addr := *serverAddr
		if *secure {
			// Check if a port is already present. If not, append the default for wss.
			_, _, err := net.SplitHostPort(addr)
			if err != nil { // This error likely means no port was found
				addr = net.JoinHostPort(addr, "443")
			}
		}
		runClient(addr, *secure)
	default:
		log.Fatalf("Invalid mode: %s. Use 'server' or 'client'.", *mode)
	}
}
