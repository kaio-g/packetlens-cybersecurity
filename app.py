import os
from flask import Flask, render_template, jsonify, request
import random

app = Flask(__name__)

# Quiz questions database
QUIZ_QUESTIONS = [
    {
        "id": 1,
        "question": "Which transport layer protocol uses a 3-way handshake (SYN, SYN-ACK, ACK) to establish a reliable connection?",
        "options": [
            "UDP (User Datagram Protocol)",
            "TCP (Transmission Control Protocol)",
            "ICMP (Internet Control Message Protocol)",
            "DNS (Domain Name System)"
        ],
        "correct": 1,
        "explanation": "TCP is a connection-oriented protocol that ensures reliable delivery. It establishes connection using a 3-way handshake: Client sends SYN, Server replies with SYN-ACK, Client sends ACK."
    },
    {
        "id": 2,
        "question": "Which of the following is a stateless protocol that does not guarantee delivery, making it ideal for speed-sensitive applications like video streaming?",
        "options": [
            "TCP",
            "HTTP",
            "UDP",
            "HTTPS"
        ],
        "correct": 2,
        "explanation": "UDP (User Datagram Protocol) is a connectionless, stateless protocol. It has lower overhead than TCP and does not verify receipt of packets, making it perfect for real-time applications."
    },
    {
        "id": 3,
        "question": "Which tcpdump command flags would you use to capture traffic on all interfaces and save the output to a file named 'sniff.pcap'?",
        "options": [
            "tcpdump -r sniff.pcap",
            "tcpdump -i any -w sniff.pcap",
            "tcpdump -v -x any",
            "tcpdump -w any -i sniff.pcap"
        ],
        "correct": 1,
        "explanation": "'-i any' specifies that tcpdump should listen on all available interfaces, and '-w sniff.pcap' writes the captured packets to a PCAP file instead of printing them to the terminal."
    },
    {
        "id": 4,
        "question": "In Wireshark, what display filter would you use to find all HTTP packets containing a GET request?",
        "options": [
            "http.request.method == \"GET\"",
            "http && get",
            "tcp.port == 80 && get",
            "ip.proto == HTTP && GET"
        ],
        "correct": 0,
        "explanation": "Wireshark supports detailed display filters. 'http.request.method == \"GET\"' matches only HTTP packets where the request method is explicitly GET."
    },
    {
        "id": 5,
        "question": "What identifies the file format of a PCAP file in its global header (typically the first 4 bytes, e.g., 0xa1b2c3d4)?",
        "options": [
            "File extension (.pcap)",
            "Global header length",
            "Magic bytes / Magic number",
            "Ethernet frame preamble"
        ],
        "correct": 2,
        "explanation": "Magic bytes (magic number) at the very start of a PCAP file (e.g., 0xa1b2c3d4 or 0xd4c3b2a1) tell readers like Wireshark the format and byte-ordering (endianness) of the capture file."
    },
    {
        "id": 6,
        "question": "Which protocol translates human-readable domain names (like google.com) into IP addresses and primarily runs over UDP port 53?",
        "options": [
            "HTTP",
            "ICMP",
            "ARP",
            "DNS"
        ],
        "correct": 3,
        "explanation": "DNS (Domain Name System) acts as the phonebook of the internet, mapping domain names to IP addresses. It typically uses UDP port 53 for standard queries."
    },
    {
        "id": 7,
        "question": "What is the primary difference between a Wireshark 'Capture Filter' and a 'Display Filter'?",
        "options": [
            "Capture filters are applied after saving; Display filters are applied before capturing.",
            "Capture filters control what packets are saved to disk; Display filters only filter what is currently visible in the interface.",
            "Capture filters only work on Windows; Display filters only work on Linux/Mac.",
            "There is no difference; they use the exact same syntax."
        ],
        "correct": 1,
        "explanation": "Capture filters are set before capturing (using libpcap syntax, same as tcpdump) to discard unwanted packets immediately, saving disk space. Display filters are applied post-capture in Wireshark to search/view packets dynamically."
    },
    {
        "id": 8,
        "question": "What protocol is used by utilities like 'ping' and 'traceroute' to send diagnostic and error messages?",
        "options": [
            "ICMP (Internet Control Message Protocol)",
            "TCP",
            "IGMP (Internet Group Management Protocol)",
            "DNS"
        ],
        "correct": 0,
        "explanation": "ICMP is used by network devices to send error messages and operational information (e.g., a requested service is not available or a host could not be reached). 'ping' utilizes ICMP Echo Request and Echo Reply messages."
    }
]

# Protocol detailed information database
PROTOCOLS = {
    "TCP": {
        "name": "Transmission Control Protocol (TCP)",
        "layer": "Transport Layer (L4)",
        "port": "Various (e.g., 80 for HTTP, 443 for HTTPS, 22 for SSH)",
        "characteristics": ["Connection-oriented", "Reliable delivery", "Flow control", "Stateful (tracks sequences)"],
        "description": "TCP is the backbone of web browsing, email, and file transfers. It sets up a dedicated virtual circuit before sending any data, guaranteeing that all bytes arrive in order and undamaged. If a packet is lost, TCP automatically requests a retransmission.",
        "handshake": [
            {"step": 1, "sender": "Client", "receiver": "Server", "flags": "SYN", "desc": "Client initiates connection request by sending a SYN (Synchronize) packet with a random sequence number (e.g., Seq=X)."},
            {"step": 2, "sender": "Server", "receiver": "Client", "flags": "SYN-ACK", "desc": "Server acknowledges with SYN-ACK (Synchronize-Acknowledge). It sets Ack=X+1 and sends its own sequence number Seq=Y."},
            {"step": 3, "sender": "Client", "receiver": "Server", "flags": "ACK", "desc": "Client finalizes connection by sending an ACK (Acknowledge) packet with Seq=X+1 and Ack=Y+1. Connection is now ESTABLISHED."}
        ]
    },
    "UDP": {
        "name": "User Datagram Protocol (UDP)",
        "layer": "Transport Layer (L4)",
        "port": "Various (e.g., 53 for DNS, 123 for NTP, 67/68 for DHCP)",
        "characteristics": ["Connectionless", "Unreliable (best-effort)", "Low overhead / Fast", "Stateless"],
        "description": "UDP is a simple, message-oriented transport protocol. It sends 'datagrams' without establishing a connection or verifying receipt. This lacks reliability, but provides maximum speed and minimal latency, making it ideal for streaming media, gaming, and simple query-response services.",
        "flow": "Client sends datagram -> Server processes datagram -> Server responds (optional). No connection state is maintained."
    },
    "ICMP": {
        "name": "Internet Control Message Protocol (ICMP)",
        "layer": "Network Layer (L3)",
        "port": "N/A (IP Protocol 1)",
        "characteristics": ["Diagnostic / Error reporting", "Used by ping and traceroute", "No port numbers", "Encapsulated in IP directly"],
        "description": "ICMP is not used to exchange user data. Instead, it is used by routers and hosts to report network conditions, errors, and diagnostic information. For example, if a packet's Time-To-Live (TTL) reaches 0, a router sends an ICMP 'Time Exceeded' message back to the sender.",
        "common_types": [
            {"type": "Type 8", "code": "Code 0", "name": "Echo Request", "desc": "Used by 'ping' to test host reachability."},
            {"type": "Type 0", "code": "Code 0", "name": "Echo Reply", "desc": "Sent in response to an Echo Request."},
            {"type": "Type 3", "code": "Code 0-15", "name": "Destination Unreachable", "desc": "Indicates a packet could not be delivered (e.g. Host Unreachable, Port Unreachable)."}
        ]
    },
    "DNS": {
        "name": "Domain Name System (DNS)",
        "layer": "Application Layer (L7)",
        "port": "UDP/TCP Port 53",
        "characteristics": ["Name resolution", "Distributed hierarchical database", "Caching features", "Query-Response model"],
        "description": "DNS translates human-friendly domain names (e.g., www.packetlens.dev) into numeric IP addresses (e.g., 192.0.2.1) that computers use to route packets. It runs over UDP for standard speed-sensitive lookups, but falls back to TCP for large zone transfers or responses exceeding 512 bytes.",
        "query_types": [
            {"record": "A", "desc": "Maps domain name to IPv4 address."},
            {"record": "AAAA", "desc": "Maps domain name to IPv6 address."},
            {"record": "CNAME", "desc": "Creates an alias (canonical name) pointing to another domain."},
            {"record": "MX", "desc": "Specifies the mail servers responsible for receiving email for the domain."}
        ]
    },
    "HTTP": {
        "name": "Hypertext Transfer Protocol (HTTP)",
        "layer": "Application Layer (L7)",
        "port": "TCP Port 80",
        "characteristics": ["Text-based (plaintext)", "Stateless client-server", "Request-Response cycle", "Extensible headers"],
        "description": "HTTP is the foundation of data exchange on the World Wide Web. A client (browser) sends a structured text request (like GET /index.html HTTP/1.1), and the server responds with status codes (like 200 OK) and the requested content. Because it is plaintext, HTTP traffic can be easily read in transit using tools like Wireshark.",
        "methods": [
            {"method": "GET", "desc": "Retrieve data from the server (e.g., loading a webpage)."},
            {"method": "POST", "desc": "Submit data to the server to create a resource (e.g., submitting a form)."},
            {"method": "PUT", "desc": "Upload representation of a resource or update an existing resource."},
            {"method": "DELETE", "desc": "Remove a resource from the server."}
        ]
    },
    "HTTPS": {
        "name": "Hypertext Transfer Protocol Secure (HTTPS)",
        "layer": "Application Layer (L7) over TLS/SSL",
        "port": "TCP Port 443",
        "characteristics": ["Encrypted payloads", "Secured via TLS (Transport Layer Security)", "Prevents eavesdropping & tampering", "Uses certificates for authentication"],
        "description": "HTTPS is HTTP encapsulated within an encrypted Transport Layer Security (TLS) tunnel. During connection, the server presents a cryptographic certificate to prove its identity. Traffic is then encrypted, meaning eavesdroppers using Wireshark can only see the outer layers (IP headers, TCP port 443, TLS handshake) but cannot read the actual HTTP URL, headers, or data payload.",
        "tls_handshake": [
            {"step": "Client Hello", "desc": "Client sends supported cipher suites, TLS version, and a random string."},
            {"step": "Server Hello", "desc": "Server responds with chosen cipher suite, its SSL/TLS certificate, and a server random string."},
            {"step": "Authentication & Key Exchange", "desc": "Client verifies the certificate authority. Keys are generated securely (Diffie-Hellman or RSA) to encrypt all future communications."},
            {"step": "Finished", "desc": "Both sides send encrypted verification messages. All subsequent data is encrypted."}
        ]
    }
}

@app.route('/')
def index():
    return render_template('index.html', protocols=PROTOCOLS)

@app.route('/api/quiz', methods=['GET'])
def get_quiz():
    # Return questions in randomized order, or keep consistent
    # Let's return them in fixed order but mix up the questions if they reload
    questions = list(QUIZ_QUESTIONS)
    return jsonify(questions)

@app.route('/api/generate-post', methods=['POST'])
def generate_post():
    data = request.get_json() or {}
    score = data.get('score', 0)
    total = data.get('total', 8)
    learned = data.get('learned', [])
    style = data.get('style', 'enthusiastic')
    
    if not learned:
        learned = ["TCP handshakes", "Wireshark display filters", "tcpdump command syntax"]

    learned_str = ", ".join(learned[:-1]) + ", and " + learned[-1] if len(learned) > 1 else learned[0]
    
    templates = {
        "enthusiastic": (
            "🚀 I just completed the interactive network analysis challenge on #PacketLens!\n\n"
            f"💡 I scored {score}/{total} on the network traffic quiz and leveled up my understanding of "
            f"{learned_str}.\n\n"
            "Understanding network packets is a critical superpower in cybersecurity and software engineering. "
            "Whether it's dissecting a TCP 3-way handshake or analyzing PCAP structures, seeing the wire-level truth "
            "changes how you write, deploy, and secure software.\n\n"
            "Recommended check: If you are looking to learn tcpdump filters or Wireshark, check out PacketLens! 🔍💻\n\n"
            "#cybersecurity #networking #wireshark #tcpdump #learning #infosec"
        ),
        "technical": (
            "📊 Network Analysis Update: Scored {score}/{total} on the #PacketLens Wireshark/tcpdump protocol challenge.\n\n"
            "Key concepts covered:\n"
            + "\n".join([f"• {item}" for item in learned]) + "\n\n"
            "Diving deep into Layer 3/4 encapsulations, DNS resolver mechanics, and the payload isolation properties of TLS (port 443 vs 80) "
            "is essential for diagnostic troubleshooting and incident response. PCAP files tell the ultimate truth of what happened on the wire.\n\n"
            "Always verify on the wire! 🛡️⚙️\n\n"
            "#infosec #networking #packetanalysis #wireshark #tcpdump #devops"
        ),
        "beginner": (
            "🌱 Today, I took another step in my cybersecurity learning journey!\n\n"
            f"I used a tool called PacketLens to explore network packets, and scored {score}/{total} on their beginner quiz! "
            f"I learned about {learned_str}.\n\n"
            "Networking used to feel like a black box, but visualizing how TCP establishes connections and learning "
            "how to filter packets in Wireshark and tcpdump makes it so much clearer. Looking forward to capturing my own PCAPs next!\n\n"
            "Step by step. 📈💻\n\n"
            "#learningdaily #networking #cybersecurity #packetlens #wireshark #beginners"
        )
    }
    
    selected_template = templates.get(style, templates["enthusiastic"])
    return jsonify({"post": selected_template})

if __name__ == '__main__':
    # Run the Flask app locally on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
