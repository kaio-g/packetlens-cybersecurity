/* PacketLens Main Application JS */

// --- Global App State ---
const state = {
    currentTab: 'dashboard',
    quizQuestions: [],
    currentQuestionIndex: 0,
    quizScore: 0,
    quizTimerInterval: null,
    quizStartTime: null,
    quizCompleted: false,
    selectedAnswer: null,
    hasSubmittedAnswer: false,
    selectedProtocolKey: null,
    handshakeStep: 0,
    pcapHoverDebounce: null
};

// --- Mock Data & TECHNICAL SPEC DETAILS for Protocols ---
const PROTOCOL_DETAILS = {
    "ICMP": {
        "types": [
            {"type": "Type 8", "code": "Code 0", "name": "Echo Request (Ping Request)", "desc": "Sent by client to query if target destination is online."},
            {"type": "Type 0", "code": "Code 0", "name": "Echo Reply (Ping Reply)", "desc": "Sent by target in response to Echo Request confirming reachability."},
            {"type": "Type 3", "code": "Code 0", "name": "Net Unreachable", "desc": "Router could not route packet to destination subnet."},
            {"type": "Type 3", "code": "Code 1", "name": "Host Unreachable", "desc": "Destination host could not be located in network segment."},
            {"type": "Type 3", "code": "Code 3", "name": "Port Unreachable", "desc": "Target host has no server process listening on requested port."},
            {"type": "Type 11", "code": "Code 0", "name": "Time Exceeded (TTL expired)", "desc": "Packet TTL reached 0 in transit. Used by traceroute to identify routers."}
        ]
    },
    "DNS": {
        "records": [
            {"record": "A", "fullname": "IPv4 Address Record", "desc": "Maps domain name to a standard 32-bit IPv4 address (e.g. 192.168.1.10)."},
            {"record": "AAAA", "fullname": "IPv6 Address Record", "desc": "Maps domain name to a 128-bit IPv6 address (e.g. 2001:db8::1)."},
            {"record": "CNAME", "fullname": "Canonical Name", "desc": "Alias record. Points a domain to another domain instead of an IP address."},
            {"record": "MX", "fullname": "Mail Exchange", "desc": "Specifies SMTP mail servers responsible for email delivery to the domain."},
            {"record": "NS", "fullname": "Name Server", "desc": "Delegates a DNS zone to authoritative nameservers."},
            {"record": "TXT", "fullname": "Text Record", "desc": "Arbitrary text data. Frequently used for SPF, DKIM, and site verification."}
        ]
    },
    "HTTP": {
        "methods": [
            {"method": "GET", "desc": "Retrieves representation of a resource. Safe and idempotent (does not modify server state).", "idempotent": "YES"},
            {"method": "POST", "desc": "Submits payload to server to create a new resource or execute processing.", "idempotent": "NO"},
            {"method": "PUT", "desc": "Uploads representation or overwrites the target resource with the request payload.", "idempotent": "YES"},
            {"method": "DELETE", "desc": "Deletes the specified resource on the remote server.", "idempotent": "YES"}
        ]
    },
    "HTTPS": {
        "tlsHandshake": [
            {"step": "1. Client Hello", "desc": "The client sends a list of supported SSL/TLS versions, supported cipher suites, a random string of bytes, and compression methods."},
            {"step": "2. Server Hello & Certificate", "desc": "The server selects the highest mutually supported TLS protocol and cipher suite, sends its digital certificate (containing public key), and a server random string."},
            {"step": "3. Server Key Exchange & Hello Done", "desc": "Server sends supplemental key parameters if needed, then sends a 'Server Hello Done' signal indicating it is done presenting options."},
            {"step": "4. Client Key Exchange & Verify Certificate", "desc": "Client validates the digital certificate. It generates a pre-master secret key, encrypts it using the server's public key, and sends it back. (Alternatively, uses Diffie-Hellman parameters)."},
            {"step": "5. Change Cipher Spec & Finished (Client)", "desc": "Client signals that all subsequent packets will be symmetrically encrypted. It sends an encrypted 'Finished' verification packet."},
            {"step": "6. Change Cipher Spec & Finished (Server)", "desc": "Server decrypts the pre-master secret, generates the shared session key, verifies the client's packet, signals its own encrypt mode, and sends an encrypted 'Finished' response. The encrypted channel is now active."}
        ]
    }
};

// --- Initial Setup on DOM Load ---
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSearch();
    initPcapHexExplorer();
    initSandboxFilter();
    initLinkedInDraftDetails();
    fetchQuizQuestions();
});

// --- Tab Navigation ---
function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    const tabTitle = document.getElementById('current-tab-title');
    const tabSubtitle = document.getElementById('current-tab-subtitle');

    const headers = {
        'dashboard': {
            title: 'Protocol Explorer',
            subtitle: 'Click and inspect network traffic fundamentals at the packet level.'
        },
        'pcap-anatomy': {
            title: 'PCAP Anatomy',
            subtitle: 'Visualize how packet capture files represent network traffic at the binary byte level.'
        },
        'cheatsheets': {
            title: 'Filters & Commands',
            subtitle: 'Cheat sheet references for tcpdump capture command syntax and Wireshark filters.'
        },
        'quiz': {
            title: 'Protocol Quiz',
            subtitle: 'Test your packet analysis and troubleshooting knowledge with interactive challenges.'
        },
        'linkedin': {
            title: 'Share Accomplishment',
            subtitle: 'Draft a learning summary for LinkedIn to showcase your network traffic mastery.'
        }
    };

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            navigateToTab(targetTab);
        });
    });
}

function navigateToTab(tabId) {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    const tabTitle = document.getElementById('current-tab-title');
    const tabSubtitle = document.getElementById('current-tab-subtitle');
    
    const headers = {
        'dashboard': {
            title: 'Protocol Explorer',
            subtitle: 'Click and inspect network traffic fundamentals at the packet level.'
        },
        'pcap-anatomy': {
            title: 'PCAP Anatomy',
            subtitle: 'Visualize how packet capture files represent network traffic at the binary byte level.'
        },
        'cheatsheets': {
            title: 'Filters & Commands',
            subtitle: 'Cheat sheet references for tcpdump capture command syntax and Wireshark filters.'
        },
        'quiz': {
            title: 'Protocol Quiz',
            subtitle: 'Test your packet analysis and troubleshooting knowledge with interactive challenges.'
        },
        'linkedin': {
            title: 'Share Accomplishment',
            subtitle: 'Draft a learning summary for LinkedIn to showcase your network traffic mastery.'
        }
    };

    // Update active navigation state
    navButtons.forEach(b => b.classList.remove('active'));
    tabPanels.forEach(p => p.classList.remove('active'));

    const activeBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
    const activePanel = document.getElementById(`tab-${tabId}`);

    if (activeBtn) activeBtn.classList.add('active');
    if (activePanel) activePanel.classList.add('active');

    // Update Topbar
    if (headers[tabId]) {
        tabTitle.textContent = headers[tabId].title;
        tabSubtitle.textContent = headers[tabId].subtitle;
    }
    
    state.currentTab = tabId;

    // Special handlers per tab entry
    if (tabId === 'quiz') {
        if (state.quizCompleted) {
            updateQuizResultScreen();
        }
    } else if (tabId === 'linkedin') {
        initLinkedInDraftDetails();
    }
}

// --- Search / Filtering Protocols ---
function initSearch() {
    const searchInput = document.getElementById('protocol-search');
    const cards = document.querySelectorAll('.protocol-card');
    const stats = document.getElementById('search-stats');

    searchInput.addEventListener('input', () => {
        const query = searchInput.value.toLowerCase().trim();
        let visibleCount = 0;

        cards.forEach(card => {
            const protoName = card.getAttribute('data-protocol').toLowerCase();
            const protoFullName = card.getAttribute('data-name').toLowerCase();
            const layer = card.getAttribute('data-layer').toLowerCase();
            const port = card.getAttribute('data-port').toLowerCase();

            const isMatch = protoName.includes(query) || 
                            protoFullName.includes(query) || 
                            layer.includes(query) || 
                            port.includes(query);

            if (isMatch || query === '') {
                card.style.display = 'flex';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        stats.textContent = `Showing ${visibleCount} of ${cards.length} protocols`;
    });
}

// --- Protocol Details Modal & Interactivity ---
function openProtocolDetails(protocolKey) {
    state.selectedProtocolKey = protocolKey;
    
    // Fetch info from existing card attributes
    const card = document.querySelector(`.protocol-card[data-protocol="${protocolKey}"]`);
    if (!card) return;

    const layer = card.getAttribute('data-layer');
    const port = card.getAttribute('data-port');
    const name = card.getAttribute('data-name');
    
    // We can pull the full description from our local database or cards.
    // For simplicity, we hardcoded overview in HTML or app.py. We'll populate dynamically.
    const overlay = document.getElementById('protocol-overlay');
    document.getElementById('overlay-layer').textContent = layer;
    document.getElementById('overlay-port').textContent = `Port: ${port}`;
    document.getElementById('overlay-name').textContent = name;
    
    // Find matching detailed overview description (will fetch or render)
    const descriptions = {
        "TCP": "Transmission Control Protocol (TCP) is a core transport protocol. It establish connections with a 3-way handshake, verifies delivery, handles timeouts and sequencing, and uses flow control. Perfect for file transfers and website delivery.",
        "UDP": "User Datagram Protocol (UDP) is a connectionless, best-effort transport protocol. Without connections, headers are small and transmission is ultra-fast. Commonly used in video calls, gaming, and name servers.",
        "ICMP": "Internet Control Message Protocol (ICMP) is a supporting Network Layer protocol. It carries diagnostics, traceroute pathing, error packets, and server redirects. It does not carry payload data.",
        "DNS": "Domain Name System (DNS) maps human-readable hostname queries to physical IP addresses, working like an internet address book. Runs primarily on port 53.",
        "HTTP": "Hypertext Transfer Protocol (HTTP) is the text-based protocol driving the World Wide Web. Requests and responses pass headers and files, but are entirely readable by default (insecure).",
        "HTTPS": "Hypertext Request Protocol Secure (HTTPS) wraps HTTP commands inside a cryptographic SSL/TLS handshake. Safe, private, and authenticated. Intercepted packets yield encrypted garbage."
    };
    
    document.getElementById('overlay-description').textContent = descriptions[protocolKey] || "";

    // Show / Hide relevant interactive section
    document.getElementById('tcp-handshake-section').style.display = (protocolKey === 'TCP') ? 'block' : 'none';
    document.getElementById('udp-flow-section').style.display = (protocolKey === 'UDP') ? 'block' : 'none';
    document.getElementById('icmp-types-section').style.display = (protocolKey === 'ICMP') ? 'block' : 'none';
    document.getElementById('dns-records-section').style.display = (protocolKey === 'DNS') ? 'block' : 'none';
    document.getElementById('http-methods-section').style.display = (protocolKey === 'HTTP') ? 'block' : 'none';
    document.getElementById('tls-handshake-section').style.display = (protocolKey === 'HTTPS') ? 'block' : 'none';

    // Populate arrays
    if (protocolKey === 'ICMP') {
        populateIcmpTable();
    } else if (protocolKey === 'DNS') {
        populateDnsTable();
    } else if (protocolKey === 'HTTP') {
        populateHttpTable();
    } else if (protocolKey === 'HTTPS') {
        populateTlsHandshake();
    }

    // Reset TCP and UDP state
    if (protocolKey === 'TCP') {
        setHandshakeStep(0);
    }
    if (protocolKey === 'UDP') {
        const stream = document.getElementById('udp-stream');
        const drips = stream.querySelectorAll('.udp-drip');
        drips.forEach(d => d.classList.remove('firing'));
    }

    overlay.classList.add('active');
}

function closeProtocolDetails() {
    document.getElementById('protocol-overlay').classList.remove('active');
}

// TCP Handshake Simulator Logic
function setHandshakeStep(step) {
    state.handshakeStep = step;
    
    const client = document.querySelector('.host-client');
    const server = document.querySelector('.host-server');
    const packet = document.getElementById('handshake-packet');
    const flagsLabel = document.getElementById('packet-flags-label');
    const clientState = document.getElementById('client-state');
    const serverState = document.getElementById('server-state');
    const descBox = document.getElementById('handshake-step-desc');
    
    // Clear active steps states
    document.querySelectorAll('.step-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`hs-step-${step}`).classList.add('active');
    
    // Clear packet styles
    packet.className = 'packet-arrow';
    client.className = 'node host-client';
    server.className = 'node host-server';

    if (step === 0) {
        client.classList.add('active');
        clientState.textContent = 'CLOSED';
        serverState.textContent = 'LISTEN';
        descBox.textContent = "Click '1. Send SYN' to start the TCP handshake process.";
    } 
    else if (step === 1) {
        client.classList.add('active');
        clientState.textContent = 'SYN_SENT';
        serverState.textContent = 'LISTEN';
        flagsLabel.textContent = 'SYN (Seq=100)';
        packet.classList.add('slide-right');
        descBox.textContent = "Step 1: The Client generates a random sequence number (Seq=100) and sends a packet with the SYN flag enabled. This signals its desire to synchronize connection parameters.";
    } 
    else if (step === 2) {
        server.classList.add('active');
        clientState.textContent = 'SYN_SENT';
        serverState.textContent = 'SYN_RCVD';
        flagsLabel.textContent = 'SYN-ACK (Seq=500, Ack=101)';
        packet.classList.add('slide-left');
        descBox.textContent = "Step 2: The Server acknowledges the client's request by adding 1 to the client's sequence number (Ack=101) and sending its own synchronization sequence (Seq=500). Flags sent: SYN-ACK.";
    } 
    else if (step === 3) {
        client.classList.add('established');
        server.classList.add('established');
        clientState.textContent = 'ESTABLISHED';
        serverState.textContent = 'ESTABLISHED';
        flagsLabel.textContent = 'ACK (Seq=101, Ack=501)';
        packet.classList.add('slide-right');
        descBox.textContent = "Step 3: The Client receives SYN-ACK. It replies with an ACK packet containing its next sequence number (Seq=101) and sets the acknowledgment to Server Seq + 1 (Ack=501). Sockets are now ESTABLISHED.";
    }
}

// UDP Simulation Firing
function fireUdpDatagram() {
    const stream = document.getElementById('udp-stream');
    const drips = stream.querySelectorAll('.udp-drip');
    
    // Toggle active animations
    drips.forEach(d => {
        d.classList.remove('firing');
        // Trigger reflow to restart CSS animation
        void d.offsetWidth; 
        d.classList.add('firing');
    });
}

// Populate ICMP Data
function populateIcmpTable() {
    const tbody = document.getElementById('icmp-table-body');
    tbody.innerHTML = '';
    
    PROTOCOL_DETAILS.ICMP.types.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="bold-cyan">${item.type}</td>
            <td class="bold-purple">${item.code}</td>
            <td><strong>${item.name}</strong></td>
            <td>${item.desc}</td>
        `;
        tbody.appendChild(row);
    });
}

// Populate DNS Record Data
function populateDnsTable() {
    const tbody = document.getElementById('dns-table-body');
    tbody.innerHTML = '';
    
    PROTOCOL_DETAILS.DNS.records.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="bold-cyan">${item.record}</td>
            <td><strong>${item.fullname}</strong></td>
            <td>${item.desc}</td>
        `;
        tbody.appendChild(row);
    });
}

// Populate HTTP Method Data
function populateHttpTable() {
    const tbody = document.getElementById('http-table-body');
    tbody.innerHTML = '';
    
    PROTOCOL_DETAILS.HTTP.methods.forEach(item => {
        const row = document.createElement('tr');
        const colorClass = item.idempotent === 'YES' ? 'bold-cyan' : 'bold-purple';
        row.innerHTML = `
            <td class="bold-cyan">${item.method}</td>
            <td>${item.desc}</td>
            <td class="${colorClass}">${item.idempotent}</td>
        `;
        tbody.appendChild(row);
    });
}

// Populate TLS Timeline List
function populateTlsHandshake() {
    const container = document.getElementById('tls-timeline-steps');
    container.innerHTML = '';
    
    PROTOCOL_DETAILS.HTTPS.tlsHandshake.forEach(item => {
        const block = document.createElement('div');
        block.className = 'tls-timeline-item';
        block.innerHTML = `
            <div class="tls-item-title">${item.step}</div>
            <div class="tls-item-desc">${item.desc}</div>
        `;
        container.appendChild(block);
    });
}


// --- PCAP Binary Anatomy Explorer ---
function initPcapHexExplorer() {
    const hexBytes = document.querySelectorAll('.hex-byte');
    const idleMsg = document.getElementById('decoder-idle-msg');
    const activePanel = document.getElementById('decoder-active-info');
    const fieldLabel = document.getElementById('decoder-field-name');
    const blockLabel = document.getElementById('decoder-block-name');
    const sizeLabel = document.getElementById('decoder-field-size');
    const hexLabel = document.getElementById('decoder-field-hex');
    const descLabel = document.getElementById('decoder-field-desc');

    const fieldsDb = {
        "magic": {
            name: "Magic Number (Identification)",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "d4 c3 b2 a1",
            desc: "The magic number identifies the capture format. '0xd4c3b2a1' indicates standard libpcap format with microsecond timestamps. Reading it backwards matches Little-Endian architectures."
        },
        "version": {
            name: "Version Number (Major / Minor)",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "02 00 04 00",
            desc: "Tells the reader which version of libpcap specifications was used to write the file. Standard current format is version 2.4 (written in little-endian as 0x0002 and 0x0004)."
        },
        "timezone": {
            name: "Timezone Correction Offset",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "00 00 00 00",
            desc: "Timezone correction offset in seconds. Historically used to offset timestamps to local timezone, but modern captures usually write 0s denoting UTC."
        },
        "sigfigs": {
            name: "Timestamp Accuracy (Sigfigs)",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "00 00 00 00",
            desc: "Significant figures of timestamps. Typically set to 0. It indicates the resolution and precision accuracy of timestamps added by capture software."
        },
        "snaplen": {
            name: "Snapshot Length Limit (Snaplen)",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "ff ff 00 00",
            desc: "The maximum amount of bytes captured per packet. '0x0000ffff' (65,535 bytes) is standard, indicating the writer captures full Ethernet frames without slicing payloads."
        },
        "network": {
            name: "Data Link Type (Network Type)",
            block: "GLOBAL FILE HEADER",
            size: "4 bytes",
            hex: "01 00 00 00",
            desc: "Specifies the link layer protocol header. '1' translates to DLT_EN10MB, signaling standard 10/100/1000 Megabit Ethernet headers. Let readers know packets start with Ethernet MACs."
        },
        "ts-sec": {
            name: "Epoch Timestamp (Seconds)",
            block: "PACKET METADATA HEADER",
            size: "4 bytes",
            hex: "d8 1a 8c 66",
            desc: "Timestamp indicating when the packet was captured, stored in standard Unix epoch format. '0x668c1ad8' translates to June 2026."
        },
        "ts-usec": {
            name: "Epoch Timestamp (Microseconds)",
            block: "PACKET METADATA HEADER",
            size: "4 bytes",
            hex: "20 4e 0a 00",
            desc: "The fractional part of the capture timestamp. Stored in microseconds to provide high-precision sorting of packets passing through the interface."
        },
        "incl-len": {
            name: "Captured Length (Slice Length)",
            block: "PACKET METADATA HEADER",
            size: "4 bytes",
            hex: "3c 00 00 00",
            desc: "The length of the packet data actually saved to the disk. '0x0000003c' (60 bytes in decimal) matches the size of the trailing payload headers."
        },
        "orig-len": {
            name: "Original Length (Wire Length)",
            block: "PACKET METADATA HEADER",
            size: "4 bytes",
            hex: "3c 00 00 00",
            desc: "The actual size of the packet as it crossed the physical link. If snaplen is exceeded, orig-len will be larger than the captured length (incl-len)."
        },
        "eth-dest": {
            name: "Destination MAC Address",
            block: "LAYER 2: ETHERNET HEADER",
            size: "6 bytes",
            hex: "00 0c 29 3e 5b 20",
            desc: "MAC address of the network interface interface cards targeting this frame. E.g., VMware virtual card: 00:0C:29:3E:5B:20."
        },
        "eth-src": {
            name: "Source MAC Address",
            block: "LAYER 2: ETHERNET HEADER",
            size: "6 bytes",
            hex: "00 50 56 c0 00 08",
            desc: "Physical MAC address of the device that originally transmitted this frame. E.g., 00:50:56:C0:00:08."
        },
        "eth-type": {
            name: "EtherType Field",
            block: "LAYER 2: ETHERNET HEADER",
            size: "2 bytes",
            hex: "08 00",
            desc: "Identifies the Layer 3 protocol encapsulated inside the frame. '0x0800' indicates that the next bytes should be parsed as an IPv4 packet."
        },
        "ip-ver": {
            name: "IP Version & Header Length",
            block: "LAYER 3: IPv4 HEADER",
            size: "1 byte",
            hex: "45",
            desc: "First nibble '4' represents IPv4. Second nibble '5' represents Internet Header Length (IHL) of 5 words (5 * 4 = 20 bytes)."
        },
        "ip-tos": {
            name: "Type of Service / DSCP",
            block: "LAYER 3: IPv4 HEADER",
            size: "1 byte",
            hex: "00",
            desc: "Used for packet prioritization and Quality of Service (QoS) markings. Set to 0 indicates standard best-effort routing."
        },
        "ip-len": {
            name: "Total Packet Length",
            block: "LAYER 3: IPv4 HEADER",
            size: "2 bytes",
            hex: "00 28",
            desc: "Total size of the IPv4 packet (IP header + L4 payload). '0x0028' translates to 40 bytes."
        },
        "ip-id": {
            name: "Identification / Fragment ID",
            block: "LAYER 3: IPv4 HEADER",
            size: "2 bytes",
            hex: "1b 4f",
            desc: "Unique ID assigned to the packet, helping reassemble IP packets that were fragmented into smaller slices across router boundaries."
        },
        "ip-flag": {
            name: "Fragmentation Flags & Offset",
            block: "LAYER 3: IPv4 HEADER",
            size: "2 bytes",
            hex: "40 00",
            desc: "Control flags relating to fragmentation. '0x4000' translates to the 'Don't Fragment' (DF) flag set to 1, instructing routers not to slice the packet."
        },
        "ip-ttl": {
            name: "Time-To-Live (TTL)",
            block: "LAYER 3: IPv4 HEADER",
            size: "1 byte",
            hex: "40",
            desc: "The maximum hops a packet can take. Decoded as '0x40' (64 in decimal). Each router decrements this by 1. If it hits 0, packet is discarded to avoid infinite loops."
        },
        "ip-proto": {
            name: "Layer 4 Protocol Indicator",
            block: "LAYER 3: IPv4 HEADER",
            size: "1 byte",
            hex: "01",
            desc: "Tells the IP engine what transport protocol payload follows the IP header. '1' translates to ICMP. (6 is TCP, 17 is UDP)."
        },
        "ip-checksum": {
            name: "Header Checksum Verification",
            block: "LAYER 3: IPv4 HEADER",
            size: "2 bytes",
            hex: "ec 27",
            desc: "A checksum value used for error-checking the IP header. If corrupt, router immediately drops the packet."
        },
        "ip-src": {
            name: "Source IP Address",
            block: "LAYER 3: IPv4 HEADER",
            size: "4 bytes",
            hex: "c0 a8 01 32",
            desc: "Logical IPv4 address of the sender. Decoded byte-by-byte: 0xc0 (192), 0xa8 (168), 0x01 (1), 0x32 (50). Yields: 192.168.1.50."
        },
        "ip-dest": {
            name: "Destination IP Address",
            block: "LAYER 3: IPv4 HEADER",
            size: "4 bytes",
            hex: "08 08 08 08",
            desc: "Logical IPv4 address of the recipient. Decoded byte-by-byte: 0x08.0x08.0x08.0x08. Yields: 8.8.8.8 (Google's Public DNS)."
        },
        "icmp-type": {
            name: "ICMP Message Type",
            block: "ICMP PAYLOAD",
            size: "1 byte",
            hex: "08",
            desc: "Identifies the core ICMP request purpose. '08' represents an Echo (Ping) Request, initiating a request for response."
        },
        "icmp-code": {
            name: "ICMP Code Sub-indicator",
            block: "ICMP PAYLOAD",
            size: "1 byte",
            hex: "00",
            desc: "Sub-code further detailing the ICMP type. For Echo Request, code is always '00'."
        },
        "icmp-chk": {
            name: "ICMP Checksum",
            block: "ICMP PAYLOAD",
            size: "2 bytes",
            hex: "f7 ff",
            desc: "Verification hash covering the ICMP packet headers and payload to verify transmission integrity."
        },
        "icmp-id": {
            name: "ICMP Identifier",
            block: "ICMP PAYLOAD",
            size: "2 bytes",
            hex: "00 01",
            desc: "A unique identifier assigned by ping client to differentiate between multiple concurrent ping processes."
        },
        "icmp-seq": {
            name: "ICMP Sequence Number",
            block: "ICMP PAYLOAD",
            size: "2 bytes",
            hex: "00 01",
            desc: "Incremental sequence number to pair ping requests and matching ping response replies. Starts at 1."
        },
        "icmp-data": {
            name: "ICMP Timestamp Payload Data",
            block: "ICMP PAYLOAD",
            size: "10 bytes",
            hex: "61 62 63 64 65 66 67 68 69 6a",
            desc: "Optional byte payload padding typical ping programs send. Decodes in ASCII to alphabetical letters: 'abcdefghij'."
        }
    };

    hexBytes.forEach(byte => {
        byte.addEventListener('mouseenter', () => {
            const fieldKey = byte.getAttribute('data-field');
            if (!fieldKey || !fieldsDb[fieldKey]) return;
            
            // Highlight all bytes in the same group
            const groupBytes = document.querySelectorAll(`.hex-byte[data-field="${fieldKey}"]`);
            groupBytes.forEach(b => b.classList.add('highlight'));

            // Show decoder panel info
            const info = fieldsDb[fieldKey];
            fieldLabel.textContent = info.name;
            blockLabel.textContent = info.block;
            sizeLabel.textContent = info.size;
            hexLabel.textContent = info.hex;
            descLabel.textContent = info.desc;

            // Adjust color theme badge on decoder card depending on block
            blockLabel.className = 'decoder-block-badge';
            if (info.block.includes('GLOBAL')) {
                blockLabel.style.borderColor = 'var(--accent-cyan)';
                blockLabel.style.color = 'var(--accent-cyan)';
            } else if (info.block.includes('METADATA')) {
                blockLabel.style.borderColor = '#94a3b8';
                blockLabel.style.color = '#f8fafc';
            } else if (info.block.includes('ETHERNET')) {
                blockLabel.style.borderColor = '#f97316';
                blockLabel.style.color = '#f97316';
            } else if (info.block.includes('IPv4')) {
                blockLabel.style.borderColor = '#3b82f6';
                blockLabel.style.color = '#3b82f6';
            } else if (info.block.includes('ICMP')) {
                blockLabel.style.borderColor = 'var(--accent-emerald)';
                blockLabel.style.color = 'var(--accent-emerald)';
            }

            idleMsg.style.display = 'none';
            activePanel.style.display = 'block';
        });

        byte.addEventListener('mouseleave', () => {
            const fieldKey = byte.getAttribute('data-field');
            const groupBytes = document.querySelectorAll(`.hex-byte[data-field="${fieldKey}"]`);
            groupBytes.forEach(b => b.classList.remove('highlight'));
            
            // Return to default prompt
            activePanel.style.display = 'none';
            idleMsg.style.display = 'block';
        });
    });
}


// --- Wireshark Filter Sandbox Parser/Validator ---
function initSandboxFilter() {
    const input = document.getElementById('sandbox-filter-input');
    
    // Validate trigger when user presses Enter
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            validateSandboxFilter();
        }
    });
}

function validateSandboxFilter() {
    const input = document.getElementById('sandbox-filter-input');
    const filter = input.value.trim();
    const respContainer = document.getElementById('sandbox-response');

    if (!filter) {
        respContainer.innerHTML = `
            <div class="sandbox-response-status idle">
                <span class="status-icon">⚙️</span>
                <span>Enter a query to validate your display filter syntax.</span>
            </div>`;
        return;
    }

    // Wireshark Validation Mock Logic
    let statusClass = 'valid';
    let icon = '✅';
    let header = 'Valid Wireshark Filter Expression';
    let feedback = '';

    // Check for single equals (Common mistake)
    if (filter.includes('=') && !filter.includes('==') && !filter.includes('!=') && !filter.includes('>=') && !filter.includes('<=')) {
        statusClass = 'invalid';
        icon = '❌';
        header = 'Syntax Error: Invalid Comparison Operator';
        feedback = 'Wireshark filters use double equals (<code>==</code>) to evaluate equality. Replace the single equals with double equals. <br><em>Example:</em> <code>ip.addr == 192.168.1.1</code>';
    }
    // Check for tcpdump syntax in sandbox (Common mistake)
    else if (filter.startsWith('tcpdump ') || filter.includes('src net') || filter.includes('-i any') || filter.includes('-w ')) {
        statusClass = 'invalid';
        icon = '❌';
        header = 'Syntax Error: CLI Command in Display Filter';
        feedback = 'You entered a tcpdump command line statement. Wireshark display filters use syntax properties. E.g. replace <code>tcpdump port 80</code> with <code>tcp.port == 80</code>.';
    }
    // Analyze and match valid structures
    else {
        // Token explanation mappings
        const interpretations = [];
        
        // Protocol matches
        if (/\b(tcp)\b/i.test(filter)) interpretations.push("filters for <strong>TCP protocol</strong> packets");
        if (/\b(udp)\b/i.test(filter)) interpretations.push("filters for <strong>UDP protocol</strong> packets");
        if (/\b(dns)\b/i.test(filter)) interpretations.push("filters for <strong>DNS queries & responses</strong>");
        if (/\b(http)\b/i.test(filter)) interpretations.push("filters for <strong>HTTP protocol</strong> traffic");
        if (/\b(ssl|tls)\b/i.test(filter)) interpretations.push("filters for <strong>SSL/TLS encrypted</strong> handshakes");
        if (/\b(icmp)\b/i.test(filter)) interpretations.push("filters for <strong>ICMP diagnostic messages</strong>");
        
        // Parameters matches
        if (filter.includes('ip.addr')) interpretations.push("matches packets where the <strong>source or destination IP</strong> matches");
        if (filter.includes('ip.src')) interpretations.push("isolates packets originating from <strong>source IP</strong>");
        if (filter.includes('ip.dst')) interpretations.push("isolates packets heading to <strong>destination IP</strong>");
        if (filter.includes('tcp.port') || filter.includes('udp.port')) interpretations.push("inspects standard <strong>L4 port numbers</strong>");
        if (filter.includes('http.request.method')) interpretations.push("filters by the specific <strong>HTTP request method (GET, POST, etc.)</strong>");
        
        // Operators
        if (filter.includes('&&') || filter.includes(' and ')) interpretations.push("combines criteria using a logical <strong>AND</strong> statement");
        if (filter.includes('||') || filter.includes(' or ')) interpretations.push("combines criteria using a logical <strong>OR</strong> statement");
        if (filter.includes('!') || filter.includes('not ')) interpretations.push("negates matching checks using logical <strong>NOT</strong>");

        if (interpretations.length > 0) {
            feedback = `Filter syntax is syntax-correct! This command: <ul>` + 
                       interpretations.map(i => `<li>${i}</li>`).join('') + 
                       `</ul>`;
        } else {
            // General fallback verification
            // Let's verify standard formats: token containing dot or equality
            if (filter.match(/^[a-z0-9\._]+(\s*(==|!=|>|<|>=|<=)\s*("[^"]+"|[0-9a-f:\.]+))?(\s*(&&|\|\||and|or)\s*[a-z0-9\._]+(\s*(==|!=|>|<|>=|<=)\s*("[^"]+"|[0-9a-f:\.]+))?)*$/i)) {
                feedback = `Filter formatting is syntactically valid! The parser identifies standard parameters. Ready to execute in Wireshark display console.`;
            } else {
                statusClass = 'invalid';
                icon = '❌';
                header = 'Syntax Warning: Unrecognized Filter Parameter';
                feedback = `This filter doesn't match standard Wireshark syntax. Ensure fields are dot-separated (like <code>ip.src</code> or <code>tcp.flags.syn</code>) and logical operators are correct.`;
            }
        }
    }

    respContainer.innerHTML = `
        <div class="sandbox-response-status ${statusClass}">
            <span class="status-icon">${icon}</span>
            <div>
                <strong>${header}</strong>
                <p class="sandbox-feedback">${feedback}</p>
            </div>
        </div>`;
}

// Copy Code Clipboard
function copyCode(btn, codeText) {
    navigator.clipboard.writeText(codeText).then(() => {
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        
        showToast('Command copied to clipboard!');
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(err => {
        console.error('Clipboard copy failed', err);
    });
}

function showToast(message) {
    const toast = document.getElementById('toast-notify');
    toast.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2500);
}


// --- Quiz Section State Machine ---
function fetchQuizQuestions() {
    fetch('/api/quiz')
        .then(response => response.json())
        .then(data => {
            state.quizQuestions = data;
        })
        .catch(err => {
            console.error('Failed to load quiz from Flask API, implementing fallback questions', err);
            // Standard fallback if API errors out
            state.quizQuestions = [
                {
                    "id": 1,
                    "question": "Which transport layer protocol uses a 3-way handshake to establish a connection?",
                    "options": ["UDP", "TCP", "ICMP", "DNS"],
                    "correct": 1,
                    "explanation": "TCP establishes connections with SYN, SYN-ACK, ACK handshake packets."
                }
            ];
        });
}

function startQuiz() {
    state.quizScore = 0;
    state.currentQuestionIndex = 0;
    state.quizCompleted = false;
    state.selectedAnswer = null;
    state.hasSubmittedAnswer = false;
    state.quizStartTime = new Date();

    document.getElementById('quiz-intro-state').style.display = 'none';
    document.getElementById('quiz-result-state').style.display = 'none';
    document.getElementById('quiz-active-state').style.display = 'block';

    // Start timer interval
    if (state.quizTimerInterval) clearInterval(state.quizTimerInterval);
    state.quizTimerInterval = setInterval(updateQuizTimer, 1000);

    renderQuizQuestion();
}

function updateQuizTimer() {
    if (!state.quizStartTime) return;
    const elapsed = Math.floor((new Date() - state.quizStartTime) / 1000);
    const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const secs = String(elapsed % 60).padStart(2, '0');
    document.getElementById('quiz-timer').textContent = `${mins}:${secs}`;
}

function renderQuizQuestion() {
    state.selectedAnswer = null;
    state.hasSubmittedAnswer = false;

    const q = state.quizQuestions[state.currentQuestionIndex];
    
    document.getElementById('quiz-progress-text').textContent = `Question ${state.currentQuestionIndex + 1} of ${state.quizQuestions.length}`;
    
    // Update progress bar
    const progressPct = ((state.currentQuestionIndex + 1) / state.quizQuestions.length) * 100;
    document.getElementById('quiz-progress-bar').style.width = `${progressPct}%`;
    
    document.getElementById('quiz-question-text').textContent = q.question;
    
    // Render Options list
    const optionsContainer = document.getElementById('quiz-options-list');
    optionsContainer.innerHTML = '';
    
    q.options.forEach((opt, idx) => {
        const btn = document.createElement('button');
        btn.className = 'quiz-opt-btn';
        btn.innerHTML = opt;
        btn.addEventListener('click', () => selectQuizAnswer(idx));
        optionsContainer.appendChild(btn);
    });

    // Reset feedback panel and actions
    document.getElementById('quiz-feedback-box').style.display = 'none';
    const actionBtn = document.getElementById('next-q-btn');
    actionBtn.textContent = 'Submit Answer';
    actionBtn.disabled = true;
}

function selectQuizAnswer(idx) {
    if (state.hasSubmittedAnswer) return;
    
    state.selectedAnswer = idx;
    
    const optionButtons = document.querySelectorAll('.quiz-opt-btn');
    optionButtons.forEach((btn, i) => {
        if (i === idx) {
            btn.classList.add('selected');
        } else {
            btn.classList.remove('selected');
        }
    });

    document.getElementById('next-q-btn').disabled = false;
}

function submitOrNextQuestion() {
    const actionBtn = document.getElementById('next-q-btn');
    
    if (!state.hasSubmittedAnswer) {
        // Submit Mode
        state.hasSubmittedAnswer = true;
        
        const q = state.quizQuestions[state.currentQuestionIndex];
        const isCorrect = (state.selectedAnswer === q.correct);
        
        if (isCorrect) {
            state.quizScore++;
        }
        
        // Render classes
        const optionButtons = document.querySelectorAll('.quiz-opt-btn');
        optionButtons.forEach((btn, i) => {
            btn.disabled = true;
            if (i === q.correct) {
                btn.classList.add('correct');
            } else if (i === state.selectedAnswer) {
                btn.classList.add('incorrect');
            }
        });

        // Show Feedback Details
        const feedbackBox = document.getElementById('quiz-feedback-box');
        const indicator = document.getElementById('feedback-indicator');
        const explanation = document.getElementById('feedback-explanation');
        
        feedbackBox.className = 'quiz-feedback-box ' + (isCorrect ? 'is-correct' : 'is-incorrect');
        document.getElementById('feedback-indicator').querySelector('.status-msg').textContent = isCorrect ? 'CORRECT' : 'INCORRECT';
        explanation.textContent = q.explanation;
        feedbackBox.style.display = 'block';

        // Toggle action button label
        const isLastQuestion = (state.currentQuestionIndex === state.quizQuestions.length - 1);
        actionBtn.textContent = isLastQuestion ? 'View Results' : 'Next Question';
    } 
    else {
        // Next Question Mode
        state.currentQuestionIndex++;
        
        if (state.currentQuestionIndex < state.quizQuestions.length) {
            renderQuizQuestion();
        } else {
            // End of Quiz
            endQuizChallenge();
        }
    }
}

function endQuizChallenge() {
    clearInterval(state.quizTimerInterval);
    state.quizCompleted = true;
    
    // Save to local storage for persistence across tabs
    localStorage.setItem('packetlens_quiz_score', state.quizScore);
    
    updateQuizResultScreen();
}

function updateQuizResultScreen() {
    document.getElementById('quiz-intro-state').style.display = 'none';
    document.getElementById('quiz-active-state').style.display = 'none';
    document.getElementById('quiz-result-state').style.display = 'block';

    const score = state.quizScore;
    const total = state.quizQuestions.length || 8;
    const accuracy = Math.round((score / total) * 100);

    document.getElementById('score-raw').textContent = score;
    document.getElementById('score-percent').textContent = `${accuracy}% Accuracy`;

    // Determine ranking
    let badgeText = '';
    let titleText = '';
    let msgText = '';

    if (score === total) {
        badgeText = 'CERTIFIED PACKET MASTER';
        titleText = 'Protocol Analyst (L7)';
        msgText = 'Absolute perfection! You understand Layer 3/4/7 flow diagnostics and display syntax better than some network administrators.';
    } else if (score >= 6) {
        badgeText = 'EXPERT ANALYST';
        titleText = 'Capture Specialist (L4)';
        msgText = 'Excellent performance! You demonstrate solid command of packet filtering, tcpdump mechanics, and global PCAP headers.';
    } else if (score >= 4) {
        badgeText = 'PRACTITIONER';
        titleText = 'Security Cadet (L3)';
        msgText = 'Good grasp of network principles. Review some of the PCAP global headers and TCP handshake steps to lock down your networking foundations.';
    } else {
        badgeText = 'NOVICE DECODER';
        titleText = 'Frame Spectator (L2)';
        msgText = 'A solid learning start! Continue exploring the Protocol Explorer and Cheat Sheets tabs to learn basic port and flag behaviors.';
    }

    const rankBadge = document.getElementById('result-status-badge');
    rankBadge.textContent = badgeText;
    document.getElementById('result-rank-title').textContent = titleText;
    document.getElementById('result-message').textContent = msgText;
    
    // Update score preview inside LinkedIn post tab
    initLinkedInDraftDetails();
}

function resetQuiz() {
    state.quizCompleted = false;
    localStorage.removeItem('packetlens_quiz_score');
    startQuiz();
}


// --- LinkedIn Post Draft Generator ---
function initLinkedInDraftDetails() {
    const scoreVal = localStorage.getItem('packetlens_quiz_score');
    const scorePreview = document.getElementById('link-score-preview');
    const scoreStatus = document.getElementById('link-score-status');

    if (scoreVal !== null) {
        scorePreview.textContent = `Quiz Score: ${scoreVal}/8`;
        scoreStatus.textContent = '✅ Score integrated. Ready to feature in post compiled output.';
    } else {
        scorePreview.textContent = `Quiz Score: Not Taken`;
        scoreStatus.textContent = '❌ Take the quiz first to automatically display accuracy stats.';
    }
}

function generateLinkedInPost() {
    // Get checked topics
    const checkedCheckboxes = document.querySelectorAll('.topic-checkbox:checked');
    const learnedTopics = Array.from(checkedCheckboxes).map(cb => cb.value);
    
    // Get score
    const scoreVal = localStorage.getItem('packetlens_quiz_score') || 0;
    
    // Get persona tone
    const toneElement = document.querySelector('input[name="tone"]:checked');
    const selectedTone = toneElement ? toneElement.value : 'enthusiastic';

    if (learnedTopics.length === 0) {
        showToast('Please select at least one topic learned!');
        return;
    }

    // Call Flask backend route to compile post
    fetch('/api/generate-post', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            score: parseInt(scoreVal, 10),
            total: 8,
            learned: learnedTopics,
            style: selectedTone
        })
    })
    .then(res => res.json())
    .then(data => {
        const txtArea = document.getElementById('linkedin-post-output');
        txtArea.value = data.post;
        showToast('Accomplishment post generated!');
    })
    .catch(err => {
        console.error('Failed to compile draft post from Flask API', err);
        showToast('Failed to compile post. Running local fallback.');
        
        // Simple local fallback if HTTP fails
        const txtArea = document.getElementById('linkedin-post-output');
        txtArea.value = `🎯 Just leveled up my network skills with PacketLens! I learned about ${learnedTopics.join(', ')}. My Quiz score: ${scoreVal}/8. #cybersecurity #networking`;
    });
}

function copyLinkedInPost() {
    const txtArea = document.getElementById('linkedin-post-output');
    const btn = document.getElementById('btn-copy-post');
    const btnText = document.getElementById('copy-btn-text');

    if (!txtArea.value) {
        showToast('Please generate a post first!');
        return;
    }

    navigator.clipboard.writeText(txtArea.value).then(() => {
        btn.classList.add('copied-state');
        btnText.textContent = 'Copied!';
        showToast('LinkedIn post copied to clipboard!');

        setTimeout(() => {
            btn.classList.remove('copied-state');
            btnText.textContent = 'Copy to Clipboard';
        }, 2000);
    }).catch(err => {
        console.error('Copy to clipboard failed', err);
        showToast('Could not copy post. Please copy manually.');
    });
}
