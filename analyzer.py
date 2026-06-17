import pyshark
import ipaddress

results = {
    "hosts": set(),
    "protocols": {},
    "source_ips": {},
    "conversations": {}
}

PROTOCOL_EXPLANATIONS = {
    "QUIC": "Modern encrypted web traffic. Commonly used by Chrome, YouTube, and Google services.",
    "TLS": "Encrypted HTTPS communication.",
    "TCP": "Reliable transport protocol used by many internet services.",
    "DNS": "Domain name lookups used to translate website names into IP addresses.",
    "MDNS": "Local network device discovery.",
    "SSDP": "Used by devices to discover services on the local network.",
    "DHCP": "Used to automatically assign IP addresses.",
    "ARP": "Maps IP addresses to MAC addresses on local networks.",
    "LLMNR": "Local hostname resolution protocol.",
    "NBNS": "NetBIOS name resolution traffic.",
    "NTP": "Network time synchronization traffic."
}


def analyze_packet(packet):
    try:
        if hasattr(packet, "ip"):
            source = packet.ip.src
            destination = packet.ip.dst

            # Host Discovery
            results["hosts"].add(source)
            results["hosts"].add(destination)

            # Top Talkers
            results["source_ips"][source] = (
                results["source_ips"].get(source, 0) + 1
            )

            # Conversation Analysis
            conversation = (source, destination)

            results["conversations"][conversation] = (
                results["conversations"].get(conversation, 0) + 1
            )

        # Protocol Analysis
        protocol = packet.highest_layer

        results["protocols"][protocol] = (
            results["protocols"].get(protocol, 0) + 1
        )

    except Exception:
        pass


def classify_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip == "255.255.255.255":
            return "Broadcast"

        if ip_obj.is_multicast:
            return "Multicast"

        if ip_obj.is_private:
            return "Internal"

        return "External"

    except ValueError:
        return "Unknown"


def get_host_statistics():
    stats = {
        "Internal": 0,
        "External": 0,
        "Multicast": 0,
        "Broadcast": 0,
        "Unknown": 0
    }

    for host in results["hosts"]:
        category = classify_ip(host)
        stats[category] += 1

    return stats


def get_most_active_internal_host():
    internal_hosts = {}

    for ip, count in results["source_ips"].items():
        if classify_ip(ip) == "Internal":
            internal_hosts[ip] = count

    if not internal_hosts:
        return None

    return max(
        internal_hosts,
        key=internal_hosts.get
    )


def generate_findings():

    findings = []

    if "QUIC" in results["protocols"]:
        findings.append(
            "[INFO] Heavy encrypted web browsing traffic detected."
        )

    if "DNS" in results["protocols"]:
        findings.append(
            "[INFO] DNS lookups observed."
        )

    if "MDNS" in results["protocols"]:
        findings.append(
            "[INFO] Local device discovery traffic observed."
        )

    if "SSDP" in results["protocols"]:
        findings.append(
            "[INFO] Smart device discovery traffic observed."
        )

    if "TELNET" in results["protocols"]:
        findings.append(
            "[WARNING] Insecure Telnet traffic detected."
        )

    if "FTP" in results["protocols"]:
        findings.append(
            "[WARNING] FTP traffic detected."
        )

    return findings


def print_executive_summary():

    stats = get_host_statistics()

    print("\n" + "=" * 60)
    print("EXECUTIVE SUMMARY")
    print("=" * 60)

    risk = "LOW"
    if "TELNET" in results["protocols"]:
        risk = "HIGH"
    elif "FTP" in results["protocols"]:
        risk = "MEDIUM"

    print(f"Risk Level: {risk}")

    print("\nWhat Happened?")

    if "QUIC" in results["protocols"]:
        print(
            "- Heavy encrypted web browsing detected."
        )

    if "DNS" in results["protocols"]:
        print(
            "- Website lookups were observed."
        )

    if "MDNS" in results["protocols"]:
        print(
            "- Local device discovery traffic detected."
        )

    most_active_internal = get_most_active_internal_host()

    if most_active_internal:
        print(
            f"- Most active internal device: "
            f"{most_active_internal}"
        )

    print(
        f"\nInternal Devices: "
        f"{stats['Internal']}"
    )

    print(
        f"External Devices: "
        f"{stats['External']}"
    )


def print_key_findings():

    print("\n" + "=" * 60)
    print("KEY FINDINGS")
    print("=" * 60)

    findings = generate_findings()

    if not findings:
        print("[INFO] No significant findings.")

    for finding in findings:
        print(finding)


def print_risk_assessment():

    print("\n" + "=" * 60)
    print("RISK ASSESSMENT")
    print("=" * 60)

    risk = "LOW"

    if "TELNET" in results["protocols"]:
        risk = "HIGH"

    elif "FTP" in results["protocols"]:
        risk = "MEDIUM"

    print(risk)

    if risk == "LOW":
        print(
            "Traffic appears consistent with normal user activity."
        )

    elif risk == "MEDIUM":
        print(
            "Potentially insecure protocols detected."
        )

    else:
        print(
            "High-risk protocols detected."
        )


def print_technical_details_header():

    stats = get_host_statistics()

    print("\n" + "=" * 60)
    print("TECHNICAL DETAILS")
    print("=" * 60)

    print(f"Internal Hosts : {stats['Internal']}")
    print(f"External Hosts : {stats['External']}")
    print(f"Multicast Hosts: {stats['Multicast']}")
    print(f"Broadcast Hosts: {stats['Broadcast']}")
    


def print_protocol_analysis():
    print("\n" + "=" * 60)
    print("PROTOCOL ANALYSIS")
    print("=" * 60)

    for protocol, count in sorted(
        results["protocols"].items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"\n{protocol}: {count}")

        if protocol in PROTOCOL_EXPLANATIONS:
            print(
                f"Explanation: "
                f"{PROTOCOL_EXPLANATIONS[protocol]}"
            )


def print_top_talkers():
    print("\n" + "=" * 60)
    print("TOP SOURCE IPS")
    print("=" * 60)

    for ip, count in sorted(
        results["source_ips"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:

        category = classify_ip(ip)

        print(
            f"{ip} ({category}) : {count}"
        )


def print_conversations():
    print("\n" + "=" * 60)
    print("TOP CONVERSATIONS")
    print("=" * 60)

    for conversation, count in sorted(
        results["conversations"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:

        source, destination = conversation

        print(
            f"{source} -> {destination} : {count}"
        )

def main():
    capture = pyshark.FileCapture(
        "sample.pcapng",
        tshark_path=r"D:\Wireshark\tshark.exe"
    )

    for packet in capture:
        analyze_packet(packet)

    capture.close()

    print_executive_summary()
    print_key_findings()
    print_risk_assessment()
    print()
    print_technical_details_header()

    print_top_talkers()
    print_conversations()
    print_protocol_analysis()


if __name__ == "__main__":
    main()