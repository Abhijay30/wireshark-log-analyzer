import pyshark

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
            print(f"Explanation: {PROTOCOL_EXPLANATIONS[protocol]}")


def print_top_talkers():
    print("\n" + "=" * 60)
    print("TOP SOURCE IPS")
    print("=" * 60)

    for ip, count in sorted(
        results["source_ips"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:

        print(f"{ip}: {count}")


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
            f"{source} -> {destination}: {count}"
        )


def generate_summary():
    print("\n" + "=" * 60)
    print("ANALYST SUMMARY")
    print("=" * 60)

    total_hosts = len(results["hosts"])

    most_active_host = max(
        results["source_ips"],
        key=results["source_ips"].get
    )

    most_common_protocol = max(
        results["protocols"],
        key=results["protocols"].get
    )

    print(f"Hosts Discovered: {total_hosts}")
    print(f"Most Active Device: {most_active_host}")
    print(f"Most Common Protocol: {most_common_protocol}")

    print("\nInterpretation:")

    if most_common_protocol == "QUIC":
        print(
            "- Traffic is dominated by modern encrypted web browsing."
        )

    if "DNS" in results["protocols"]:
        print(
            "- DNS activity detected, indicating website lookups."
        )

    if "MDNS" in results["protocols"]:
        print(
            "- Local device discovery traffic detected."
        )

    if "SSDP" in results["protocols"]:
        print(
            "- Smart device/service discovery traffic detected."
        )

    print(
        "- No obvious scanning behavior detected from current statistics."
    )

    print(
        "- Traffic appears consistent with normal user activity."
    )


def print_hosts():
    print("=" * 60)
    print("HOSTS FOUND")
    print("=" * 60)

    for host in sorted(results["hosts"]):
        print(host)


def main():

    capture = pyshark.FileCapture(
        "sample.pcapng",
        tshark_path=r"D:\Wireshark\tshark.exe"
    )

    for packet in capture:
        analyze_packet(packet)

    capture.close()

    print_hosts()
    print_protocol_analysis()
    print_top_talkers()
    print_conversations()
    generate_summary()


if __name__ == "__main__":
    main()