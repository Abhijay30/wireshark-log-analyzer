import pyshark

results = {
    "hosts": set(),
    "protocols": {},
    "source_ips": {}
}


def analyze_packet(packet):
    try:
        # --------------------------
        # IP Analysis
        # --------------------------
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

        # --------------------------
        # Protocol Analysis
        # --------------------------
        protocol = packet.highest_layer

        results["protocols"][protocol] = (
            results["protocols"].get(protocol, 0) + 1
        )

    except Exception:
        pass


def print_report():
    print("\n" + "=" * 50)
    print("HOSTS FOUND")
    print("=" * 50)

    for host in sorted(results["hosts"]):
        print(host)

    print("\n" + "=" * 50)
    print("PROTOCOL STATISTICS")
    print("=" * 50)

    for protocol, count in sorted(
        results["protocols"].items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"{protocol}: {count}")

    print("\n" + "=" * 50)
    print("TOP SOURCE IPS")
    print("=" * 50)

    for ip, count in sorted(
        results["source_ips"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:
        print(f"{ip}: {count}")


def main():
    capture = pyshark.FileCapture(
        "sample.pcapng",
        tshark_path=r"D:\Wireshark\tshark.exe"
    )

    for packet in capture:
        analyze_packet(packet)

    capture.close()

    print_report()


if __name__ == "__main__":
    main()
    