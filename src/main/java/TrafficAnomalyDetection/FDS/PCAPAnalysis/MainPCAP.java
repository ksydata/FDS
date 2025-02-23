package TrafficAnomalyDetection.FDS.PCAPAnalysis;
// C:\Eclipse\dataArchive\network_packet_analysis\DDoS\3. 대역폭 공격\1.dns_tcp_truncate.pcap
// C:\Eclipse\dataArchive\network_packet_analysis\DDoS\대역폭 공격\1.dns_tcp_truncate.json

import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.File;
import java.util.*;

public class MainPCAP {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
			// 사용자로부터 입력 파일 경로 받기
			System.out.print("변환할 PCAP 파일 경로를 입력하세요: ");
			String pcapFile = scanner.nextLine();

			// 사용자로부터 출력 파일 경로 받기
			System.out.print("출력할 JSON 파일 경로를 입력하세요: ");
			String outputJson = scanner.nextLine();

			// 변환 작업 시작
			convertPcapToJson(pcapFile, outputJson);
		}
    }

    public static void convertPcapToJson(String pcapFile, String outputJson) {
        try {
            // Pcap 파일 핸들러 열기
            PcapHandle handle = Pcaps.openOffline(pcapFile);

            // 패킷 정보를 담을 리스트
            List<Map<String, Object>> packetsList = new ArrayList<>();
            Packet packet;

            // 모든 패킷 읽기
            while ((packet = handle.getNextPacket()) != null) {
                Map<String, Object> packetMap = extractPacketInfo(packet);
                packetsList.add(packetMap);
            }

            // JSON 변환 및 파일로 저장
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(outputJson), packetsList);

            System.out.println("PCAP 파일이 JSON으로 성공적으로 변환되었습니다: " + outputJson);

            // 핸들러 종료
            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> extractPacketInfo(Packet packet) {
        Map<String, Object> packetMap = new HashMap<>();

        // 각 계층별 패킷 정보 추출
        packetMap.put("raw_data", packet.getRawData());
        packetMap.put("payload", extractPayload(packet));
        packetMap.put("headers", extractHeaders(packet));

        return packetMap;
    }

    public static Map<String, Object> extractHeaders(Packet packet) {
        Map<String, Object> headerMap = new HashMap<>();

        // Ethernet 헤더
        if (packet.contains(org.pcap4j.packet.EthernetPacket.class)) {
            org.pcap4j.packet.EthernetPacket ethernetPacket = packet.get(org.pcap4j.packet.EthernetPacket.class);
            headerMap.put("Ethernet", extractEthernetInfo(ethernetPacket));
        }

        // IP 헤더 (IPv4 및 IPv6)
        if (packet.contains(org.pcap4j.packet.IpV4Packet.class)) {
            org.pcap4j.packet.IpV4Packet ipv4Packet = packet.get(org.pcap4j.packet.IpV4Packet.class);
            headerMap.put("IPv4", extractIpv4Info(ipv4Packet));
        } else if (packet.contains(org.pcap4j.packet.IpV6Packet.class)) {
            org.pcap4j.packet.IpV6Packet ipv6Packet = packet.get(org.pcap4j.packet.IpV6Packet.class);
            headerMap.put("IPv6", extractIpv6Info(ipv6Packet));
        }

        // TCP/UDP 헤더
        if (packet.contains(org.pcap4j.packet.TcpPacket.class)) {
            org.pcap4j.packet.TcpPacket tcpPacket = packet.get(org.pcap4j.packet.TcpPacket.class);
            headerMap.put("TCP", extractTcpInfo(tcpPacket));
        } else if (packet.contains(org.pcap4j.packet.UdpPacket.class)) {
            org.pcap4j.packet.UdpPacket udpPacket = packet.get(org.pcap4j.packet.UdpPacket.class);
            headerMap.put("UDP", extractUdpInfo(udpPacket));
        }

        return headerMap;
    }

    public static Map<String, Object> extractEthernetInfo(org.pcap4j.packet.EthernetPacket ethernetPacket) {
        Map<String, Object> ethernetMap = new HashMap<>();
        ethernetMap.put("src_mac", ethernetPacket.getHeader().getSrcAddr().toString());
        ethernetMap.put("dst_mac", ethernetPacket.getHeader().getDstAddr().toString());
        ethernetMap.put("type", ethernetPacket.getHeader().getType().valueAsString());
        return ethernetMap;
    }

    public static Map<String, Object> extractIpv4Info(org.pcap4j.packet.IpV4Packet ipv4Packet) {
        Map<String, Object> ipv4Map = new HashMap<>();
        ipv4Map.put("src_ip", ipv4Packet.getHeader().getSrcAddr().toString());
        ipv4Map.put("dst_ip", ipv4Packet.getHeader().getDstAddr().toString());
        ipv4Map.put("ttl", ipv4Packet.getHeader().getTtlAsInt());
        ipv4Map.put("protocol", ipv4Packet.getHeader().getProtocol().valueAsString());
        return ipv4Map;
    }

    public static Map<String, Object> extractIpv6Info(org.pcap4j.packet.IpV6Packet ipv6Packet) {
        Map<String, Object> ipv6Map = new HashMap<>();
        ipv6Map.put("src_ip", ipv6Packet.getHeader().getSrcAddr().toString());
        ipv6Map.put("dst_ip", ipv6Packet.getHeader().getDstAddr().toString());
        ipv6Map.put("hop_limit", ipv6Packet.getHeader().getHopLimit());
        ipv6Map.put("protocol", ipv6Packet.getHeader().getNextHeader().valueAsString());
        return ipv6Map;
    }

    public static Map<String, Object> extractTcpInfo(org.pcap4j.packet.TcpPacket tcpPacket) {
        Map<String, Object> tcpMap = new HashMap<>();
        tcpMap.put("src_port", tcpPacket.getHeader().getSrcPort().valueAsInt());
        tcpMap.put("dst_port", tcpPacket.getHeader().getDstPort().valueAsInt());
        tcpMap.put("seq_number", tcpPacket.getHeader().getSequenceNumber());
        tcpMap.put("ack_number", tcpPacket.getHeader().getAcknowledgmentNumber());
        tcpMap.put("flags", tcpPacket.getHeader().getFlags());
        return tcpMap;
    }

    public static Map<String, Object> extractUdpInfo(org.pcap4j.packet.UdpPacket udpPacket) {
        Map<String, Object> udpMap = new HashMap<>();
        udpMap.put("src_port", udpPacket.getHeader().getSrcPort().valueAsInt());
        udpMap.put("dst_port", udpPacket.getHeader().getDstPort().valueAsInt());
        udpMap.put("length", udpPacket.getHeader().getLengthAsInt());
        return udpMap;
    }

    public static String extractPayload(Packet packet) {
        return packet.getPayload() != null ? packet.getPayload().toString() : null;
    }
}
