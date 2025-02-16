package TrafficAnomalyDetection.FDS.PCAPAnalysis;

import java.util.Scanner;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

public class MainPCAP {

	public static void main(String[] args) throws PcapNativeException {
		// Scanner()를 통해 외부에서 파일경로와 탐지 대상 오 입력받기
		Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the path to PCAP file: ");
        String filePath = scanner.nextLine();
        System.out.print("Enter anomaly detection type: ");
        String detectionType = scanner.nextLine();
        
        PcapHandle handle = Pcaps.openOffline(filePath);
        Packet packet;
        
        try {
			while ((packet = handle.getNextPacket()) != null) { // packet 변수 사용 가능
			    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
			    if (ipPacket != null) {
			        UdpPacket udpPacket = packet.get(UdpPacket.class);
			        if (udpPacket != null) {
			            DnsPacket dnsPacket = packet.get(DnsPacket.class);
			            if (dnsPacket != null) {
			                String queriedDomain = dnsPacket.getHeader().getQuestions().get(0).getQName().toString();
			                System.out.println("⚠ Suspicious DNS Request: " + queriedDomain);
			            }
			        }
			    }
			}
		} catch (NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
