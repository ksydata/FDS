package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.util.Scanner;

import org.json.JSONArray;
import org.json.JSONObject;

public class PortScanDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter Port Scan Type: ");
		String scanType = scanner.nextLine();
		if (scanType.equalsIgnoreCase("HALF_OPEN_SCAN")) {
			halpOpenScanDetection(jsonDataArray);
		} else if (scanType.equalsIgnoreCase("FIN_SCAN")) {
			FINScanDetection(jsonDataArray);
		} else if (scanType.equalsIgnoreCase("XMAS_SCAN")) {
			XMASScanDetection(jsonDataArray);
		} else if (scanType.equalsIgnoreCase("NULL_SCAN")) {
			NULLScanDetection(jsonDataArray);
		} else {
			System.out.println("Enter accurate Scan Type!");
		}
		
		scanner.close();		
	}
	

	private void halpOpenScanDetection(JSONArray jsonDataArray) {
		// 패킷이 [SYN] - [SYN, ACK] 순인지, [SYN] - [RST] 순으로 전개되는지 확인
		// 패킷 수순에 따라 열린 포트와 닫힌 포트를 구별하여 판독		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);

			
			if (DetectionTools.TCPDetection(packet) && i+1 < jsonDataArray.length()) {
				JSONObject layers = DetectionTools.getPacketLayers(packet);
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				if (DetectionTools.FlagDetection(packet).equals("SYN") && DetectionTools.TCPDetection(targetPkt)) {
					
					// 첫 패킷이 {"ip.src": "10.111.222.333", "ip.dst": "33.222.444.555"} 일 때
			    	// 두번째 패킷이 {"ip.src": "33.222.444.555", "ip.dst": "10.111.222.333"} 인 구성인지 확인하기
					String ipSrc = DetectionTools.getPacketIPInfo(packet)[0];
					String ipDst = DetectionTools.getPacketIPInfo(packet)[1];
					String targetIpSrc = DetectionTools.getPacketIPInfo(targetPkt)[0];
					String targetIpDst = DetectionTools.getPacketIPInfo(targetPkt)[1];
			    	
			    	
			    	if (ipSrc.equals(targetIpDst) && ipDst.equals(targetIpSrc)) {
			    		// 열린 포트: [SYN] - [SYN, ACK] 순으로 전개되는지 확인
			    		// [SYN] - [SYN, ACK] 순으로 패킷 전개 시 대상 서버의 해당 포트가 열려있음
						if (DetectionTools.FlagDetection(targetPkt).equals("SYN-ACK")){
							String openPort = tcp.getString("tcp.dstport");
							System.out.println("Open: " + ipDst + ":" + openPort);
						}
						// 닫힌 포트: [SYN] - [RST, ACK] 순으로 전개되는지 확인
						// [SYN] - [RST, ACK] 순으로 패킷 전개 시 대상 서버의 해당 포트가 닫혀있음
						if (DetectionTools.FlagDetection(targetPkt).equals("RST-ACK")) {
							String closedPort = tcp.getString("tcp.dstport");
//							System.out.println("Closed: " + ipDst + ":" + closedPort);
						}
			    	} 
				} 
				
			}
		}
		System.out.println("------- Half Open Scan Completed! --------");
		
	}
	
	private void FINScanDetection(JSONArray jsonDataArray) {		
		// FIN Scan: [FIN] 패킷 전달 후 응답이 없는 경우를 판별
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			if (DetectionTools.TCPDetection(packet) && (i+1 < jsonDataArray.length())) {
				JSONObject layers = DetectionTools.getPacketLayers(packet);
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				
				if (DetectionTools.FlagDetection(packet).equals("FIN") && DetectionTools.TCPDetection(targetPkt)) {
					
					// 첫 패킷과 두번째 패킷이 동일한 ip.src 와 ip.dst를 갖고 있는지 확인하기
					String ipSrc = DetectionTools.getPacketIPInfo(packet)[0];
					String ipDst = DetectionTools.getPacketIPInfo(packet)[1];
					String targetIpSrc = DetectionTools.getPacketIPInfo(targetPkt)[0];
					String targetIpDst = DetectionTools.getPacketIPInfo(targetPkt)[1];
			    	
			    	if (ipSrc.equals(targetIpSrc) && ipDst.equals(targetIpDst)) {
			    		if (DetectionTools.FlagDetection(targetPkt).equals("FIN")) {
			    			String closedPort = tcp.getString("tcp.dstport");
			    			System.out.println("Closed: " + ipDst + ":" + closedPort);
			    		}
			    	} 
				}
			}
				
		}
		System.out.println("------- FIN Scan Completed! --------");
	}
	
	private void XMASScanDetection(JSONArray jsonDataArray) {		
		// XMas Scan: [FIN, PSH, URG] 패킷 전달 후 응답이 없는 경우를 판별
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			if (DetectionTools.TCPDetection(packet) && (i+1 < jsonDataArray.length())) {
				JSONObject layers = DetectionTools.getPacketLayers(packet);
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				if (DetectionTools.FlagDetection(packet).equals("FIN-PSH-URG") && DetectionTools.TCPDetection(targetPkt)) {
					
					// 첫 패킷과 두번째 패킷이 동일한 ip.src 와 ip.dst를 갖고 있는지 확인하기
					String ipSrc = DetectionTools.getPacketIPInfo(packet)[0];
					String ipDst = DetectionTools.getPacketIPInfo(packet)[1];
					String targetIpSrc = DetectionTools.getPacketIPInfo(targetPkt)[0];
					String targetIpDst = DetectionTools.getPacketIPInfo(targetPkt)[1];
			    	
			    	if (ipSrc.equals(targetIpSrc) && ipDst.equals(targetIpDst)) {
			    		if (DetectionTools.FlagDetection(targetPkt).equals("FIN-PSH-URG")) {
			    			String closedPort = tcp.getString("tcp.dstport");
			    			System.out.println("Closed: " + ipDst + ":" + closedPort);
			    		}
			    	} 
				}
				
			}
		}
		
		System.out.println("-------- XMas Scan Completed! ---------");
	}
	
	private void NULLScanDetection(JSONArray jsonDataArray) {
		// Null Scan: [Null] 패킷 전달 후 응답이 없는 경우를 판별		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			if (DetectionTools.TCPDetection(packet) && (i+1 < jsonDataArray.length())) {
				JSONObject layers = DetectionTools.getPacketLayers(packet);
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				if (DetectionTools.FlagDetection(packet).equals("NULL") && DetectionTools.TCPDetection(targetPkt)) {
					
					// 첫 패킷과 두번째 패킷이 동일한 ip.src 와 ip.dst를 갖고 있는지 확인하기
					String ipSrc = DetectionTools.getPacketIPInfo(packet)[0];
					String ipDst = DetectionTools.getPacketIPInfo(packet)[1];
					String targetIpSrc = DetectionTools.getPacketIPInfo(targetPkt)[0];
					String targetIpDst = DetectionTools.getPacketIPInfo(targetPkt)[1];
			    	
			    	if (ipSrc.equals(targetIpSrc) && ipDst.equals(targetIpDst)) {
			    		if (DetectionTools.FlagDetection(targetPkt).equals("NULL")) {
			    			String closedPort = tcp.getString("tcp.dstport");
			    			System.out.println("Closed: " + ipDst + ":" + closedPort);
			    		}
			    	} 
					
				}
			}
		}
		
		System.out.println("------- Null Scan Completed! --------");
	}
	
	
}
