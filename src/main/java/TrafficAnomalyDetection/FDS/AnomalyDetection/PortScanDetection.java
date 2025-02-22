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
		}
		
		scanner.close();		
	}
	
	public boolean TCPDetection(JSONObject packet) {
		// 패킷이 TCP 프로토콜인지 구별
    	JSONObject layers = getPacketLayers(packet);
    	JSONObject frame = layers.getJSONObject("frame");
    	
    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:tcp")) {
    		return true;
    	} else {
    		return false;
    	}
	}
	
	public JSONObject getPacketLayers(JSONObject packet) {
		// 패킷에서 "layers" 만 남겨서 이하 "tcp", "frame" 등을 쉽게 뽑아서 사용할 수 있게 함
		JSONObject data = packet.getJSONObject("data");
    	JSONObject layers = data.getJSONObject("layers");
    	return layers;
	}

	public String FlagDetection(JSONObject packet) {
		// 각 패킷의 플래그가 [SYN], [ACK], [RST], [SYN, ACK] 중 무엇인지 확인
    	JSONObject layers = getPacketLayers(packet);
    	JSONObject tcp = layers.getJSONObject("tcp");
    	
    	// 패킷 플래그가 [SYN] 인 경우
    	if (tcp.get("tcp.flags").equals("0x0002")) {
    		return "SYN";
    	} 
    	// 패킷 플래그가 [ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0010")) {
    		return "ACK";
    	}
    	// 패킷 플래그가 [RST] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0004")) {
    		return "RST";
    	}
    	// 패킷 플래그가 [SYN, ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0012")) {
    		return "SYN-ACK";
    	}
    	// 패킷 플래그가 [RST, ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0014")) {
    		return "RST-ACK";
    	} 
    	// 패킷 플래그가 [FIN] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0001")) {
    		return "FIN";
    	}
    	// 그 외
    	else {
    		return "ETC";
    	}
		
	}
	
	public void halpOpenScanDetection(JSONArray jsonDataArray) {
		// 패킷이 [SYN] - [SYN, ACK] 순인지, [SYN] - [RST] 순으로 전개되는지 확인
		// 패킷 수순에 따라 열린 포트와 닫힌 포트를 구별하여 판독
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);

			
			if (TCPDetection(packet) && i+1 < jsonDataArray.length()) {
				JSONObject layers = getPacketLayers(packet);
				JSONObject ip = layers.getJSONObject("ip");
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				if (FlagDetection(packet).equals("SYN") && TCPDetection(targetPkt)) {
					JSONObject targetLayers = getPacketLayers(targetPkt);
					JSONObject targetIp = targetLayers.getJSONObject("ip");
			    	
			    	// 첫 패킷이 {"ip.src": "10.111.222.333", "ip.dst": "33.222.444.555"} 일 때
			    	// 두번째 패킷이 {"ip.src": "33.222.444.555", "ip.dst": "10.111.222.333"} 인 구성인지 확인하기
			    	String ipSrc = ip.getString("ip.src");
			    	String ipDst = ip.getString("ip.dst");
			    	String targetIpSrc = targetIp.getString("ip.src");
			    	String targetIpDst = targetIp.getString("ip.dst");
			    	
			    	
			    	
			    	if (ipSrc.equals(targetIpDst) && ipDst.equals(targetIpSrc)) {
			    		// 열린 포트: [SYN] - [SYN, ACK] 순으로 전개되는지 확인
			    		// [SYN] - [SYN, ACK] 순으로 패킷 전개 시 대상 서버의 해당 포트가 열려있음
						if (FlagDetection(targetPkt).equals("SYN-ACK")){
							String openPort = tcp.getString("tcp.dstport");
							System.out.println("Open: " + ipDst + ":" + openPort);
						}
						// 닫힌 포트: [SYN] - [RST, ACK] 순으로 전개되는지 확인
						// [SYN] - [RST, ACK] 순으로 패킷 전개 시 대상 서버의 해당 포트가 닫혀있음
						if (FlagDetection(targetPkt).equals("RST-ACK")) {
							String closedPort = tcp.getString("tcp.dstport");
//							System.out.println("Closed: " + ipDst + ":" + closedPort);
						}
			    	} 
				} 
				
			}
		}
		
	}
	
	public void FINScanDetection(JSONArray jsonDataArray) {
		// [FIN] 패킷 전달 후 응답이 없는 경우를 판별
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			if (TCPDetection(packet) && (i+1 < jsonDataArray.length())) {
				JSONObject layers = getPacketLayers(packet);
				JSONObject ip = layers.getJSONObject("ip");
				JSONObject tcp = layers.getJSONObject("tcp");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				
				if (FlagDetection(packet).equals("FIN") && TCPDetection(targetPkt)) {
					JSONObject targetLayers = getPacketLayers(targetPkt);
					JSONObject targetIp = targetLayers.getJSONObject("ip");
					
					// 첫 패킷이 {"ip.src": "10.111.222.333", "ip.dst": "33.222.444.555"} 일 때
			    	// 두번째 패킷이 {"ip.src": "33.222.444.555", "ip.dst": "10.111.222.333"} 인 구성인지 확인하기
			    	String ipSrc = ip.getString("ip.src");
			    	String ipDst = ip.getString("ip.dst");
			    	String targetIpSrc = targetIp.getString("ip.src");
			    	String targetIpDst = targetIp.getString("ip.dst");
			    	
			    	if (ipSrc.equals(targetIpSrc) && ipDst.equals(targetIpDst)) {
			    		if (FlagDetection(targetPkt).equals("FIN")) {
			    			String closedPort = tcp.getString("tcp.dstport");
			    			System.out.println("Closed: " + ipDst + ":" + closedPort);
			    		}
			    	} 
				}
			}
				
		}
	}
	
	
}
