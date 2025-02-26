package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

public class SYNFloodDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		int count = 0;
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			// 현재 패킷이 TCP, SYN 패킷인지 판별
			if (TCPDetection(packet) && i+1 < jsonDataArray.length()) {
				JSONObject layers = getPacketLayers(packet);
				JSONObject ip = layers.getJSONObject("ip");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				
				if (FlagDetection(packet).equals("SYN") && TCPDetection(targetPkt)) {
					
					JSONObject targetLayers = getPacketLayers(targetPkt);
					JSONObject targetIp = targetLayers.getJSONObject("ip");
					
					String ipSrc = ip.getString("ip.src");
			    	String ipDst = ip.getString("ip.dst");
			    	String targetIpSrc = targetIp.getString("ip.src");
			    	String targetIpDst = targetIp.getString("ip.dst");
			    	
			    	// 현재 패킷과 직후 패킷이 Source는 다르고 Destination은 같은 IP인지 확인.
			    	if (ipDst.equals(targetIpDst) && !ipSrc.equals(targetIpSrc)) {
			    		// SYN 패킷이 연속되어 진행되는 지 확인되면 카운트 올리기
			    		if (FlagDetection(targetPkt).equals("SYN")) {
			    			count++;
			    			
			    			// 카운트가 10을 넘기면 SYN Flood로 판별
			    			if (count > 10) {
			    				System.out.println("SYN Flood: " + count);
			    			}
			    		} 
			    		// ACK 패킷이 나올 시 카운트 초기화
			    		else if (FlagDetection(targetPkt).equals("ACK")) {
			    			count = 0;
			    		}
			    	}
				}
			}
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
    	// 패킷 플래그가 [FIN, PSH, URG] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0029")) {
    		return "FIN-PSH-URG";
    	}
    	// 패킷 플래그가 [Null] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0000")) {
    		return "NULL";
    	}
    	// 그 외
    	else {
    		return "ETC";
    	}
		
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
}
