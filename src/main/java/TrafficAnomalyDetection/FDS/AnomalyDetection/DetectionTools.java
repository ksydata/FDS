package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONObject;

public class DetectionTools {

	public static JSONObject getPacketLayers(JSONObject packet) {
		// 패킷에서 "layers" 만 남겨서 이하 "tcp", "frame" 등을 쉽게 뽑아서 사용할 수 있게 함
		JSONObject data = packet.getJSONObject("data");
    	JSONObject layers = data.getJSONObject("layers");
    	return layers;
	}
	
	public static String FlagDetection(JSONObject packet) {
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
	
	public static boolean TCPDetection(JSONObject packet) {
		// 패킷이 TCP 프로토콜인지 구별		
    	JSONObject layers = getPacketLayers(packet);
    	JSONObject frame = layers.getJSONObject("frame");
    	
    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:tcp")) {
    		return true;
    	} else {
    		return false;
    	}
	}
	
	public static boolean UDPDetection(JSONObject packet) {
		// 패킷이 UDP 프로토콜인지 구별
    	JSONObject layers = getPacketLayers(packet);
    	JSONObject frame = layers.getJSONObject("frame");
    	
    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:udp:data")) {
    		return true;
    	} else {
    		return false;
    	}
	}
	
	public static String[] getPacketIPInfo(JSONObject packet) {
		JSONObject layers = DetectionTools.getPacketLayers(packet);
		JSONObject ip = layers.getJSONObject("ip");
		
		String ipSrc = ip.getString("ip.src");
    	String ipDst = ip.getString("ip.dst");
    	    	
    	return new String[] {ipSrc, ipDst};
	}
	
	
	
}
