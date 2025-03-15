package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.util.Iterator;
import org.json.JSONObject;

public class DetectionTools {
	// 패킷 데이터(JSON 형식)에서 layers 필드 추출하는 메서드
	// tcp, frame 등의 하위 필드를 추출하기 위함
	public static JSONObject getPacketLayers(JSONObject packet) {
		JSONObject data = packet.getJSONObject("data");
		JSONObject layers = data.getJSONObject("layers");
		return layers;
	}
	
	// IP 프로토콜 출발지, 도착지 주소 추출하는 메서드
	public static String[] getIPAddress(JSONObject packet) {
		JSONObject layers = getPacketLayers(packet);
		JSONObject ip = layers.getJSONObject("ip");
		
		String ipSrc = ip.getString("ip.src");
		String ipDst = ip.getString("ip.dst");
		return new String[] {ipSrc, ipDst};
	}
	
	// 패킷의 TCP 프로토콜 플래그 유형 추출하는 메서드
	public static String getTCPFlagOption(JSONObject packet) {
		JSONObject layers = getPacketLayers(packet);
		JSONObject tcp = layers.getJSONObject("tcp");
		
    	// 패킷 플래그가 [SYN] 인 경우
    	if (tcp.get("tcp.flags").equals("0x0002")) return "SYN";
    	// 패킷 플래그가 [ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0010")) return "ACK";
    	// 패킷 플래그가 [RST] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0004")) return "RST";
    	// 패킷 플래그가 [SYN, ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0012")) return "SYN-ACK";
    	// 패킷 플래그가 [RST, ACK] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0014")) return "RST-ACK";
    	// 패킷 플래그가 [FIN] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0001")) return "FIN";
    	// 패킷 플래그가 [FIN, PSH, URG] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0029")) return "FIN-PSH-URG";
    	// 패킷 플래그가 [Null] 인 경우
    	else if (tcp.get("tcp.flags").equals("0x0000")) return "NULL";
    	// 기타
    	else return "ETC";
	}
	
	// 주어진 JSONObject에서 특정 키를 찾고, 해당 키에 대한 값을 반환하는 재귀적인 메서드
	public static Object findKeyValue(JSONObject packet, String targetKey) {
		// 키 순회
		Iterator<String> keys = packet.keys();
		
		while (keys.hasNext()) { 
			// 키 일치 검사
			String key = keys.next();
			Object value = packet.get(key);
			// 원하는 특정 키(입력받은 targetKey)를 찾으면 반환
			if (key.equals(targetKey)) {
				return value;
			}
			// findKeyValue() 메서드 재귀 호출: JSON 객체는 트리 구조인 점 고려
	        if (value instanceof JSONObject) {
	            Object result = findKeyValue( (JSONObject) value, targetKey );
	            if (result != null) return result;
	        }
	    }
		return null;
	}
}