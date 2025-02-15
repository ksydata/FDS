package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

public class SYNFloodDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		// TCP 프로토콜 패킷 판별 : “frame.protocols”: “eth:ethertype:ip:tcp" 만 남기기
		JSONArray TCPPackets = new JSONArray();
		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	JSONObject frame = layers.getJSONObject("frame");
	    	
	    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:tcp")) {
	    		TCPPackets.put(packet);
	    	}
		}
		
		System.out.println(TCPPackets.getJSONObject(0));
		System.out.println(TCPPackets.length());
		
		
		// 판별된 패킷 중에서 tcp -> tcp.flags_tree -> "tcp.flags.syn" = "1" 찾기
		int count = 0;
		for (int i = 0; i < TCPPackets.length(); i++) {
			JSONObject packet = TCPPackets.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	JSONObject tcp = layers.getJSONObject("tcp");
	    	JSONObject tcpFlags = tcp.getJSONObject("tcp.flags_tree");
	    	
	    	// SYN 패킷인지 확인
            boolean isSyn = "1".equals(tcpFlags.optString("tcp.flags.syn", "0"));
            boolean isAck = "1".equals(tcpFlags.optString("tcp.flags.ack", "0"));

            // "tcp.flags.syn" = "1" 인 시작지점부터 TCP 패킷을 다시 읽으며 "tcp.flags.ack" = "1" 인 지점 찾기
            if (isSyn && !isAck) { // SYN 플래그만 세트됨 (SYN 요청)
                count++;
//                System.out.println("SYN 패킷 감지! 현재 카운트: " + count);
                // "tcp.flags.syn" = "1" & "tcp.flags.ack" = "0" 만 5회 이상 반복되면 SYN Flood로 판별
                if (count >= 5) {
                    System.out.print("🚨 SYN Flood 공격 감지! 🚨 현재 카운트: " + count);
                }
            } else if (isAck) { // ACK 플래그가 세트됨 (정상 응답 발생)
                count = 0;
                initialCount++;
            }
		}
		
	}
}
