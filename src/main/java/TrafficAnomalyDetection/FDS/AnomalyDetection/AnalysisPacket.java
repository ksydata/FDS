package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;
// https://ggonmerr.tistory.com/38
// https://blog.naver.com/stop2y/221018537228

public class AnalysisPacket extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		for (int index = 0; index < jsonDataArray.length(); index++) {
			// JSON 배열 내 index 번째 document(패킷)을 JSON 문자열 형식으로 변환 
			JSONObject packet = jsonDataArray.getJSONObject(index);
            // System.out.println("Packet at index " + index + ": " + packet.toString());
			
			// _source 필드 layers 아래에 패킷의 구조 정의(이더넷, IP, TCP, TLS 등)
            if (packet.has("data")) {
                JSONObject source = packet.getJSONObject("data");
                JSONObject layers = source.getJSONObject("layers");
			// JSONObject layers = packet.getJSONObject("_source").getJSONObject("layers");
		            
				// TCP 패킷 여부 확인
				if (layers.has("tcp")) {
	                JSONObject tcpLayer = layers.getJSONObject("tcp");
	                // 'tcp_srcport'. 'tcp_dstport', 'tcp_flags'
	                if (tcpLayer.has("tcp_flags")) {
	                	String tcpFlag = tcpLayer.getJSONArray("tcp_flags").getString(0);
	                	
	                	if (tcpFlag.contains("")) {
	                		System.out.println("Scan")
	                		// Closed Port 0x14(RST+ACK)
	                		// Stealth Scan-FIN Scan0x001(FIN)
	                		// X-mas Scan 0x029(FIN, PSH, URG)
	                		// NULL Scan 0x000 <None>
	                	}
	                }
	                    
				}
            } else {
                System.out.println("No '_source' or 'data' field found for packet");
            }
        }
    }
}
