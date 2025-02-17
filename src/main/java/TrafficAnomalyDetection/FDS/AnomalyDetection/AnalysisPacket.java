package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

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
		            
				// HTTP 패킷 여부 확인
				if (layers.has("http")) {
	                JSONObject httpLayer = layers.getJSONObject("http");
					
					// 1. HTTP 메서드 확인
					if (httpLayer.has("http.request.method")) {
						String method = httpLayer.getString("http.request.method");
						System.out.println("HTTP Method: " + method);
					}
				
					// 2. HTTPS 적용 여부
	                /*
					if (packet.getJSONObject("_source").getJSONObject("layers").has("ssl")) {
	                	System.out.println("SSL/TLS is enabled");
	                }              } else {
	                    System.out.println("Warning: HTTP traffic without SSL/TLS.");
	                */  
					// 3. HTTP 헤더 분석
					
					// 4. HTTP 요청 패킷 내 Payload 검사(GET, POST 파라미터에서 SQL 인젝션, XSS 공격패턴 탐지 목적)
	                    
				}
            } else {
                System.out.println("No '_source' field found for packet");
            }
        }
    }
}
