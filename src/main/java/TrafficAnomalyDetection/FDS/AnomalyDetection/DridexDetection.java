package TrafficAnomalyDetection.FDS.AnomalyDetection;


import org.json.JSONArray;
import org.json.JSONObject;


public class DridexDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		// 기본 웹 필터 적용: (http.request or tls.handshake.type eq 1) and !(ssdp)
    	
    	// 필터 적용 대상 중 도메인이 없는 ip 찾기
		
		// TLS 인증서에서 이상한 도메인 찾아 오류 탐지하기
		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	
		}
	}
}
