package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.net.URLDecoder;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;

// https://jurogrammer.tistory.com/171

public class WebHackingDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
				
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	
	    	
	    	if (layers.has("http")) {
	    		JSONObject protocolData = layers.getJSONObject("http");
	    		String targetKey = "http.request.uri";
	    		String result = (String) DetectionTools.findKeyValue(protocolData, targetKey);	
	    		
	    		if (result != null) {
	    			String decodedURL = URLDecoder.decode(result, StandardCharsets.UTF_8);
	    			System.out.println(result);
	    		}
	    	}
		}
	}
}
	    	// 기본 웹 필터 적용: (http.request or tls.handshake.type eq 1) and !(ssdp)
	    	// boolean isHttpRequest = layers.has("http") && layers.getJSONObject("http").has("request.method");
//	    	boolean isTlsHandshake = layers.has("tls") && layers.getJSONObject("tls").has("tls.record");
//	    	boolean isTlsHandshake = layers.has("tls") && layers.getJSONArray("tls").getJSONArray("tls.record");
            // http.request.full_uri || http.response.code == 200       
//	    	boolean isSsdp = layers.has("ssdp");
//	    	
//	    	if ((isHttpRequest || isTlsHandshake) && !isSsdp) {
//	    		System.out.println(layers);
//            }
	    	
//	    	if ((layers.get("tls.handshake.type").equals("1")) || (layers.get("http.request.method").equals("GET"))) {
//	    		System.out.println(layers);
//	    	}
	    	
	    	// 필터 적용 대상 중 도메인이 없는 ip 찾기
			// TLS 인증서에서 이상한 도메인 찾아 오류 탐지하기
	    