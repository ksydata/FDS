package TrafficAnomalyDetection.FDS.AnomalyDetection;


import org.json.JSONArray;
import org.json.JSONObject;

public class WebHackingDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		JSONArray filteredPackets = new JSONArray();
		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	
	    	// 기본 웹 필터 적용: (http.request or tls.handshake.type eq 1) and !(ssdp)
	    	boolean isHttpRequest = layers.has("http") && layers.getJSONObject("http").has("request.method");
//	    	boolean isTlsHandshake = layers.has("tls") && layers.getJSONObject("tls").has("tls.record");
//	    	boolean isTlsHandshake = layers.has("tls") && layers.getJSONArray("tls").getJSONArray("tls.record");
            // http.request.full_uri || http.response.code == 200       
//	    	boolean isSsdp = layers.has("ssdp");
//	    	
//	    	if ((isHttpRequest || isTlsHandshake) && !isSsdp) {
//	    		System.out.println(layers);
//            }
	    	if (isHttpRequest) {
	    		System.out.println(layers);
	    	}
	    	
	    	
//	    	if ((layers.get("tls.handshake.type").equals("1")) || (layers.get("http.request.method").equals("GET"))) {
//	    		System.out.println(layers);
//	    	}
	    	
	    	
	    	
	    	
	    	// 필터 적용 대상 중 도메인이 없는 ip 찾기
			
			// TLS 인증서에서 이상한 도메인 찾아 오류 탐지하기
	    	
		}
		
/*
		private String[] extractIP(JSONObject packet) {
		    // 변수들을 상단에서 선언
		    String sourceIP = null;
		    String destinationIP = null;
		    String flagsIP = null;
		    
		    if (packet.has("data")) {
		        JSONObject source = packet.getJSONObject("data");
		        JSONObject layers = source.getJSONObject("layers");

		        if (layers.has("http")) {
		            JSONObject ipLayer = layers.getJSONObject("ip");
		            sourceIP = ipLayer.optString("ip.src", null);
	                // String sourceIP = ipLayer.getString("src");
		            destinationIP = ipLayer.optString("ip.dst", null);
	                // String destinationIP = ipLayer.getString("dst");	            
		        }

		        if (layers.has("tcp")) {
		            JSONObject tcpLayer = layers.getJSONObject("tcp");
		            flagsIP = tcpLayer.optString("tcp.flags", "0");
	                // int flagsIP = ipLayer.getInt("flags");
		        }
		    }
		    
		    if (sourceIP != null || destinationIP != null || flagsIP != null) {
		        return new String[]{sourceIP, destinationIP, flagsIP};
		    }
		    return null;
		}
*/		
	}
}
