package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

public class XSSDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		String[] xssPatterns = {
                "<script>", "</script>", "javascript:", "onerror=", "onload=",
                "alert(", "document.cookie", "document.write", "eval(", "href="
        };
		Pattern xssPattern = Pattern.compile(String.join("|", xssPatterns), Pattern.CASE_INSENSITIVE);
     
	     for (int i = 0; i < jsonDataArray.length(); i++) {
	    	 JSONObject packet = jsonDataArray.getJSONObject(i);
	    	 JSONObject data = packet.getJSONObject("data");
	    	 JSONObject layers = data.getJSONObject("layers");
	    	 
	    	// HTTP 요청이 포함된 패킷인지 확인
	        if (layers.has("http") && layers.getJSONObject("http").has("http.request.uri")) {
	            String uri = layers.getJSONObject("http").getString("http.request.uri");
	
	            // XSS 패턴이 포함되어 있는지 검사
	            if (xssPattern.matcher(uri).find()) {
	                System.out.println("🚨 Potential XSS Attack detected: " + uri);
	            }
	        }
	     }
	}
}
