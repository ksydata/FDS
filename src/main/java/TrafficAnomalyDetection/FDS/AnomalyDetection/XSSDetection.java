package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

public class XSSDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		String[] xssPatterns = {
				"<script>", "</script>", "javascript:", "onerror=", "onload=",
                "alert\\(", "document.cookie", "document.write", "eval\\(", "href="
        };
		Pattern xssPattern = Pattern.compile(String.join("|", xssPatterns), Pattern.CASE_INSENSITIVE);
     
		 int count = 0;
	     for (int i = 0; i < jsonDataArray.length(); i++) {
	    	 JSONObject packet = jsonDataArray.getJSONObject(i);
	    	 JSONObject data = packet.getJSONObject("data");
	    	 JSONObject layers = data.getJSONObject("layers");
	    	 
	    	 if (layers.has("http")) {
		    		JSONObject httpData = layers.getJSONObject("http");
		    		String targetKey = "http.request.uri";
		            String result = DetectionTools.findValueByKey(httpData, targetKey);
		            
		            // 결과 출력
		            if (result != null) {	                
		                String decodedURL = URLDecoder.decode(result, StandardCharsets.UTF_8);
		    			
		    			if (xssPattern.matcher(decodedURL).find()) {
		    				count++;
		                    System.out.println("🚨 Potential SQL Injection detected: " + decodedURL);
		                    System.out.println("Count: " + count);
		                }
		    			
		            } 
		            
		    	}
	    	 
	    	
	     }
	}
}
