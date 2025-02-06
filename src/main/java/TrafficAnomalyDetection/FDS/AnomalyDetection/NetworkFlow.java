package TrafficAnomalyDetection.FDS.AnomalyDetection;
 import java.util.regex.Pattern;

import org.json.JSONArray;
//[ {...}, {...} ] - JSONArray, JSON 파일이 배열로 시작하는 경우
import org.json.JSONObject;
//{ ... } 형식 - JSONObject로 읽는 경우

public class NetworkFlow {
//	public void executeDetection(JSONObject jsonDataObject) {
//		System.out.println(jsonDataObject);
	 public void executeDetection(JSONArray jsonDataArray, String abnormalType) {
		 System.out.println(jsonDataArray.length());
		 System.out.println(jsonDataArray.getJSONObject(0));
		 
		 if (abnormalType == "SQLInjection") {
			 NetworkFlow networkFlow = new NetworkFlow();
			 networkFlow.SQLInjectionDetect(jsonDataArray);
		 } else {
			System.out.println("No proper detection type!");
		 }
	}
	 
	 public void SQLInjectionDetect(JSONArray jsonDataArray) {
		 String[] sqlKeywords = {
	                "UNION SELECT", "DROP TABLE", "INSERT INTO", "DELETE FROM",
	                "' OR 1=1 --", "'; --", "' OR 'a'='a'", "\" OR \"a\"=\"a\""};
	     Pattern sqlPattern = Pattern.compile(String.join("|", sqlKeywords), Pattern.CASE_INSENSITIVE);
	     
	     for (int i = 0; i < jsonDataArray.length(); i++) {
	    	 JSONObject packet = jsonDataArray.getJSONObject(i);
	    	 JSONObject data = packet.getJSONObject("data");
	    	 JSONObject layers = data.getJSONObject("layers");
//	    	 System.out.println(layers);
	    	 
	    	// HTTP 요청이 포함된 패킷인지 확인
            if (layers.has("http") && layers.getJSONObject("http").has("http.request.uri")) {
                String uri = layers.getJSONObject("http").getString("http.request.uri");

                // SQL Injection 패턴이 포함되어 있는지 검사
                if (sqlPattern.matcher(uri).find()) {
                    System.out.println("🚨 Potential SQL Injection detected: " + uri);
                }
            }
	     }
	 }
};