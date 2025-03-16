package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

public class SQLInjectionDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		int count = 0;
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	
	    	String[] sqlKeywords = {
	    			// SQL Injection에 필요한 구문 패턴 모음
	    			"SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP",
	    		    "UNION", "ORDER BY", "GROUP BY", "HAVING", "LIMIT", "OFFSET",
	    		    "--", "#", "/\\*", "\\*/",
	    		    "SLEEP", "BENCHMARK",
	    		    "IF", "CASE", "ELSE",
	    		    "CAST", "CONVERT",
	    		    "EXEC", "EXECUTE", "XP_",
	    		    "INFORMATION_SCHEMA", "SCHEMA", "CHARACTER_SET",

	    		    // 🚨 추가 패턴 (고급 SQLi 기법 대응)
	    		    "MID", "IFNULL", "BINARY", "HEX", "UNHEX", "ASCII", "LENGTH",
	    		    "FLOOR", "RAND", "COUNT", "CONCAT",
	    		    "TABLES", "COLUMNS", "SCHEMATA", "CHARACTER_SETS"
	    		    };
			Pattern sqlPattern = Pattern.compile(String.join("|", sqlKeywords), Pattern.CASE_INSENSITIVE);
	    	
			// 정적 리소스 확장자 필터링 패턴
	        Pattern staticFilePattern = Pattern.compile("\\.(css|js|gif|png|jpg|jpeg|ico)(\\?.*)?$", Pattern.CASE_INSENSITIVE);
	        
	        // 🚨 ".php"로 끝나지만, 쿼리스트링이 없는 경우만 제외
	        Pattern staticPhpPattern = Pattern.compile("\\.php$", Pattern.CASE_INSENSITIVE);

			
	    	if (layers.has("http")) {
	    		JSONObject httpData = layers.getJSONObject("http");
	    		String targetKey = "http.request.uri";
	            String result = DetectionTools.findKeyValue(httpData, targetKey);
	            
	            
	            // 결과 출력
	            if (result != null) {	                
	                String decodedURL = URLDecoder.decode(result, StandardCharsets.UTF_8);
	                
	                // 🚨 정적 파일 요청이면 스킵
	                if (staticFilePattern.matcher(decodedURL).find()) {
	                    continue;
	                }
	                
	                // 🚨 ".php"로 끝나지만, 쿼리스트링이 없는 경우 스킵
	                if (staticPhpPattern.matcher(decodedURL).find() && !decodedURL.contains("?")) {
	                    continue;
	                }
	    			
	    			if (sqlPattern.matcher(decodedURL).find()) {
	    				count++;
	                    System.out.println("🚨 Potential SQL Injection detected: " + decodedURL);
	                    System.out.println("Count: " + count);
	                }
	    			
	            } 
	            
	    	}
		    	
	   }
	}
}