package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

public class SQLInjectionDetection2 extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		int count = 0;
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	
	    	String[] sqlKeywords = {
	                "SELECT", "FROM"};
			Pattern sqlPattern = Pattern.compile(String.join("|", sqlKeywords), Pattern.CASE_INSENSITIVE);
	    	
			
	    	if (layers.has("http")) {
	    		JSONObject httpData = layers.getJSONObject("http");
//	    		System.out.println(httpData);
	    		
	    		String targetKey = "http.request.uri";
	            String result = findValueByKey(httpData, targetKey);
	            
	            
	            // 결과 출력
	            if (result != null) {
//	                System.out.println("http.request.uri 값: " + result);
	                
	                String decodedURL = URLDecoder.decode(result, StandardCharsets.UTF_8);
//	    			System.out.println(decodedURL);
	    			
	    			if (sqlPattern.matcher(decodedURL).find()) {
	    				count++;
	                    System.out.println("🚨 Potential SQL Injection detected: " + decodedURL);
	                    System.out.println("Count: " + count);
	                }
	    			
	            } 
	            
	    	}
		    	
	   }
	}

	public static String findValueByKey(JSONObject jsonObject, String targetKey) {
        Iterator<String> keys = jsonObject.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = jsonObject.get(key);

            // 원하는 키를 찾으면 반환
            if (key.equals(targetKey)) {
                return value.toString();
            }

            // JSON 객체인 경우 재귀 호출
            if (value instanceof JSONObject) {
                String result = findValueByKey((JSONObject) value, targetKey);
                if (result != null) return result;
            }
        }
        return null;
    }
}

/*
 * 현재는 /items.php?num=1 AND (SELECT 8532 FROM(SELECT COUNT(*),CONCAT(0x717a707071,(SELECT MID((IFNULL(CAST(user_tel AS CHAR),0x20)),1,50) FROM dmshop.shop_user ORDER BY id LIMIT 2,1),0x7178767a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)
 * 위와 같은 문구와 /css/jquery.selectBox-arrow.gif 가 같이 뽑히는 상황인데
 * 로직 정교하게 다듬기가 필요
 * 
 */
