package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.HttpURLConnection;
import java.net.URL;

class XSStoSQLiSimulation extends AttackSimulation {
	// 부모 클래스(추상)인 AttackSimulation를 상속받아 초기화 생성자를 호출하여 url 설정
	private String attackPayload;
	
	public XSStoSQLiSimulation(String url, String attackPayload) {
		super(url);
		this.attackPayload = attackPayload;
	}
	
	@Override
	public void simulate() throws Exception {
		String attackURL = url + "?query=" + attackPayload;
		// ?query=<script>alert('XSS')</script>
		// ?user=' OR '1'='1
		// ?input= / ?csrftoken="
		// String secureCodingURL = URLEncoder.encode(attackURL, "UTF-8");
		
		HttpURLConnection connection = (HttpURLConnection) new URL(attackURL)
				.openConnection();
		connection.setRequestMethod("GET");
		
		int httpResponseCode = connection.getResponseCode();
		System.out.println("HTTP Response Code(Cross-Site Scripting, XSS): " + httpResponseCode);
	}
}