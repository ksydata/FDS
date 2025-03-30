package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.HttpURLConnection;
import java.net.URL;

class CSRFSimulation extends AttackSimulation {
// CrossSiteRequestForgery
	public CSRFSimulation(String url, String attackPayload) {
		super(url);
	}
	
	@Override
	public int simulate(String payload, String sessionID) throws Exception {
		String attackURL = url + payload;
		
		HttpURLConnection connection = (HttpURLConnection) new URL(attackURL).openConnection();
		connection.setRequestMethod("GET");
	    connection.setRequestProperty("Cookie", "PHPSESSID=" + sessionID);
	    
		return 0;
	}
}