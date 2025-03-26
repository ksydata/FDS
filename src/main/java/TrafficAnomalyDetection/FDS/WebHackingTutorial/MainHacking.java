package TrafficAnomalyDetection.FDS.WebHackingTutorial;

public class MainHacking {

	public static void main(String[] args) throws Exception {
//		SessionDetection sd = new SessionDetection();
//		sd.detectSession();
		
		
//		SessionDVWA sd = new SessionDVWA();
//		String cookie = sd.getCookie();
//		System.out.println(cookie);
		
		SQLInjectionTrial sq = new SQLInjectionTrial();
//		sq.SQLInjection();
		sq.run();
		
		
		
		

	}

}

/*
 * DVWA 접속 정보: ip 192.168.219.102 /DVWA
 * 
 * 
 * 
 * 
 */
