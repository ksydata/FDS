package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.IOException;
import java.net.MalformedURLException;

public class MainHacking {

	public static void main(String[] args) throws MalformedURLException, IOException {
		SessionDetection sd = new SessionDetection();
		sd.detectSession();

	}

}
