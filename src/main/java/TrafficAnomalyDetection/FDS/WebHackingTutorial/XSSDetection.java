package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;

public class XSSDetection {
	public void XSSAction() throws MalformedURLException, IOException {
		Scanner scanner = new Scanner(System.in);
		System.out.print("id: ");
		String memberID = scanner.nextLine();
		System.out.print("pw: ");
		String memberPassword = scanner.nextLine();
		scanner.close();
		
		String target = "http://dowellcomputer.com/hacking/member/memberLoginForm.jsp?memberID=" 
				+ memberID + "&memberPassword=" + memberPassword;
		HttpURLConnection con = (HttpURLConnection) new URL(target).openConnection();
		
		String actionScript = "<script>alert('hello world');</script>";
		con.addRequestProperty("http", actionScript);
		BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
		br.close();
		
	}
}
