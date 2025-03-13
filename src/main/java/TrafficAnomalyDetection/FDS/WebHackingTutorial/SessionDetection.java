package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;

public class SessionDetection {

	public void detectSession() throws MalformedURLException, IOException {
		Scanner scanner = new Scanner(System.in);
		System.out.print("id: ");
		String memberID = scanner.nextLine();
		System.out.print("pw: ");
		String memberPassword = scanner.nextLine();
		scanner.close();
		
		String target = "http://dowellcomputer.com/hacking/member/memberLoginForm.jsp?memberID=" 
							+ memberID + "&memberPassword=" + memberPassword;
		HttpURLConnection con = (HttpURLConnection) new URL(target).openConnection();
		
		String cookie = "";
		String temp = con.getHeaderField("Set-Cookie");
		
		if (temp != null)
		{
			cookie = temp;
		}
		
		System.out.println("현재 당신의 세션은 : " + cookie);
		
		String updateTarget = "http://dowellcomputer.com/hacking/member/memberUpdateForm.jsp?ID=" + memberID;
		HttpURLConnection con2 = (HttpURLConnection) new URL(updateTarget).openConnection();
		con2.setRequestProperty("Cookie", cookie);
		BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
		
		while ((temp = br.readLine()) != null)
		{
			System.out.println(temp);
		}
		con.disconnect();
		br.close();
	}
	
}
