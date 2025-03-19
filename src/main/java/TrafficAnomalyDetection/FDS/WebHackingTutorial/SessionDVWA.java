package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class SessionDVWA {

	public String getCookie() throws Exception {
		String loginUrl = "http://192.168.219.102/DVWA/login.php";
        String credentials = "username=admin&password=password&Login=Login"; // DVWA 기본 계정
        String cookie = loginAndGetSession(loginUrl, credentials);
        

        if (cookie != null) {
            System.out.println("로그인 성공! 세션 쿠키: " + cookie);
        } else {
            System.out.println("로그인 실패!");
        }
        
        return cookie;
	}
	
	public static String loginAndGetSession(String loginUrl, String credentials) throws Exception {
        URL url = new URL(loginUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        // 로그인 데이터 전송
        try (OutputStream os = conn.getOutputStream()) {
            os.write(credentials.getBytes());
            os.flush();
        }

        // 응답 헤더에서 쿠키 추출
        Map<String, List<String>> headerFields = conn.getHeaderFields();
//        System.out.println(headerFields);
        List<String> cookies = headerFields.get("Set-Cookie");
        System.out.println(cookies);
        
        if (cookies != null) {
            for (String cookie : cookies) {
                if (cookie.contains("PHPSESSID")) {
                    return cookie.split(";")[0]; // "PHPSESSID=xxxxxx" 형태만 추출
                }
            }
        }
       
        return null; // 쿠키 없으면 로그인 실패
    }
}
