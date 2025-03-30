package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URI;
import java.io.BufferedReader;
import java.io.InputStreamReader;


class GetRequestHandler extends RequestHandler {
	// CookieManager를 활용하여 자동 쿠키 관리
    private static final CookieManager cookieManager = new CookieManager();
	
    // 세션 쿠키를 저장하는 변수 생성
    String cookie = "";

    // 부모 클래스인 RequestHandler를 상속받아 초기화 생성자를 호출하여 url 설정
    public GetRequestHandler(String url) {
        super(url);
        CookieHandler.setDefault(cookieManager); // 쿠키 매니저를 기본 핸들러로 설정
    }
    
    // 최초 로그인 진행? 로그인 페이지 로딩 GET -> 로그인 페이지에 payload 넣어서 POST 진행 -> POST 결과 이후 쿠키 뽑기
    // 

    // GET 방식의 요청을 처리하는 기능 메서드
    // 클라이언트가 서버에서 특정 리소스를 요청할 때 사용되며, 데이터 조회 목적
    @Override
    public String sendRequest(String parameter) throws Exception {
        // GET 방식의 url 쿼리 스트림 변수 생성(HTTP url 연결 변수 생성)
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", "Mozilla/5.0");
        connection.setRequestProperty("Accept", "text/html");
        
        int responseCode = connection.getResponseCode();

        // 🔹 리디렉션 여부 확인 및 처리
        if (responseCode >= 300 && responseCode < 400) {
            String newLocation = connection.getHeaderField("Location");
            if (newLocation != null) {
                System.out.println("🔄 리디렉션 감지: " + newLocation);
                return handleRedirect(newLocation);
            }
        }
        
        // 서버에서 받은 쿠키 값을 가져오는 변수 생성
        Map<String, List<String>> headers = connection.getHeaderFields();
        List<String> headerSetCookie = headers.get("Set-Cookie");

        // 쿠키 값이 있을 경우 저장(여러 속성 중 쿠키 값만 정확하게 추출하는 로직을 개선)
        if (headerSetCookie != null && !headerSetCookie.isEmpty()) {
            // 헤더에서 첫번째 세션 ID를 저장
            for (String setCookie : headerSetCookie) {
                if (setCookie.contains("PHPSESSID")) {
                    cookie = setCookie.split("PHPSESSID=")[1].split(";")[0];
                    break;
                }
            }
        } else {
            System.out.println("Not found Set-Cookie header");
        }
        
        // 새로운 연결을 열어서 세션 쿠키를 설정 및 서버와 연결
        connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestProperty("Cookie", "PHPSESSID=" + cookie);
//        int responseCode = connection.getResponseCode();

        // 서버로부터 응답 데이터를 읽어오는 BufferedReader 생성(html 파일 출력을 위해 utf-8 인코딩)
        BufferedReader bufferedReader = new BufferedReader(
        		new InputStreamReader(connection.getInputStream(), "UTF-8"));
        // 서버 응답을 출력
        String line;
        while ((line = bufferedReader.readLine()) != null) {
        	System.out.println(line);
        }
        // 리소스 해제
        connection.disconnect();
        bufferedReader.close();
        
        return cookie;
    }
    
 // 리디렉션 처리 메서드
    private String handleRedirect(String newLocation) throws Exception {
        URL newUrl = new URL(newLocation);
        HttpURLConnection redirectConnection = (HttpURLConnection) newUrl.openConnection();
        redirectConnection.setRequestMethod("GET");
        redirectConnection.setRequestProperty("User-Agent", "Mozilla/5.0");

        // 쿠키 자동 관리 (이전 요청에서 받은 쿠키가 자동으로 포함됨)
        int redirectResponseCode = redirectConnection.getResponseCode();
        System.out.println("🔄 리디렉션 응답 코드: " + redirectResponseCode);

        // 🔹 응답 데이터 읽기
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(redirectConnection.getInputStream(), "UTF-8"));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            response.append(line).append("\n");
        }
        bufferedReader.close();

        return response.toString();
    }
    
   // 쿠키를 직접 저장하는 메서드
    private void storeCookie(String cookieString) {
        CookieManager cookieManager = (CookieManager) CookieHandler.getDefault();
        CookieStore cookieStore = cookieManager.getCookieStore();

        // 🔥 Set-Cookie 값에서 쿠키 이름과 값을 추출하여 수동 저장
        String[] cookies = cookieString.split(";");
        for (String cookie : cookies) {
            String[] parts = cookie.split("=", 2);
            if (parts.length == 2) {
                HttpCookie httpCookie = new HttpCookie(parts[0].trim(), parts[1].trim());
                httpCookie.setDomain(url);  // 🔥 DVWA 서버 도메인 설정
                httpCookie.setPath("/DVWA/");            // 🔥 DVWA 경로 설정
                cookieStore.add(URI.create(url), httpCookie);
            }
        }
    }
    
   // ✅ 현재 저장된 쿠키를 문자열로 변환 (요청에 넣을 때 사용)
    private String getCookies() {
        CookieManager cookieManager = (CookieManager) CookieHandler.getDefault();
        CookieStore cookieStore = cookieManager.getCookieStore();

        StringBuilder cookieHeader = new StringBuilder();
        for (URI uri : cookieStore.getURIs()) {
            if (!uri.toString().contains(url)) continue; // 🔥 올바른 도메인인지 확인

            for (HttpCookie cookie : cookieStore.get(uri)) {
                if (cookieHeader.length() > 0) {
                    cookieHeader.append("; ");
                }
                cookieHeader.append(cookie.getName()).append("=").append(cookie.getValue());
            }
        }
        return cookieHeader.toString();
    }
}

/*
Set-Cookie=[
	security=impossible; 
	
	path=/; 
	HttpOnly, 
	PHPSESSID=b74d4v6736svvlj3fkqkchfpqu; 
	expires=Mon, 
	24 Mar 2025 11:46:05 GMT; 
	Max-Age=86400; 
	
	path=/; 
	HttpOnly; 
	SameSite=Strict, 
	PHPSESSID=pk488ap5v40cs5hfih7nugq8et; 
	expires=Mon, 
	24 Mar 2025 11:46:05 GMT; 
	Max-Age=86400; 
	
	path=/; 
	HttpOnly; 
	SameSite=Strict]
*/

/*
// 리디렉션 코드
if (responseCode >= 300 && responseCode < 400) {
    // Location 헤더를 확인
    String location = connection.getHeaderField("Location");
    if (location != null) {
        // 리디렉션된 새로운 URL로 요청을 재전송
        System.out.println("Redirected to: " + location);
        connection = (HttpURLConnection) new URL(location).openConnection();
        // 기존 쿠키 사용
        connection.setRequestProperty("Cookie", "PHPSESSID=" + cookie);
        // 리디렉션 후 응답 데이터 읽기
        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), "UTF-8"));
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            System.out.println(line);
        }
        connection.disconnect();
        bufferedReader.close();
    }
} else {}
*/