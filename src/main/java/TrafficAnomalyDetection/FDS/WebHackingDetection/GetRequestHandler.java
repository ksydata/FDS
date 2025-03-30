package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.URL;
import java.util.List;
import java.util.Map;

import java.net.HttpURLConnection;
import java.net.URI;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookieStore;
import java.net.HttpCookie;

// https://honeyinfo7.tistory.com/325

class GetRequestHandler extends RequestHandler {
    // 세션 쿠키를 저장하는 변수 생성
	// HTTP(하이퍼텍스트의 기록서)의 일종으로 인터넷 사용자가 어떤 웹사이트를 방문할 경우 그 사이트가 사용하는 서버를 통해 사용자 컴퓨터에 설치되는 작은 기록정보 파일
	// private String cookie;

    // 부모 클래스인 RequestHandler를 상속받아 초기화 생성자를 호출하여 url 설정
    public GetRequestHandler(String url) {
        super(url);
    }

    // GET 방식의 요청을 처리하는 기능 메서드
    // 클라이언트가 서버에서 특정 리소스를 요청할 때 사용되며, 데이터 조회 목적
    @Override
    public String sendRequest(CookieStore cookieStore, Map<String, String> parameters) throws Exception {
    	// parameters = {String "cookieString", String "ip", String "menu"}

        // GET 방식의 url 쿼리 스트림 변수 생성(HTTP url 연결 변수 생성)
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");
        // 웹 개발자 도구의 헤더 및 키 정보(Content-Type, Accept-Language)
        connection.setRequestProperty("User-Agent", "Mozilla/5.0");
        connection.setRequestProperty("Accept", "text/html");
        
        // 현재 저장된 쿠키를 요청 헤더에 추가
        String cookies = getCookies(cookieStore);
        if (!cookies.isEmpty()) connection.setRequestProperty("Cookie", cookies);

        // 서버로부터 응답 데이터를 읽어오는 BufferedReader 생성(html 파일 출력을 위해 utf-8 인코딩)
        BufferedReader bufferedReader = new BufferedReader(
        		new InputStreamReader(connection.getInputStream(), "UTF-8"));
        StringBuilder httpResponse = new StringBuilder();
        String line;
        // 서버 응답 저장
        while ((line = bufferedReader.readLine()) != null) {
        	httpResponse.append(line); // System.out.println(line);
        }
        // 리소스 해제
        bufferedReader.close();
        
        // Set-Cookie 헤더 처리
        // 새로운 연결을 열어서 세션 쿠키를 설정 및 서버와 연결
        Map<String, List<String>> responseHeader = connection.getHeaderFields();
        List<String> setCookies = responseHeader.get("Set-Cookie");
        if (setCookies != null) storeCookie(cookieStore, setCookies);
        
        return httpResponse.toString();
        // 리소스 해제
        connection.disconnect();
    }
	// 쿠키 및 세션 관리를 위한 쿠키 매니저 선언
	// 쿠키값들을 ";" 구분자로 분리한 문자열을 cookies 배열에 저장

    // Set-Cookie 헤더를 처리하여 쿠키값(세션ID)를 저장하는 메서드
    private void storeCookie(CookieStore cookieStore, List<String> setCookies) {
        // 쿠키값 배열에서 하나씩 꺼내어 반복 루프 수행
        for (String setCookie : setCookies) {
        	String[] parts = setCookie.split(";", 2);
        	if (parts[0].contains("=")) {
        		String[] keyValue = parts[0].split("=", 2);
        		HttpCookie httpCookie = new HttpCookie(keyValue[0], keyValue[1]);
        		cookieStore.add(URI.create(url), httpCookie);
        	}
        }
    }
    
    // 요청 시 헤더에 포함하기 위해 저장된 쿠키를 문자열로 변환 후 반환하는 메서드 
    private String getCookies(CookieStore cookieStore) {
        StringBuilder cookieHeader = new StringBuilder();
        for (HttpCookie cookie : cookieStore.getCookies()) {
        	if (cookieHeader.length() > 0) {
        		cookieHeader.append("; ");
    		}
        	cookieHeader.append(cookie.getName())
        		.append("=").append(cookie.getValue());
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