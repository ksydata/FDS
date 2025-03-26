package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;


class GetRequestHandler extends RequestHandler {
    // 세션 쿠키를 저장하는 변수 생성
    String cookie = "";

    // 부모 클래스인 RequestHandler를 상속받아 초기화 생성자를 호출하여 url 설정
    public GetRequestHandler(String url) {
        super(url);
    }

    // GET 방식의 요청을 처리하는 기능 메서드
    // 클라이언트가 서버에서 특정 리소스를 요청할 때 사용되며, 데이터 조회 목적
    @Override
    public void sendRequest(String parameter) throws Exception {
        // GET 방식의 url 쿼리 스트림 변수 생성
        // HTTP url 연결 변수 생성
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();

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
        
        // 세션 쿠키를 출력
        System.out.println("Session is: " + cookie);        

        // 새로운 연결을 열어서 세션 쿠키를 설정 및 서버와 연결
        connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestProperty("Cookie", "PHPSESSID=" + cookie);
        int responseCode = connection.getResponseCode();

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
        } else {
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
        }
    }
}
