package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;

class GetRequestHandler extends RequestHandler {
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
		HttpURLConnection connection = (HttpURLConnection) new URL(url)
				.openConnection();
		// URL targetURL = new URL(url);
		// HttpURLConnection connection = (HttpURLConnection) targetURL.openConnection();

		// 세션 쿠키를 저장하는 변수 생성
		String cookie = "";
		// 서버에서 받은 쿠키 값을 가져오는 변수 생성
		String temp = connection.getHeaderField("Set-Cookie");
		// 쿠키 값이 있을 경우 저장 
		if (temp != null) cookie = temp;
		// 세션 쿠키를 출력
		System.out.println("Session is: " + cookie);
		
		// connection = (HttpURLConnection) new URL(url).openconnection;
		// 세션 쿠키를 설정 및 서버와 연결
		connection.setRequestProperty("Cookie", cookie);
		
		// 서버로부터 응답 데이터를 읽어오는 BufferedReader 생성(html 파일 출력을 위해 utf-8 인코딩)
		BufferedReader bufferedReader = new BufferedReader(
				new InputStreamReader(
						connection.getInputStream(), "UTF-8"));
		// 서버 응답을 출력
        while ((temp = bufferedReader.readLine()) != null) {
            System.out.println(temp);
        }
        
        connection.disconnect();
        bufferedReader.close();
	}
}