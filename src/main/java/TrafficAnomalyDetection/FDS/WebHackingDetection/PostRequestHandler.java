package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

class PostRequestHandler extends RequestHandler {
	// 부모 클래스인 RequestHandler를 상속받아 초기화 생성자를 호출하여 url 설정
	public PostRequestHandler(String url) {
		super(url);
	}
	// POST 방식의 요청을 처리하는 기능 메서드
	// 클라이언트에서 서버에 데이터를 URL에 포함하지 않고 요청의 본문(body)에 포함하여 전송할 때 주로 사용 
	@Override
	public void sendRequest(String parameter) throws Exception {
		// HTTP url 연결 변수 생성
		HttpURLConnection connection = (HttpURLConnection) new URL(url)
				.openConnection();
		// POST 요청 방식을 설정
		connection.setRequestMethod("POST");
			// •GET •POST •HEAD •OPTIONS •PUT •DELETE •TRACE 
		
		

		// 서버로부터 응답 데이터를 읽어오는 BufferedReader 생성
		BufferedReader bufferedReader = new BufferedReader(
				new InputStreamReader(
						connection.getInputStream(), "UTF-8"));
		// Q. temp?
		// 서버 응답을 출력
        // while ((temp = bufferedReader.readLine()) != null) {
            // System.out.println(temp);
	}
}