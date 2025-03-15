package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
// https://velog.io/@reasonoflife39/JAVA%EB%A1%9C-HTTP-POST-%EC%9A%94%EC%B2%AD-%EB%B3%B4%EB%82%B4%EA%B8%B0
// https://velog.io/@ggg4155/22.03.03-%EC%84%B8%EC%85%98-%EC%A0%95%EB%B3%B4-%EA%B0%80%EC%A0%B8%EC%98%A4%EA%B8%B0

class PostRequestHandler extends RequestHandler {
	// 부모 클래스인 RequestHandler를 상속받아 초기화 생성자를 호출하여 url 설정
	public PostRequestHandler(String url) {
		super(url);
	}
	// HTTP 요청을 보내고, 서버로부터 응답을 읽어들이는 과정: POST 방식의 요청을 처리하는 기능 메서드
	// 클라이언트에서 서버에 데이터를 URL에 포함하지 않고 요청의 본문(body)에 포함하여 전송할 때 주로 사용 
	@Override
	public void sendRequest(String parameter) throws Exception {
		// HTTP url 연결 변수 생성
		HttpURLConnection connection = (HttpURLConnection) new URL(url)
				.openConnection();
		// POST 요청 방식을 설정하는 setter 메서드
		connection.setRequestMethod("POST");
			// •GET •POST •HEAD •OPTIONS •PUT •DELETE •TRACE 
		// url 연결 객체(connection)에서 요청 본문에 데이터를 전송할 수 있도록 연결과 관련된 OutputStream 객체를 사용하기 위한 setter 메서드
		connection.setDoOutput(true);			
			// .setChunkedStreamingMode(int chunkLength): 콘텐츠 길이를 미리 알 수 없을 때 HTTP 요청 본문 스트리밍
			// .setFollowRedirects(boolean follow): HTTP 리다이렉션 뒤에 이 클래스의 미래 객체가 자동으로 따라야 하는지 여부 결정
			// .setInstanceFollowRedirects(boolean follow)
			// .setRequestProperty("Content-Type", "application/json");
		
		// 출력 스트림(서버에 데이터를 보내는 통로)을 열기 위해 객체를 가져오는 getter 메서드
		try (OutputStream os = connection.getOutputStream()) {
			// 전송할 데이터를 UTF-8 형식으로 인코딩
			// 바이트 단위로 변환해야 네트워크를 통한 서버 전송 가능
			byte[] input = parameter.getBytes("UTF-8");
			// 변환된 바이트 배열로 출력 스트림을 통해 전송
			os.write(input, 0, input.length);
		}
		
		int httpResponseCode = connection.getResponseCode(); // .message()
		System.out.println("HTTP Response Code: " + httpResponseCode);
		
		// 서버로부터 응답 데이터를 읽어오는 BufferedReader 객체 생성
		BufferedReader bufferedReader = new BufferedReader(
				new InputStreamReader(
						connection.getInputStream(), "UTF-8"));
		// 서버 응답을 저장하는 StringBuffer 객체 생성
		StringBuffer serverResponse = new StringBuffer();
		// 한 줄씩 읽고, 그 내용을 StringBuffer에 추가하기 위한 문자열 선언
		String line;
		
		// 응답 데이터를 한 줄씩 읽어서 StringBuffer 객체에 저장
		// 각 줄을 읽어와 line 변수에 저장: line = bufferedReader.readLine()
		// loop 중단 조건: line != null
		while ( (line = bufferedReader.readLine()) != null ) {
			serverResponse.append(line);
		}
		// 리소스 해제
		bufferedReader.close();
		// 받은 응답을 하나의 문자열로 변환 후 콘솔창에 출력
		System.out.println(serverResponse.toString());
	}
}