package TrafficAnomalyDetection.FDS.WebHackingDetection;

abstract class RequestHandler {
	// 요청을 보낼 url을 문자열에 저장
	protected String url;
	
	// url을 초기화하는 생성자
	public RequestHandler(String url) {
		this.url = url;
	}
	
	// GET, POST(HTTP header method)와 같은 요청 방식을 
	// 확장성이 높도록 각 기능 클래스에서 구현하기 위해 정의하는 추상 메서드
	public abstract String sendRequest(String parameter) throws Exception;
}