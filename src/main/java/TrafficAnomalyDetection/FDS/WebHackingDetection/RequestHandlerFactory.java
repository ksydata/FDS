package TrafficAnomalyDetection.FDS.WebHackingDetection;

// HTTP 헤더 요청 방식을 Main 클래스에서 입력받아 객체를 생성하는 추상 팩토리 클래스
class RequestHandlerFactory {
	public static RequestHandler getRequestHandler(String method, String url) {
		if ("GET".equalsIgnoreCase(method)) {
			return new GetRequestHandler(url);
		} else if ("POST".equalsIgnoreCase(method)) {
			return new PostRequestHandler(url);
		} else {
			System.out.println("Not proper method type!");
		}
		return null;
	}
}