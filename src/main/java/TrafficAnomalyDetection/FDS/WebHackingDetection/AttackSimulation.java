package TrafficAnomalyDetection.FDS.WebHackingDetection;

abstract class AttackSimulation {
	// 요청을 보낼 url을 문자열에 저장
	protected String url;
	
	// url을 초기화하는 생성자
	public AttackSimulation(String url) {
		this.url = url;
	}
	// 공격 시뮬레이션을 할 수 있도록 각 기능 클래스에서 구현하기 위해 정의하는 추상 메서드
	public abstract void simulate() throws Exception;
}