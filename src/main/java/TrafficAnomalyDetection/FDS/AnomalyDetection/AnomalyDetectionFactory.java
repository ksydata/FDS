package TrafficAnomalyDetection.FDS.AnomalyDetection;

public class AnomalyDetectionFactory {

	public static AnomalyDetection getAnomalyDetection(String detectionType) {
		// 실행 클래스에서 detectionType을 입력받지 못했을 경우 null값 반환 
		if (detectionType == null) {
			return null;
		}
		
		// 실행 클래스에서 scanner를 통해 입력받은 detectionType에 따른 구체 클래스 반환
		if (detectionType.equalsIgnoreCase("IP_PORT_SCAN")) {
			return new AnalysisPacket();
		} else if (detectionType.equalsIgnoreCase("DDoS")) {
			return new DDoSDetection();
		} else {
			System.out.println("No proper detection type!");
		}
		// detectionType이 지정되지 않은 탐지 로직일 경우 null값 반환
		return null;
	}
}
