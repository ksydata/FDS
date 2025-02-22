package TrafficAnomalyDetection.FDS.AnomalyDetection;

public class AnomalyDetectionFactory {

	public static AnomalyDetection getAnomalyDetection(String detectionType) {
		// 실행 클래스에서 detectionType을 입력받지 못했을 경우 null값 반환 
		if (detectionType == null) {
			return null;
		}
		
		// 실행 클래스에서 scanner를 통해 입력받은 detectionType에 따른 구체 클래스 반환
		if (detectionType.equalsIgnoreCase("IP_PORT_SCAN")) {
			// "PACKET_PATTERN", ...
			return new AnalysisPacket();
		} else if (detectionType.equalsIgnoreCase("DDoS")) {
			return new DDoSDetection();
		} else if (detectionType.equalsIgnoreCase("SQLDetection")) {
			return new SQLInjectionDetection();
		 } else if (detectionType.equalsIgnoreCase("XSSInjection")) {
			return new XSSDetection();
		 } else if (detectionType.equalsIgnoreCase("Dridex")) {
			 return new DridexDetection();
		 } else if (detectionType.equalsIgnoreCase("SYNFlood")) {
			 return new SYNFloodDetection();
		 } else if (detectionType.equalsIgnoreCase("QUIC")) {
			 return new QUICDetection();
		 } else if (detectionType.equalsIgnoreCase("HALF_OPEN_SCAN")) {
			 return new PortScanDetection();
		 } else {
			System.out.println("No proper detection type!");
		 }
		
		// detectionType이 지정되지 않은 탐지 로직일 경우 null값 반환
		return null;
	}
}
