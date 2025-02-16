package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;

public class AnalysisPacket extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		System.out.print("IP 주소 기반 이상행위, Port 스캔 공격 탐지");
		// 패킷 크기/빈도(타이밍) 분석, 비정상 시그니처 탐지
	}
}
