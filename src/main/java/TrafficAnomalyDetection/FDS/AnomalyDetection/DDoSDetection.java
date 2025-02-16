package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;

public class DDoSDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		System.out.print("트래픽 비율 분석결과 DDoS공격이나 스캐닝 공격 탐지");
	}
}
