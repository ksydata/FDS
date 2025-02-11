package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;

// 추상 클래스
public abstract class AnomalyDetection {
	public abstract void executeDetection(JSONArray jsonDataArray);
}
