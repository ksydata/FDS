package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;

public class UDPFloodDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		// 현재 패킷이 UDP 패킷인지 판별
		
		// 현재 패킷과 직후 패킷이 Source는 다르고 Destination은 같은 IP인지 확인.
		
		// UDP 패킷이 연속되어 진행되는 지 확인되면 카운트 올리기
		
		// 카운트가 10을 넘기면 UDP Flood로 판별
		
	}
	
}
