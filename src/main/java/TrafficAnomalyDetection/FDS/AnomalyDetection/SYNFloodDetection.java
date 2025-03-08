package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

public class SYNFloodDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		int count = 0;
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			// 현재 패킷이 TCP, SYN 패킷인지 판별
			if (DetectionTools.TCPDetection(packet) && i+1 < jsonDataArray.length()) {
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				
				if (DetectionTools.FlagDetection(packet).equals("SYN") && DetectionTools.TCPDetection(targetPkt)) {
					String ipSrc = DetectionTools.getPacketIPInfo(packet)[0];
					String ipDst = DetectionTools.getPacketIPInfo(packet)[1];
					String targetIpSrc = DetectionTools.getPacketIPInfo(targetPkt)[0];
					String targetIpDst = DetectionTools.getPacketIPInfo(targetPkt)[1];
			    	
			    	// 현재 패킷과 직후 패킷이 Source는 다르고 Destination은 같은 IP인지 확인.
			    	if (ipDst.equals(targetIpDst) && !ipSrc.equals(targetIpSrc)) {
			    		// SYN 패킷이 연속되어 진행되는 지 확인되면 카운트 올리기
			    		if (DetectionTools.FlagDetection(targetPkt).equals("SYN")) {
			    			count++;
			    			
			    			// 카운트가 10을 넘기면 SYN Flood로 판별
			    			if (count > 10) {
			    				System.out.println("SYN Flood: " + count);
			    			}
			    		} 
			    		// ACK 패킷이 나올 시 카운트 초기화
			    		else if (DetectionTools.FlagDetection(targetPkt).equals("ACK")) {
			    			count = 0;
			    		}
			    	}
				}
			}
		}
		
	}
	

}
