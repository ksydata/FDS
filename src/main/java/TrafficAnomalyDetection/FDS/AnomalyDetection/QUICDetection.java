package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

public class QUICDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		// QUIC 프로토콜 패킷 판별: “frame.protocols”: “eth:ethertype:ip:udp:quic” 만 남기기
		JSONArray QUICPackets = new JSONArray();
		
		for (int i = 0; i < jsonDataArray.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	JSONObject frame = layers.getJSONObject("frame");
	    	
	    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:udp:quic")) {
	    		QUICPackets.put(packet);
	    	}
		}
		
//		System.out.println(QUICPackets);
		
		// 판별한 패킷 중에서 “frame.time_delta” 값이 5~10 사이인 경우가 5회 이상 지속될 시 위협으로 판별하기
		int count = 0;
		for (int i = 0; i < QUICPackets.length(); i++) {
			JSONObject packet = jsonDataArray.getJSONObject(i);
	    	JSONObject data = packet.getJSONObject("data");
	    	JSONObject layers = data.getJSONObject("layers");
	    	JSONObject frame = layers.getJSONObject("frame");
	    	
	    	String deltaTime = (String) frame.get("frame.time_delta");
	    	if (Double.parseDouble(deltaTime) >= 4.5 && Double.parseDouble(deltaTime) <= 10.5) {
	    		count++;
	    		System.out.println(count);
	    		
	    		if (count >= 5) {
	    			System.out.print("🚨 QUIC 공격 감지! 🚨 현재 카운트: " + count);
	    		}
	    	} else {
	    		count = 0;
	    	}
	    	
		}
		
	}
}
