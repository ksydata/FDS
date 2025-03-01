package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;

public class UDPFloodDetection extends AnomalyDetection {
	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		
		int count = 0;
		for (int i = 0; i < jsonDataArray.length(); i++) {
			
			JSONObject packet = jsonDataArray.getJSONObject(i);
			
			// 현재 패킷이 UDP 패킷인지 판별
			if (UDPDetection(packet) && i+1 < jsonDataArray.length()) {
				JSONObject layers = getPacketLayers(packet);
				JSONObject ip = layers.getJSONObject("ip");
				JSONObject targetPkt = jsonDataArray.getJSONObject(i+1);
				
				if (UDPDetection(targetPkt)) {
					JSONObject targetLayers = getPacketLayers(targetPkt);
					JSONObject targetIp = targetLayers.getJSONObject("ip");
					
					String ipSrc = ip.getString("ip.src");
			    	String ipDst = ip.getString("ip.dst");
			    	String targetIpSrc = targetIp.getString("ip.src");
			    	String targetIpDst = targetIp.getString("ip.dst");
			    	
			    	// 현재 패킷과 직후 패킷이 Source는 다르고 Destination은 같은 IP인지 확인.
			    	if (ipDst.equals(targetIpDst) && !ipSrc.equals(targetIpSrc)) {
			    		// UDP 패킷이 연속되어 진행되는 지 확인되면 카운트 올리기
			    		count++;
			    	}
			    	
			    	// 카운트가 10을 넘기면 UDP Flood로 판별
			    	if (count > 10) {
			    		System.out.println("UDP Flood : " + count);
			    	}
				} 
				// 패킷이 UDP가 아닐 시 카운트 초기화
				else {
					count = 0;
				}
			}
			
		}
		
				
		// UDP 패킷이 연속되어 진행되는 지 확인되면 카운트 올리기
		
		
		
	}
	
	public JSONObject getPacketLayers(JSONObject packet) {
		// 패킷에서 "layers" 만 남겨서 이하 "tcp", "frame" 등을 쉽게 뽑아서 사용할 수 있게 함
		JSONObject data = packet.getJSONObject("data");
    	JSONObject layers = data.getJSONObject("layers");
    	return layers;
	}
	
	public boolean UDPDetection(JSONObject packet) {
		// 패킷이 UDP 프로토콜인지 구별
    	JSONObject layers = getPacketLayers(packet);
    	JSONObject frame = layers.getJSONObject("frame");
    	
    	if (frame.get("frame.protocols").equals("eth:ethertype:ip:udp:data")) {
    		return true;
    	} else {
    		return false;
    	}
	}
	
}
