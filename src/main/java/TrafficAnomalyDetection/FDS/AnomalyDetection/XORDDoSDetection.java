package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;
/*
 * XOR DDoS는 리눅스 시스템을 봇넷으로 사용하는 서비스 거부 공격
 * key = {0x42, 0x42, 0x32, 0x46, 0x41, 0x33, 0x36, ...}
 * # HEX값(TCP OPTION 헤더의 특정값)을 포함하는 KEY
 * 
 * def dec_conf(data):
 * 	   """XOR DDoS 악성코드의 c&c와 봇넷의 통신을 위한 구문"""
 *     rv = [ord(x) for x in data]
 *     for i, b in enumerate(rv):
 *     		b1 = b^key[i%len(key)]
 *     		rv[i] = chr(b1)		
 *     return rv
 */

// TRF_CS_DB(document): XORDDoS_SYNFLOODING_PACKET
public class XORDDoSDetection extends AnomalyDetection {
    
    @Override
    public void executeDetection(JSONArray jsonDataArray) {
        for (int index = 0; index < jsonDataArray.length(); index++) {
            // JSON 배열 내 index 번째 document(패킷)을 JSON 문자열 형식으로 변환 
            JSONObject packet = jsonDataArray.getJSONObject(index);
            getPacket(packet, index);
        }
    }
    
    // 패킷에서 데이터를 추출하고, XOR 디코딩 작업 
    private void getPacket(JSONObject packet, int index) {
    	String packetData = packet.getString("data");
    	// _source 필드가 mongoDB에서 data 필드로 변환
    	
    }
    
    private void decodeXOR(String data) {
    }
}