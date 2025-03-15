package TrafficAnomalyDetection.FDS.AnomalyDetection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/* SYN Flooding Attack 방식일 경우
 * 1. 공격자가 서버에 SYN(플래그) 전송
 * 2. 서버에서 SYN 응답으로 ACK를 보내고, 연결을 위해 SYN 전송(백로그 큐에서 대기시간 75초 경과 후 사라짐)
 * 3.1. 공격자는 ACK를 전송하지 않고, 대량의 SYN을 전송
 * 3.2. 공격자는 SYN 패킷 발송시 source IP주소를 존재하지 않는 주소로 설정 후 전송
 * 4. 서버는 SYN에 대응하기 위해 사용하지 않는 포트 할당하다가 모든 포트 사용 시 서버 다운
 */
// https://blog.naver.com/shj1126zzang/90193887664
// https://velog.io/@cchoijjinyoung/%EC%9E%90%EB%A3%8C%EA%B5%AC%EC%A1%B0-5-HashMap%ED%95%B4%EC%8B%9C%EB%A7%B5%EC%9D%84-%EC%95%8C%EC%95%84%EB%B3%B4%EC%9E%90

/* 문제의 소재
 * 1. IP 주소별로 SYN, ACK 요청을 집계하지 못함
 * 2. SYN Flooding 탐지 로직이 시간 간격 없이 지속적으로 집계하여 공격 상황을 탐지하지 못함
 * 
 * 대안
 * 1. IP별로 그룹화된 데이터에 대해서만 루프를 돌리고, 그 안에서 SYN/ACK 플래그를 집계
 */

public class SynFloodingDetection extends AnomalyDetection {
	
	// SYN 플래그 16진수
	private static final String SYN_FLAG = "0x0002"; // "0x02"
	private static final String ACK_FLAG = "0x0010"; // "0x10"
		// private static final int FIN_FLAG = 0x01;
		// private static final int NULL_FLAG = 0x00;
	// 특정 시간 동안의 SYN 요청 패킷 수의 임계치 설정
	private static final int SYN_THRESHOLD = 10;
	// 특정 시간의 범위 설정(현재 미사용)
	private static final int TIME_WINDOW_MS = 10000; // 10,000ms = 10초
	
	// SYN, ACK 패킷의 양 분석하기 위한 전역 변수 정의(IP별 SYN 패킷 비율 및 ACK 응답 비율 계산)
	// int synCount = 0;
	// int ackCount = 0;
	
	// IP별로 SYN 및 ACK 패킷의 수를 집계하는 해시맵 정의(IP 주소를 키로 하고 SYN/ACK 패킷 수를 값으로 저장하는 전역변수)
	Map<String, Integer> synPacketCount = new HashMap<>(); // HASHMAP == DATAFRAME(HASHTABLE)
	Map<String, Integer> ackPacketCount = new HashMap<>();
    Map<String, List<JSONObject>> ipGroupData = new HashMap<>();

	@Override
	public void executeDetection(JSONArray jsonDataArray) {
		// 서버의 백로그 큐(연결 대기 큐)가 source IP주소가 조작된 공격자의 SYN 패킷으로 가득 차서 서비스 거부(Denial of Service)
		int totalLength = jsonDataArray.length();

		for (int i = 0; i < totalLength; i++) {
			JSONObject jsonDataObject = jsonDataArray.getJSONObject(i);
			// IP 주소, 플래그 추출하는 메서드 적용
			String[] ipInfo = extractIP(jsonDataObject);
			// TEST -> TRUE
			// System.out.println(ipInfo[0] + ipInfo[1] + ipInfo[2]);

			if (ipInfo != null) {
				String sourceIP = ipInfo[1];

				// 추출된 IP별로 JSON 객체 그룹화
				ipGroupData.computeIfAbsent(
						sourceIP, k -> new ArrayList<>()).add(jsonDataObject);
	        }
	    }
	
		// 추출된 IP별로 JSON 객체 그룹화	
		for (String ip : ipGroupData.keySet()) {
			List<JSONObject> packetForIP = ipGroupData.get(ip);
			
			for (JSONObject packet : packetForIP) {
				String[] ipInfo = extractIP(packet);
				if (ipInfo != null) {
	                String flagsIP = ipInfo[0];
					// int flagsIP = Integer.parseInt(ipInfo[0]);
	                String sourceIP = ipInfo[1];
	                // String destinationIP = ipInfo[2];
	                
	                // TCP 플래그 카운트
	                countFlags(flagsIP, sourceIP);
					// countFlags(flagsIP, sourceIP, destinationIP);
				}
		    }
		}
		
		// 클래스 변수에 저장된 데이터를 활용하여 SYN 플러딩 공격 탐지 메서드 적용
		detectSYNFlooding();
		
		// TCP 플래그 카운트 출력
		// if (synCount > ackCount) System.out.printf("Total Length: %d, SYN Count: %d, ACK Count: %d%n", totalLength, synCount, ackCount);
	}
			
	// 데이터에서 IP 패킷 찾아서 출발지 IP, 도착지 IP 추출
	private String[] extractIP(JSONObject packet) {
	    // 변수들을 상단에서 선언
	    String sourceIP = null;
	    String destinationIP = null;
	    String flagsIP = null;
	    
	    if (packet.has("data")) {
	        JSONObject source = packet.getJSONObject("data");
	        JSONObject layers = source.getJSONObject("layers");

	        // IP 패킷 여부 확인
	        if (layers.has("ip")) {
	            JSONObject ipLayer = layers.getJSONObject("ip");
	            sourceIP = ipLayer.optString("ip.src", null);
                // String sourceIP = ipLayer.getString("src");
	            destinationIP = ipLayer.optString("ip.dst", null);
                // String destinationIP = ipLayer.getString("dst");	            
	        }

	        // TCP 패킷 여부 확인
	        if (layers.has("tcp")) {
	            JSONObject tcpLayer = layers.getJSONObject("tcp");
	            flagsIP = tcpLayer.optString("tcp.flags", "0");
                // int flagsIP = ipLayer.getInt("flags");
	        }
	    }
	    
	    if (sourceIP != null || destinationIP != null || flagsIP != null) {
	        return new String[]{sourceIP, destinationIP, flagsIP};
	    }
	    return null;
	}

	// SYN/ACK 플래그를 확인하고, 카운트를 증가시키는 메서드
	// 입력변수에서 String destinationIP 제외
	private void countFlags(String flagsIP, String sourceIP) {
		// IP별로 SYN 패킷의 수를 집계
		if (SYN_FLAG.equals(flagsIP)) { 
			// synCount++;
			synPacketCount.put(
					sourceIP, 
					synPacketCount.getOrDefault(sourceIP, 0) + 1);
		}
		
		// IP별로 ACK 패킷의 수를 집계
		if (ACK_FLAG.equals(flagsIP)) {
			// ackCount++;
			ackPacketCount.put(
					sourceIP, 
					ackPacketCount.getOrDefault(sourceIP, 0) + 1);
			// ackPacketCount.put(destinationIP, ackPacketCount.getOrDefault(destinationIP, 0) + 1);
		}
	}
	
	// SYN flooding 공격을 탐지하는 메서드
	private void detectSYNFlooding() {
	    for (String ip : synPacketCount.keySet()) {
			int synRatio = synPacketCount.get(ip);
	        int ackRatio = ackPacketCount.getOrDefault(ip, 0);
	        
			// ACK가 없을 경우 비율 계산 오류 방지
			if (ackRatio == 0) ackRatio = 1;
			
			// SYN 패킷 수(synRatio)에 비해 ACK 패킷 수(ackRatio)가 너무 적을 때 공격 의심
			// SYN 패킷이 10개가 왔는데, ACK 패킷이 임계치(SYN_THRESHOLD)의 10% 미만
	        if (synRatio > SYN_THRESHOLD && ackRatio < (synRatio * 0.1)) {
	            System.out.println("Detected SYN Flooding Attack from IP " + ip);
	        }
		}
	}
}
