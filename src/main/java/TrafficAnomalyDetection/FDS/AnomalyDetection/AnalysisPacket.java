package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;
// https://ggonmerr.tistory.com/38
// https://blog.naver.com/stop2y/221018537228
//SYN ACK(synchronize, acknowledge)는 TCP의 3-way handshake 맺을 때 교환되는 비트정보

public class AnalysisPacket extends AnomalyDetection {
    
    @Override
    public void executeDetection(JSONArray jsonDataArray) {
        for (int index = 0; index < jsonDataArray.length(); index++) {
            // JSON 배열 내 index 번째 document(패킷)을 JSON 문자열 형식으로 변환 
            JSONObject packet = jsonDataArray.getJSONObject(index);
            getPacket(packet, index);
        }
    }
    
    // 패킷에서 tcp 패킷 구조 확인하는 메서드
    private void getPacket(JSONObject packet, int index) {
        // _source(data) 필드 layers 아래에 패킷의 구조 정의(이더넷, IP, TCP, TLS 등)
        if (packet.has("data")) {
            JSONObject source = packet.getJSONObject("data");
            JSONObject layers = source.getJSONObject("layers");
            
            // TCP 패킷 여부 확인
            if (layers.has("tcp")) {
                JSONObject tcpLayer = layers.getJSONObject("tcp");

                // tcp_flags 여부 확인 후 detectTcpFlags 메서드 호출
                if (tcpLayer.has("tcp.flags")) {
                    String tcpFlag = tcpLayer.getString("tcp.flags");
                    detectTcpFlags(tcpFlag, index);
                } else {
                    System.out.println("No 'tcp.flags' field found for TCP packet at index " + index);
                // No 'tcp_flags' field found for TCP packet at index ...
                // Closing MongoDB connection
                }
            } else {
            	System.out.println();
                // System.out.println("No 'tcp' field found for packet at index " + index);
            }
        } else {
            System.out.println("No 'data' or '_source' field found for packet at index " + index);
        }
    }
    
    // tcp_flags(16진수) 비트 분석하는 메서드
    private void detectTcpFlags(String tcpFlag, int index) {
        switch (tcpFlag) {
            // tcp.flags.reset == 1 && tcp.flags.ack == 1
            case "0x14":
                System.out.println("Closed Port Scan Detected (RST + ACK) Flags at index " + index);
                break;
            // tcp.flags.fin == 1 && tcp.flags.syn == 0 && tcp.flags.ack == 0
            case "0x01":
                System.out.println("Stealth Scan Detected (FIN) Flags at index " + index);
                break;
            // tcp.flags.fin == 1 && tcp.flags.urg == 1 && tcp.flags.psh == 1  
            case "0x029":
                System.out.println("Xmas Scan Detected (FIN + PSH + URG) Flags at index " + index);
                break;
            // tcp.flags == 0x000
            case "0x00":
            // if (tcpFlag == null || tcpFlag.isEmpty())
                System.out.println("NULL Scan Detected <none>, No Flags at index " + index);
                break;
            // 정상 케이스인 TCP 연결 요청 케이스 추가
            // tcp.flags.syn == 1 && tcp.flags.ack == 0
            case "0x0002":
                System.out.println("Syn(Open) Scan Detected (SYN) Flags at index " + index);
                break;
            // default:
                // System.out.println("Unrecognized TCP flags: " + tcpFlag + " at index " + index);
        }
    }
}

/*
Syn(Open) Scan Detected (SYN) Flags at index 0
Syn(Open) Scan Detected (SYN) Flags at index 13
Syn(Open) Scan Detected (SYN) Flags at index 32
Syn(Open) Scan Detected (SYN) Flags at index 50
Syn(Open) Scan Detected (SYN) Flags at index 71
Syn(Open) Scan Detected (SYN) Flags at index 2731
Syn(Open) Scan Detected (SYN) Flags at index 3959
Closing MongoDB connection
 */

/*
				// TCP 패킷 여부 확인
				if (layers.has("tcp")) {
	                JSONObject tcpLayer = layers.getJSONObject("tcp");
	                // 'tcp_srcport'. 'tcp_dstport', 'tcp_flags'
	                
	                // tcp_flags 여부 확인
	                if (tcpLayer.has("tcp_flags")) {
	                	String tcpFlag = tcpLayer.getJSONArray("tcp_flags").getString(0);
	                	
	                	// 닫힌 포트
	                	if (tcpFlag.contains("0x014")) {
	                		System.out.println("Closed Port Scan Detected (RST + ACK) flag at index " + index);
	                	} else if (tcpFlag.contains("0x001")) {
	                		System.out.println("Stealth Scan Detecated (FIN) flag at index " + index);
	                	} else if (tcpFlag.contains("0x029")) {
	                		System.out.println("Xmas Scan Detected (FIN + PSH + URG) flag at index " + index);
	                	} else if (tcpFlag.contains("0x000")) {
	                		System.out.println("NULL Scan Detected <none> at index " + index);
	                	}
	                }
				}
 */