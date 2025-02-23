package TrafficAnomalyDetection.FDS.AnomalyDetection;

import org.json.JSONArray;
import org.json.JSONObject;
// https://ggonmerr.tistory.com/38
// https://blog.naver.com/stop2y/221018537228

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
            
            System.out.println("Packet at index " + index + ": " + packet.toString(2));

            // TCP 패킷 여부 확인
            if (layers.has("tcp")) {
                JSONObject tcpLayer = layers.getJSONObject("tcp");

                // tcp_flags 여부 확인 후 detectTcpFlags 메서드 호출
                if (tcpLayer.has("tcp_flags")) {
                    String tcpFlag = tcpLayer.getString("tcp_flags");
                    detectTcpFlags(tcpFlag, index);
                } else {
                    System.out.println("No 'tcp_flags' field found for TCP packet at index " + index);
                // No 'tcp_flags' field found for TCP packet at index ...
                // Closing MongoDB connection
                }
            } else {
                System.out.println("No 'tcp' field found for packet at index " + index);
            }
        } else {
            System.out.println("No 'data' or '_source' field found for packet at index " + index);
        }
    }
    
    // tcp_flags(16진수) 비트 분석하는 메서드
    private void detectTcpFlags(String tcpFlag, int index) {
        switch (tcpFlag) {
            // tcp.flags.reset == 1 && tcp.flags.ack == 1
            case "0x014":
                System.out.println("Closed Port Scan Detected (RST + ACK) Flags at index " + index);
                break;
            // tcp.flags.fin == 1 && tcp.flags.syn == 0 && tcp.flags.ack == 0
            case "0x001":
                System.out.println("Stealth Scan Detected (FIN) Flags at index " + index);
                break;
            // tcp.flags.fin == 1 && tcp.flags.urg == 1 && tcp.flags.psh == 1  
            case "0x029":
                System.out.println("Xmas Scan Detected (FIN + PSH + URG) Flags at index " + index);
                break;
            // tcp.flags == 0x000
            case "0x000":
                System.out.println("NULL Scan Detected <none>, No Flags at index " + index);
                break;
            // 정상 케이스인 TCP 연결 요청 케이스 추가
            // tcp.flags.syn == 1 && tcp.flags.ack == 0
            case "0x0002":
                System.out.println("Syn(Open) Scan Detected (SYN) Flags at index " + index);
                break;
            default:
                System.out.println("Unrecognized TCP flags: " + tcpFlag + " at index " + index);
        }
    }
}

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

/*
No 'tcp_flags' field found for TCP packet at index 52220
Packet at index 52221: {
  "data": {"layers": {
    "tcp": {
      "tcp.port": [
        "50744",
        "39757"
      ],
      "tcp.seq_raw": "1632836488",
      "tcp.nxtseq": "1",
      "tcp.flags": "0x0014",
      "tcp.checksum": "0xa928",
      "tcp.dstport": "39757",
      "tcp.len": "0",
      "tcp.window_size_scalefactor": "256",
      "tcp.ack_raw": "3429806538",
      "tcp.window_size_value": "0",
      "Timestamps": {
        "tcp.time_delta": "0.410013000",
        "tcp.time_relative": "45.124950000"
      },
      "tcp.seq": "1",
      "tcp.hdr_len": "20",
      "tcp.srcport": "50744",
      "tcp.window_size": "0",
      "tcp.checksum.status": "2",
      "tcp.stream": "6",
      "tcp.completeness": "30",
      "tcp.flags_tree": {
        "tcp.flags.ece": "0",
        "tcp.flags.ae": "0",
        "tcp.flags.syn": "0",
        "tcp.flags.ack": "1",
        "tcp.flags.push": "0",
        "tcp.flags.urg": "0",
        "tcp.flags.fin": "0",
        "tcp.flags.reset": "1",
        "tcp.flags.reset_tree": {"_ws.expert": {
          "_ws.expert.message": "Connection reset (RST)",
          "_ws.expert.severity": "6291456",
          "tcp.connection.rst": "",
          "_ws.expert.group": "33554432"
        }},
        "tcp.flags.cwr": "0",
        "tcp.flags.res": "0",
        "tcp.flags.str": "·······A·R··"
      },
      "tcp.ack": "25366310",
      "tcp.urgent_pointer": "0"
    },
    "ip": {
      "ip.hdr_len": "20",
      "ip.frag_offset": "0",
      "ip.len": "40",
      "ip.flags": "0x02",
      "ip.dsfield": "0x00",
      "ip.ttl": "128",
      "ip.src_host": "192.168.1.119",
      "ip.host": [
        "192.168.1.119",
        "200.236.31.1"
      ],
      "ip.version": "4",
      "ip.checksum.status": "2",
      "ip.dsfield_tree": {
        "ip.dsfield.ecn": "0",
        "ip.dsfield.dscp": "0"
      },
      "ip.flags_tree": {
        "ip.flags.rb": "0",
        "ip.flags.df": "1",
        "ip.flags.mf": "0"
      },
      "ip.src": "192.168.1.119",
      "ip.dst": "200.236.31.1",
      "ip.dst_host": "200.236.31.1",
      "ip.proto": "6",
      "ip.id": "0x12a9",
      "ip.addr": [
        "192.168.1.119",
        "200.236.31.1"
      ],
      "ip.checksum": "0x3e1a"
    },
    "eth": {
      "eth.dst_tree": {
        "eth.addr.oui": "7550",
        "eth.addr": "00:1d:7e:d9:94:c0",
        "eth.dst.oui_resolved": "Cisco-Linksys, LLC",
        "eth.dst_resolved": "Cisco-Li_d9:94:c0",
        "eth.addr_resolved": "Cisco-Li_d9:94:c0",
        "eth.dst.lg": "0",
        "eth.lg": "0",
        "eth.addr.oui_resolved": "Cisco-Linksys, LLC",
        "eth.dst.oui": "7550",
        "eth.dst.ig": "0",
        "eth.ig": "0"
      },
      "eth.dst": "00:1d:7e:d9:94:c0",
      "eth.src": "4c:80:93:06:e2:8f",
      "eth.src_tree": {
        "eth.addr.oui": "5013651",
        "eth.addr": "4c:80:93:06:e2:8f",
        "eth.src.oui": "5013651",
        "eth.addr_resolved": "IntelCor_06:e2:8f",
        "eth.src.ig": "0",
        "eth.src.lg": "0",
        "eth.lg": "0",
        "eth.addr.oui_resolved": "Intel Corporate",
        "eth.src_resolved": "IntelCor_06:e2:8f",
        "eth.src.oui_resolved": "Intel Corporate",
        "eth.ig": "0"
      },
      "eth.type": "0x0800"
    },
    "frame": {
      "frame.time": "Nov 16, 2013 02:04:29.643330000 UTC",
      "frame.offset_shift": "0.000000000",
      "frame.encap_type": "1",
      "frame.time_delta_displayed": "0.410013000",
      "frame.number": "52222",
      "frame.section_number": "1",
      "frame.time_relative": "89.109633000",
      "frame.marked": "0",
      "frame.interface_id": "0",
      "frame.time_delta": "0.410013000",
      "frame.ignored": "0",
      "frame.protocols": "eth:ethertype:ip:tcp",
      "frame.len": "54",
      "frame.time_epoch": "1384567469.643330000",
      "frame.interface_id_tree": {"frame.interface_name": "Unknown/not available in original file format(libpcap)"},
      "frame.cap_len": "54"
    }
  }},
  "_id": {"$oid": "67a59752d3966143a652f57a"}
}
No 'tcp_flags' field found for TCP packet at index 52221
Closing MongoDB connection
*/