package TrafficAnomalyDetection.FDS.AnomalyDetection;

import TrafficAnomalyDetection.FDS.NoSQLDatabase.ConfigureMongoDB;
import TrafficAnomalyDetection.FDS.NoSQLDatabase.LoadDataToMongoDB;

import java.io.IOException;
import java.util.Scanner;
import org.json.JSONArray;


public class MainFDS {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter mongoDB collection name: ");
        String collectionName = scanner.nextLine();
        System.out.print("Enter anomaly detection type: ");
        String detectionType = scanner.nextLine();
        
        // 연결상수 enum에서 DB 연결정보 가져오기
        String connectionString = ConfigureMongoDB.CONNECTION_STRING.getValue();
        String dbName = ConfigureMongoDB.DATABASE_NAME.getValue();
    
        // LoadDataToMongoDB(MongoDB와 상호작용하는 기능) 클래스의 인스턴스 생성
        LoadDataToMongoDB mongoDBHandler = new LoadDataToMongoDB(connectionString, dbName);
        
        // MongoDB에서 데이터 불러오기
        JSONArray jsonDataArray= mongoDBHandler.getDataFromCollectionAsArray(collectionName);
        
        AnomalyDetection packetAnalysis = AnomalyDetectionFactory.getAnomalyDetection(detectionType);
        if (packetAnalysis != null) {
        	packetAnalysis.executeDetection(jsonDataArray);
        } else {
        	System.out.println("Invalid anomaly detection type");
        }
        
        
        // 객체 리소스 종료
        mongoDBHandler.close();
        scanner.close();
    }
}

/*
 * Enter mongoDB collection name: TWOHOSTS_PACKET
* Enter ObjectId: 679db6d476bcf5c24259d9a3
* Feb 01, 2025 3:32:06 PM com.mongodb.diagnostics.logging.Loggers shouldUseSLF4J
WARNING: SLF4J not found on the classpath.  Logging is disabled for the 'org.mongodb.driver' component
{"_index":"packets-2013-11-16","_type":"doc","_source":{"layers":{"tcp":{"tcp.port":"21","tcp.seq_raw":"3961669297","tcp.analysis":{"tcp.analysis.ack_rtt":"0.000197000","tcp.analysis.initial_rtt":"0.207645000","tcp.analysis.acks_frame":"20"},"tcp.nxtseq":"55","tcp.flags":"0x0010","tcp.checksum":"0xa9f8","tcp.dstport":"21","tcp.len":"0","tcp.window_size_scalefactor":"4","tcp.ack_raw":"2295146669","tcp.window_size_value":"16293","Timestamps":{"tcp.time_delta":"0.000197000","tcp.time_relative":"1.665937000"},"tcp.seq":"55","tcp.hdr_len":"20","tcp.srcport":"21262","tcp.window_size":"65172","tcp.checksum.status":"2","tcp.stream":"0","tcp.completeness":"15","tcp.flags_tree":{"tcp.flags.ece":"0","tcp.flags.ae":"0","tcp.flags.syn":"0","tcp.flags.ack":"1","tcp.flags.push":"0","tcp.flags.urg":"0","tcp.flags.fin":"0","tcp.flags.reset":"0","tcp.flags.cwr":"0","tcp.flags.res":"0","tcp.flags.str":"·······A····"},"tcp.ack":"526","tcp.urgent_pointer":"0"},"ip":{"ip.hdr_len":"20","ip.frag_offset":"0","ip.len":"40","ip.flags":"0x02","ip.dsfield":"0x00","ip.ttl":"128","ip.src_host":"192.168.1.72","ip.host":"200.236.31.1","ip.version":"4","ip.checksum.status":"2","ip.dsfield_tree":{"ip.dsfield.ecn":"0","ip.dsfield.dscp":"0"},"ip.flags_tree":{"ip.flags.rb":"0","ip.flags.df":"1","ip.flags.mf":"0"},"ip.src":"192.168.1.72","ip.dst":"200.236.31.1","ip.dst_host":"200.236.31.1","ip.proto":"6","ip.id":"0x43ce","ip.addr":"200.236.31.1","ip.checksum":"0x0000"},"eth":{"eth.dst_tree":{"eth.addr.oui":"11296016","eth.addr":"ac:5d:10:11:e2:b9","eth.dst.oui_resolved":"Pace Americas","eth.dst_resolved":"PaceAmer_11:e2:b9","eth.addr_resolved":"PaceAmer_11:e2:b9","eth.dst.lg":"0","eth.lg":"0","eth.addr.oui_resolved":"Pace Americas","eth.dst.oui":"11296016","eth.dst.ig":"0","eth.ig":"0"},"eth.dst":"ac:5d:10:11:e2:b9","eth.src":"d4:85:64:a7:bf:a3","eth.src_tree":{"eth.addr.oui":"13927780","eth.addr":"d4:85:64:a7:bf:a3","eth.src.oui":"13927780","eth.addr_resolved":"HewlettP_a7:bf:a3","eth.src.ig":"0","eth.src.lg":"0","eth.lg":"0","eth.addr.oui_resolved":"Hewlett Packard","eth.src_resolved":"HewlettP_a7:bf:a3","eth.src.oui_resolved":"Hewlett Packard","eth.ig":"0"},"eth.type":"0x0800"},"frame":{"frame.time":"Nov 16, 2013 02:03:02.199634000 UTC","frame.offset_shift":"0.000000000","frame.encap_type":"1","frame.time_delta_displayed":"0.000197000","frame.number":"21","frame.section_number":"1","frame.time_relative":"1.665937000","frame.marked":"0","frame.interface_id":"0","frame.time_delta":"0.000197000","frame.ignored":"0","frame.protocols":"eth:ethertype:ip:tcp","frame.len":"54","frame.time_epoch":"1384567382.199634000","frame.interface_id_tree":{"frame.interface_name":"Unknown/not available in original file format(libpcap)"},"frame.cap_len":"54"}}},"_id":{"$oid":"679db6d476bcf5c24259d9a3"},"_score":null}
Closing MongoDB connection

 */