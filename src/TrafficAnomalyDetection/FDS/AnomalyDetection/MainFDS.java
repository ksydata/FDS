package TrafficAnomalyDetection.FDS.AnomalyDetection;

import TrafficAnomalyDetection.FDS.NoSQLDatabase.ConfigureMongoDB;
import TrafficAnomalyDetection.FDS.NoSQLDatabase.LoadDataToMongoDB;
import java.util.Scanner;
import org.json.JSONArray;


public class MainFDS {
	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter mongoDB collection name: ");
		String collectionName = scanner.nextLine();
		
		// 연결상수 enum에서 DB 연결정보 가져오기
		String connectionString = ConfigureMongoDB.CONNECTION_STRING.getValue();
		String dbName = ConfigureMongoDB.DATABASE_NAME.getValue();
	
		// LoadDataToMongoDB(MongoDB와 상호작용하는 기능) 클래스의 인스턴스 생성
		LoadDataToMongoDB mongoDBHandler = new LoadDataToMongoDB(connectionString, dbName);
		
		// MongoDB에서 데이터 불러오기
		JSONArray jsonDataArray = mongoDBHandler.getDataFromCollection(collectionName);
		
		// NetworkFlow 기능 클래스의 인스턴스 생성
		NetworkFlow networkFlow = new NetworkFlow();
		// 이상행위 탐지 로직 적용
		networkFlow.executeDetection(jsonDataArray);
		
		// 객체 리소스 종료
		mongoDBHandler.close();
		scanner.close();
	}
}

/*
 * 1. mongoDB에 저장한 컬렉션에서 데이터 골라서 Java 프로젝트로 로드하는 클래스 - 기존 코드 재활용
 * 3. 데이터를 불러와서 탐지 기능을 적용하는 메인 클래스
 * 2. 데이터에서 이상행위를 탐지하는 각종 기능 클래스
 */ 