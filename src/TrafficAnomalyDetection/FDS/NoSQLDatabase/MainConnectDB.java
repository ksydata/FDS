// MongoDB에 데이터 삽입 기능을 실행하는 클래스
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import java.io.IOException;

import org.bson.Document;

public class MainConnectDB {
	public static void main(String[] args) {
		// 연결상수 enum에서 DB 연결정보 가져오기
		String connectionString = ConfigureMongoDB.CONNECTION_STRING.getValue();
		String dbName = ConfigureMongoDB.DATABASE_NAME.getValue();
		
		// LoadDataToMongoDB(MongoDB와 상호작용하는 기능) 클래스의 인스턴스 생성
		LoadDataToMongoDB mongoDBHandler = new LoadDataToMongoDB(connectionString, dbName);
		
		// 
		String filePath;
		String collectionName;
		
		try {
			mongoDBHandler.insertDataFromFile(collectionName, filePath);
		} catch (IOException e) {
			System.err.println("An error occurred while reading the file" + e.getMessage());
		} finally {
			mongoDBHandler.close();
		}
	}
}