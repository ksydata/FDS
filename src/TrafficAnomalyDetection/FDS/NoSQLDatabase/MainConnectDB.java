// MongoDB에 데이터 삽입 기능을 실행하는 클래스
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import java.io.IOException;
import java.util.Scanner;
//import org.bson.Document;

public class MainConnectDB {
	public static void main(String[] args) {
		// Scanner()를 통해 외부에서 파일경로와 컬렉션이름 입력받기
		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter the path to JSON file: ");
		String filePath = scanner.nextLine();
		// MongoDB는 데이터를 삽입하는 순간 컬렉션을 자동으로 생성
		System.out.print("Enter mongoDB collection name: ");
		String collectionName = scanner.nextLine();
		
		// 연결상수 enum에서 DB 연결정보 가져오기
		String connectionString = ConfigureMongoDB.CONNECTION_STRING.getValue();
		String dbName = ConfigureMongoDB.DATABASE_NAME.getValue();
		
		// LoadDataToMongoDB(MongoDB와 상호작용하는 기능) 클래스의 인스턴스 생성
		LoadDataToMongoDB mongoDBHandler = new LoadDataToMongoDB(connectionString, dbName);
		
		// 객체를 통해 접속한 DB에 데이터 삽입(실제 기능 수행)
		try {
			mongoDBHandler.insertDataFromFile(collectionName, filePath);
		} catch (IOException e) {
			System.err.println("An error occurred while reading the file" + e.getMessage());
        } catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
		} finally {
			mongoDBHandler.close();
		}
		scanner.close();
	}
}