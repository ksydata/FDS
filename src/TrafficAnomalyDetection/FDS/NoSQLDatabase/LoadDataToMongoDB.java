// MongoDB와 상호작용하는 기능을 담당하는 클래스 LoadDataToMongoDB.java
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

// import com.mongodb.*;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoCollection;

import org.bson.Document;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;


public class LoadDataToMongoDB {
	// 필드 선언
	// 필드 - 객체의 데이터가 저장되는 곳
	private MongoClient mongoClient;
	private MongoDatabase database;
	
	// MongoDB 연동을 위한 ip주소, port번호를 포함한 로컬 주솟값과 데이터베이스명 입력받는 생성자
	// 생성자 - 객체 생성 시 초기화 역할
	public LoadDataToMongoDB(String connectionStiring, String dbName) {
		this.mongoClient = MongoClients.create(connectionStiring);
		this.database = mongoClient.getDatabase(dbName);
	}
	
	// json파일에서 데이터를 읽어와 MongoDB 컬렉션에 삽입하는 메서드
	// 메서드 - 객체의 동작으로 호출 실행하는 블록
	public void insertDataFromFile(String collectionName, String filePath) throws IOException {
		// DB 서버에 접속
        MongoCollection<Document> collection = database.getCollection(collectionName);
        
        // 경로 내 파일에서 json 데이터 로드(json 대신 csv 파일을 사용 가능)
		String jsonData = new String( Files.readAllBytes( Paths.get(filePath) ) );
		JSONObject jsonObject = new JSONObject(jsonData);
		
		// json 데이터를 MongoDB Document로 변환하여 데이터 삽입
		Document document = Document.parse(jsonObject.toString());
		collection.insertOne(document);
		// collection.insertOne(document);

		System.out.println(document.toJson());
	}
	
	// 리소스를 정리하는 메서드
	public void close() {
		if (mongoClient != null) {
			mongoClient.close();
			System.out.println("Closing MongoDB connection");
			// System.exit(0)
		}
	}
}
