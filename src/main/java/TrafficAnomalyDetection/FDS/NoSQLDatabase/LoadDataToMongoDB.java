// MongoDB와 상호작용하는 기능을 담당하는 클래스 LoadDataToMongoDB.java
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
// import com.mongodb.*;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.InsertManyOptions;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;

import org.bson.Document;
import org.json.JSONArray;
// [ {...}, {...} ] - JSONArray, JSON 파일이 배열로 시작하는 경우
import org.json.JSONObject;
//{ ... } 형식 - JSONObject로 읽는 경우

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
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
        
        // 경로 내 파일에서 json 데이터 로드(json 대신 csv 파일을 사용 가능) : Files.readAllBytes 대신 JsonParser 활용
//		String jsonData = new String( Files.readAllBytes( Paths.get(filePath) ) );
        JsonFactory factory = new JsonFactory();
        JsonParser parser = factory.createParser(new File(filePath));
        
        
		// Jackson ObjectMapper 불러오기
		ObjectMapper mapper = new ObjectMapper();
		
		// BATCH 로 모아서 데이터 입력할 수 있도록 준비
		List<Document> documents = new ArrayList<>();
		final int BATCH_SIZE = 100; // 배치 크기 (조절 가능)
		
		// JSON이 배열인지 확인
        if (parser.nextToken() != JsonToken.START_ARRAY) {
            throw new IOException("JSON 파일이 배열([])로 시작하지 않음.");
        }

        // BATCH로 MongoDB에 데이터 입력 진행
		 while (parser.nextToken() != JsonToken.END_ARRAY) {
            MapSource source = mapper.readValue(parser, MapSource.class);
            Document doc = new Document("data", source.getSource());
            documents.add(doc);

            // 배치 크기 도달 시 insertMany 수행
            if (documents.size() >= BATCH_SIZE) {
//            	System.out.println(documents);
                collection.insertMany(documents, new InsertManyOptions().ordered(false));
                documents.clear(); // 리스트 초기화
                System.gc(); // 메모리 해제
            }
        }
        
		
	}
	
	public JSONArray getDataFromCollectionAsArray(String collectionName) {
		// JSON 배열 객체 생성
		JSONArray jsonArray = new JSONArray();
		// MongoDB 컬렉션과 연동
		MongoCollection<Document> collection = database.getCollection(collectionName);
		// DB 커서 생성 - 쿼리 결과에 대한 포인터(도큐먼트의 위치정보만을 반환)
		MongoCursor<Document> cursor = collection.find().iterator();
		
		try {
			while (cursor.hasNext()) {
				Document docs = cursor.next();
				// 도큐먼트 객체 docs를 JSON 객체로 변환하여 Json 배열에 추가 
				JSONObject jsonObject = new JSONObject(docs.toJson());
				jsonArray.put(jsonObject);
			}
		} catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
		} finally {
			cursor.close();
		} 
		return jsonArray;
	}
	
    // MongoDB 컬렉션에서 단일 객체로 조회
    public JSONObject getDataFromCollectionAsObject(String collectionName, String objectId) {
        MongoCollection<Document> collection = database.getCollection(collectionName);
        Document query = new Document("_id", new org.bson.types.ObjectId(objectId));  
        Document result = collection.find(query).first();

        if (result != null) {
            return new JSONObject(result.toJson());
        } else {
            return null;
        }
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
