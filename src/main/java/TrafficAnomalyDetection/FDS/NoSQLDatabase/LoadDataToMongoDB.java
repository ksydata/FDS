// MongoDB와 상호작용하는 기능을 담당하는 클래스 LoadDataToMongoDB.java
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
// import com.mongodb.*;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;

import org.bson.Document;
import org.json.JSONArray;
import org.json.JSONException;
// [ {...}, {...} ] - JSONArray, JSON 파일이 배열로 시작하는 경우
import org.json.JSONObject;
//{ ... } 형식 - JSONObject로 읽는 경우
import org.json.JSONTokener;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.ArrayList;
 import java.util.Collections;


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
//		System.out.print(jsonData);
		
		// 참고: https://stackoverflow.com/questions/64181422/deserialize-json-with-duplicate-keys-using-jackson
		ObjectMapper mapper = new ObjectMapper();
		Test test = mapper.readValue(jsonData, Test.class);
		Map<String, List<String>> keyValuesMap = test.getKeyValuesMap();
        System.out.println(mapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(keyValuesMap));
		
//		JsonFactory factory = new JsonFactory();
//		JsonParser parser = factory.createJsonParser(Files.readAllBytes( Paths.get(filePath)));
//		parser.nextToken();  
//	    int count=0;
//	    while (parser.nextToken() != JsonToken.NOT_AVAILABLE) {    //loop until "}"
//	    	System.out.println(parser.nextToken());
//	        String fieldName = parser.getCurrentName();
//
//	        if(fieldName==null){
//	            break;
//	        }
//	        if(fieldName.equals("C")&&parser.getText().equals("C")){
//	            count++;
//	        }
//	        if (fieldName.equals("A")) {
//	            parser.nextToken();
//	            System.out.println("Value : " + parser.getText());
//	        }
//	    }
//	    System.out.println(count);
//	    parser.close();
		
		
        // JSONTokener를 사용해 중복 키를 허용
        JSONTokener tokener = new JSONTokener(jsonData);
        
//		JSONObject jsonObject = new JSONObject(jsonData);
//        JSONObject jsonObject = new JSONObject(tokener);
        JSONArray jsonArray = new JSONArray(tokener);
		
		// 중복된 키가 있는 경우(예: 호스트 IP주소가 두 개인 트래픽 - AWS, Google Cloud 등 트래픽 분산 처리하는 네트워크/클라우드 환경)
//		for (int i = 0; i < jsonArray.length(); i++) {
//			JSONObject jsonObject = jsonArray.getJSONObject(i);
//			
//			// json 데이터를 MongoDB Document로 변환하여 데이터 삽입
//			Document document = new Document("data", jsonArray.toString());
//				// Document document = Document.parse(jsonObject.toString());
//			
//			// 중복된 키를 데이터베이스 컬렉션 내 삽입 허용 
//			collection.insertOne(document);
//				// collection.insertOne(document);
//
//			System.out.println(document.toJson());
		
        // json 데이터를 MongoDB Document로 변환하여 데이터 삽입
 		Document document = new Document("data", jsonArray.toList());
// 		Document document = Document.parse(jsonObject.toString());
 		collection.insertOne(document);
 		// collection.insertOne(document);

 		System.out.println(document.toJson());
	
//		}
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
    
    // JSON 파일의 중복 필드 정리  (예: {'ip': 200, 'ip: 300} 을 {'ip': [200, 300]}으로 정리하기)
    // 원하는 방법: jsonArray.getJSONObject(i); 에서 중복 필드가 나올 때 (= IOException 발생), 
    // 그 중복 필드들을 한 리스트로 묶어주기
   
	
	// 리소스를 정리하는 메서드
	public void close() {
		if (mongoClient != null) {
			mongoClient.close();
			System.out.println("Closing MongoDB connection");
			// System.exit(0)
		}
	}
}
