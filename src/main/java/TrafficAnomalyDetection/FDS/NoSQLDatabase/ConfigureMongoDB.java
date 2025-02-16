// MongoDB의 연결정보(상호작용하는 설정값)를 관리하는 enum 클래스
package TrafficAnomalyDetection.FDS.NoSQLDatabase;

public enum ConfigureMongoDB {
	CONNECTION_STRING("mongodb://localhost:27017"),
	DATABASE_NAME("TRF_CS_DB");
	// COLLECTION_NAME("");
	// 컬렉션은 여러 개의므로 동적으로 처리하도록 연결상수에서 제외
	
	private final String value;
	ConfigureMongoDB(String value) {
		this.value = value;
	}
	
	public String getValue() {
		return value;
	}
}
