package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

//Json에서 {id: [1, 2]} 형태의 데이터를 정의하고 표현하기 위한 클래스
@JsonIgnoreProperties(ignoreUnknown = true)
public class MapSource {

    @JsonProperty("_source")
    @JsonDeserialize(using = DuplicateKeyDeserializer.class)  // JSON 변환 적용
    private Map<String, Object> source;

    public Map<String, Object> getSource() {
        return source;
    }

    public void setSource(Map<String, Object> source) {
        this.source = source;
    }
}