package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.*;

// {id: 1, id: 2} 형태의 데이터를 {id: [1, 2]}로 변환하기 위한 클래스
// Jackson 라이브러리의 JsonDeserializer를 수정하여 제작
public class DuplicateKeyDeserializer extends JsonDeserializer<Map<String, Object>> {
    @Override
    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JsonProcessingException {

        Map<String, Object> keyValuesMap = new HashMap<>();

        if (p.currentToken() != JsonToken.START_OBJECT) {
            throw new IOException("Expected JSON Object");
        }

        while (p.nextToken() != JsonToken.END_OBJECT) {
            String fieldName = p.getCurrentName();
            p.nextToken();

            if (p.currentToken() == JsonToken.START_OBJECT) {
                // 중첩 객체일 경우 재귀적으로 처리
                Map<String, Object> nestedMap = deserialize(p, ctxt);
                keyValuesMap.put(fieldName, nestedMap);
            } else if (p.currentToken() == JsonToken.VALUE_STRING) {
                String value = p.getText();

                if (keyValuesMap.containsKey(fieldName)) {
                    Object existingValue = keyValuesMap.get(fieldName);
                    if (existingValue instanceof List) {
                        ((List<String>) existingValue).add(value);
                    } else {
                        List<String> newList = new ArrayList<>();
                        newList.add(existingValue.toString()); // 기존 값 추가
                        newList.add(value); // 새 값 추가
                        keyValuesMap.put(fieldName, newList);
                    }
                } else {
                    keyValuesMap.put(fieldName, value);
                }
            } else {
                p.skipChildren();
            }
        }
        return keyValuesMap;
    }
}