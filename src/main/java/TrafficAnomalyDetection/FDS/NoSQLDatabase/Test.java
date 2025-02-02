package TrafficAnomalyDetection.FDS.NoSQLDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;

public class Test {
    
    private Map<String, List<String>> keyValuesMap = new HashMap<String, List<String>>();

    /**
     * @return the keyValuesMap
     */
    @JsonAnyGetter
    public Map<String, List<String>> getKeyValuesMap() {
        return keyValuesMap;
    }

    /**
     * @param keyValuesMap
     *            the keyValuesMap to set
     */
    public void setKeyValuesMap(Map<String, List<String>> keyValuesMap) {
        this.keyValuesMap = keyValuesMap;
    }

    @JsonAnySetter
    public void duplicateKeyValues(String key, String value) {
        List<String> values = null;
        if (!keyValuesMap.containsKey(key)) {
            values = new ArrayList<String>();
        } else {
            values = keyValuesMap.get(key);
        }
        values.add(value);
        keyValuesMap.put(key, values);
    }
}