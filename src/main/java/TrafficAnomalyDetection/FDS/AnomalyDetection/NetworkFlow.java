package TrafficAnomalyDetection.FDS.AnomalyDetection;
 import org.json.JSONArray;
//[ {...}, {...} ] - JSONArray, JSON 파일이 배열로 시작하는 경우
import org.json.JSONObject;
//{ ... } 형식 - JSONObject로 읽는 경우

public class NetworkFlow {
//	public void executeDetection(JSONObject jsonDataObject) {
//		System.out.println(jsonDataObject);
	 public void executeDetection(JSONArray jsonDataArray) {
		 System.out.println(jsonDataArray.length());
		 System.out.println(jsonDataArray.getJSONObject(0));
	}
};