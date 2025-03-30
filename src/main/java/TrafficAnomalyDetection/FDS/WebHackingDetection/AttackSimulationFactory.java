package TrafficAnomalyDetection.FDS.WebHackingDetection;

public class AttackSimulationFactory {
	public static AttackSimulation executeSimulation(String attackType, String url, String payload) {
		switch(attackType) {
			case "XSS_SQLI":
				return new XSStoSQLiSimulation(url);
			default:
				throw new IllegalArgumentException("Invalid attack type " + attackType);
		}
	}
 }