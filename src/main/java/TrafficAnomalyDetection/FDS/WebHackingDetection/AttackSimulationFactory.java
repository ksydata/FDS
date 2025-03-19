package TrafficAnomalyDetection.FDS.WebHackingDetection;

public class AttackSimulationFactory {
	public AttackSimulation executeSimulation(String attackType, String url, String payload) {
		switch(attackType) {
			case "XSS_SQLINJECTION":
				return new XSStoSQLiSimulation(url, payload);
			default:
				throw new IllegalArgumentException("Invalid attack type " + attackType);
		}
	}
 }