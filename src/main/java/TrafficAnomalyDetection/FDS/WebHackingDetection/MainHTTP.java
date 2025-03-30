package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookieStore;
import java.util.HashMap;
import java.util.Map;
//import java.net.URLEncoder;
import java.util.Scanner;

/* 
 * 1. 송수신자간 시간별 통신내역(세션, 통신 순서) 분석
 * 
 * 2. 전송파일 분석
 * GET 방식
 * SQLInjection, Reflect XSS, LFI, RFI
 * 
 * POST 방식
 * Stored XSS, CSRF, Webshell upload
 * 
 * 3. 악성코드 분석
 * Network Miner 툴 활용 -> tls 이걸 주로 분석할 수 있음. but, 이해를 못함
 * WireShark의 Statistics-Conversations
 */
// https://learn.microsoft.com/ko-kr/dotnet/api/system.web.ui.design.urlbuilder.buildurl?view=netframework-4.8
// https://blueyikim.tistory.com/2199


public class MainHTTP {
// 1. 로그인 과정 -> 2. 세션 유지(관리) -> 3. 공격 시뮬레이션
	private String dnsURL;
	private String sessionID;
	private RequestHandler requestHandler;
	private AttackSimulation attackSimulation;
    private CookieStore cookieStore;
    
    public MainHTTP(String dnsURL, String method) {
        this.dnsURL = dnsURL;
        this.requestHandler = RequestHandlerFactory.getRequestHandler(method, dnsURL);
        this.cookieStore = new CookieManager().getCookieStore();
    }

    public static void main(String[] args) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            // 사용자에게 도메인 주소 입력 받기
            System.out.print("Enter the domain name (e.g., http://example.com): ");
            String dnsURL = scanner.nextLine();
            // 사용자에게 HTTP 요청 메서드 입력 받기
            System.out.print("Enter request method (GET/POST): ");
            String method = scanner.nextLine();
            
            // MainHTTP 객체 생성
            MainHTTP mainHttp = new MainHTTP(dnsURL, method);

            // 사용자에게 로그인 페이지 확장자 입력 받기
            System.out.print("Enter the login page path (e.g. /login.php): ");
            String loginPage = scanner.nextLine();
            // 사용자 아이디와 패스워드 입력
            System.out.print("Enter id: ");
            String ID = scanner.nextLine();
            System.out.print("Enter password: ");
            String PW = scanner.nextLine();

            // 로그인 인증 수행
            mainHttp.loginSession(dnsURL, loginPage, ID, PW);

            // 공격 수행 여부 확인
            System.out.print("Do you want to simulate web hacking attack? (Y/N): ");
            String confirmation = scanner.nextLine();

            if ("Y".equalsIgnoreCase(confirmation)) {
                System.out.print("Enter the attack type (e.g. XSS, SQLI): ");
                String attackType = scanner.nextLine();
                System.out.print("Enter attack payload: ");
                String payload = scanner.nextLine();
                
                // 웹 모의해킹 수행
                mainHttp.executeAttack(attackType, payload);
            } else {
                System.out.println("Attack simulation canceled.");
            }
        }
    }
	
	public void loginSession(String loginPage, String username, String password) throws Exception {
        Map<String, String> loginParams = new HashMap<>();
        loginParams.put("username", username);
        loginParams.put("password", password);
		// String loginURL = dnsURL + loginPage + "&username" + username + "&password" + password;

        try {
	        // 로그인 후 세션 아이디 값을 받아 변수에 저장
			sessionID = requestHandler.sendRequest(cookieStore, loginParams);
			System.out.println("Session ID: " + sessionID);
		} catch (Exception e) {
			// e.printStackTrace();
            System.err.println("Failed to log in: " + e.getMessage());
		}
		// http://www.dowellcomputer.com/hacking/member/memberLoginAction.jsp
	    // http://www.dowellcomputer.com/hacking/member/memberUpdateForm.jsp?ID
	    // http://192.168.56.101/DVWA/login.php
	    // http://192.168.56.101/DVWA/vulnerabilities/sqli/?id=&Submit=Submit&user_token={}
	}
	
    public void executeAttack(String attackType, String payload) throws IOException {
    	if (sessionID == null || sessionID.isEmpty()) {
            throw new IllegalStateException("Session ID not found. Please log in first.");
        }
    	String attackURL = dnsURL + payload;
    	// 세션을 유지하면서 공격 요청
    	try {
            attackSimulation = AttackSimulationFactory.executeSimulation(attackType, dnsURL, payload);
			int result = attackSimulation.simulate(attackURL, sessionID);
			System.out.println("Web Hacking Attack Simulation: " + result);
    	} catch (Exception e) {
			// e.printStackTrace();
            System.err.println("Failed to execute attack: " + e.getMessage());
            // e.g. payload: /vulnerabilities/sqli/?id=1' OR '1'='1		}
    }
}
