package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.io.IOException;
import java.net.URLEncoder;
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
	
    public MainHTTP(String dnsURL, String method) {
        this.dnsURL = dnsURL;
        this.requestHandler = RequestHandlerFactory.getRequestHandler(method, dnsURL);
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
	
	public void loginSession(String dnsURL, String loginPage, String username, String password) throws Exception {
		String loginURL = dnsURL + loginPage + "&username" + username + "&password" + password;
		// loginPage = "/login.php"
		try {
	        // 로그인 후 세션 아이디 값을 받아 변수에 저장
			sessionID = requestHandler.sendRequest(loginURL);
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
		}
    }
}

/*
Enter the domain name: http://192.168.56.101/DVWA/login.php
Enter id: admin
Enter password: password
Do you want to simulate web hacking attack? (Y/N): Y
Enter attack Type: XSS_SQLINJECTION
Enter attack payload: <script>alert('XSS')</script>
java.lang.IllegalArgumentException: Invalid attack type http://192.168.56.101/DVWA/login.php?username=admin&password=password
 */

/*
Enter the domain name: http://192.168.56.101/DVWA/login.php
Enter id: admin
Enter password: password
Do you want to simulate web hacking attack? (Y/N): N
Enter request method (GET/POST): GET
Cookie is: PHPSESSID=pk488ap5v40cs5hfih7nugq8et; expires=Mon, 24 Mar 2025 11:46:05 GMT; Max-Age=86400; path=/; HttpOnly; SameSite=Strict
Session is: pk488ap5v40cs5hfih7nugq8et
Session is: {null=[HTTP/1.1 200 OK], Keep-Alive=[timeout=5, max=100], Server=[Apache/2.4.62 (Debian)], Cache-Control=[no-cache, must-revalidate], Connection=[Keep-Alive], Set-Cookie=[security=impossible; path=/; HttpOnly, PHPSESSID=b74d4v6736svvlj3fkqkchfpqu; expires=Mon, 24 Mar 2025 11:46:05 GMT; Max-Age=86400; path=/; HttpOnly; SameSite=Strict, PHPSESSID=pk488ap5v40cs5hfih7nugq8et; expires=Mon, 24 Mar 2025 11:46:05 GMT; Max-Age=86400; path=/; HttpOnly; SameSite=Strict], Vary=[Accept-Encoding], Expires=[Tue, 23 Jun 2009 12:00:00 GMT], Pragma=[no-cache], Content-Length=[1342], Date=[Sun, 23 Mar 2025 11:46:05 GMT], Content-Type=[text/html;charset=utf-8]}
 */

/*
Enter the domain name: http://www.dowellcomputer.com/hacking/member/memberLoginAction.jsp
Enter id: alwayssummer
Enter password: password

Enter request method (GET/POST): GET
Session is: JSESSIONID=CA3C59D94F0B1F3AFB04C4A6023F9CD1; Path=/; HttpOnly

Enter request method (GET/POST): POST
HTTP Response Code: 200
HTTP Response Message: OK
<script>location.href='../main.jsp';</script>
<script>alert('아이디가 존재하지 않습니다.');location.href='./memberLoginForm.jsp';</script>
<script>alert('비밀번호가 일치하지 않습니다.');location.href='./memberLoginForm.jsp';</script>

HTTP Response Code: 404
java.io.FileNotFoundException: URL
HTTP Response Message: Not Found
*/
