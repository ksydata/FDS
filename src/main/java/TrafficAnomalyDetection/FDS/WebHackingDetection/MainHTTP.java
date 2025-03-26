package TrafficAnomalyDetection.FDS.WebHackingDetection;

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
 * 
 * Network Miner 툴 활용 -> tls 이걸 주로 분석할 수 있음. but, 이해를 못함
 * WireShark의 Statistics-Conversations
 */
// https://learn.microsoft.com/ko-kr/dotnet/api/system.web.ui.design.urlbuilder.buildurl?view=netframework-4.8
// https://blueyikim.tistory.com/2199


public class MainHTTP {
// 1. 로그인 과정 -> 2. 세션 유지(관리) -> 3. 공격 시뮬레이션
	public static void main(String[] args) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            // 사용자의 외부 입력으로 URL의 기본 호스트 주소(도메인 이름) 및 파라미터 받기
            System.out.print("Enter the domain name: ");
        	String dns = scanner.nextLine();
        	// http://www.dowellcomputer.com/hacking/member/memberLoginAction.jsp
        	// http://www.dowellcomputer.com/hacking/member/memberUpdateForm.jsp?ID
        	// http://192.168.56.101/DVWA/login.php
        	// http://192.168.56.101/DVWA/vulnerabilities/sqli/?id=&Submit=Submit&user_token=1b390a71714157dd68453245206a6061#
        	
        	System.out.print("Enter id: ");
            String memberID = scanner.nextLine();
            
            System.out.print("Enter password: ");
            String memberPW = scanner.nextLine();
            
            // 호스트, 경로, 쿼리 등 파라미터를 결합한 전체 URL
            String encodedID = URLEncoder.encode(memberID, "UTF-8");
            String encodedPW = URLEncoder.encode(memberPW, "UTF-8");
            String url = dns + "?username=" + encodedID + "&password=" + encodedPW;
            	// "?memberID=" "&memberPassword="
            
            // 모의해킹(공격 시뮬레이션) 수행 여부 확인
            if (isSimulateAttack(scanner)) {
                System.out.print("Enter attack Type: ");
                String attackType = scanner.nextLine();
                getAttackSimulation(url, attackType, scanner);
            } else {
                // 사용자의 외부 입력으로 HTTP 헤더 요청 방식 확인
                getHttpRequest(url, scanner);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

	private static boolean isSimulateAttack(Scanner scanner) {
		System.out.print("Do you want to simulate web hacking attack? (Y/N): ");
		String simulation = scanner.nextLine();
		return simulation.equalsIgnoreCase("Y");
	}
	
    private static void getAttackSimulation(String attackType, String url, Scanner scanner) {
        System.out.print("Enter attack payload: ");
        String attackPayload = scanner.nextLine();
        
        AttackSimulationFactory factory = new AttackSimulationFactory();
        AttackSimulation attackSimulation = factory.executeSimulation(attackType, url, attackPayload);
        try {
			attackSimulation.simulate();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
	private static void getHttpRequest(String url, Scanner scanner) {
        // 사용자의 외부 입력으로 HTTP 헤더 요청 방식 받기
		System.out.print("Enter request method (GET/POST): ");
        String method = scanner.nextLine();
        
        // 팩토리 클래스로 요청 핸들러 객체를 생성
        RequestHandler requestHandler = RequestHandlerFactory.getRequestHandler(method, url);
        try {
			requestHandler.sendRequest(url);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
