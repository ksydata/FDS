package TrafficAnomalyDetection.FDS.WebHackingDetection;

import java.net.URLEncoder;
import java.util.Scanner;

/* 
 * 1. 송수신자간 시간별 통신내역(세션, 통신 순서) 분석 
 * 2. 전송파일 분석
 * GET 방식
 * SQLInjection, Reflect XSS, LFI, RFI
 * 
 * POST 방식
 * Stored XSS, CSRF, Webshell upload
 * 3. 악성코드 분석
 * 
 * Network Miner 툴 활용 -> tls 이걸 주로 분석할 수 있음. but, 이해를 못함
 * WireShark의 Statistics-Conversations
 */
// https://learn.microsoft.com/ko-kr/dotnet/api/system.web.ui.design.urlbuilder.buildurl?view=netframework-4.8
// https://blueyikim.tistory.com/2199

public class MainHTTP {

	public static void main(String[] args) throws Exception {
        try (Scanner scanner = new Scanner(System.in)) {
            // 사용자의 외부 입력으로 URL의 기본 호스트 주소(도메인 이름) 및 파라미터 받기
            System.out.print("Enter the domain name: ");
        	String dns = scanner.nextLine();
        	// http://www.dowellcomputer.com/hacking/member/memberLoginAction.jsp
        	// http://www.dowellcomputer.com/hacking/member/memberUpdateForm.jsp?ID
        	
        	System.out.print("Enter id: ");
            String memberID = scanner.nextLine();
            
            System.out.print("Enter password: ");
            String memberPW = scanner.nextLine();
            
            // 호스트, 경로, 쿼리 등 파라미터를 결합한 전체 URL
            String encodedID = URLEncoder.encode(memberID, "UTF-8");
            String encodedPW = URLEncoder.encode(memberPW, "UTF-8");
            String url = dns + "?memberID=" + encodedID + "&memberPassword=" + encodedPW;
            
            // 사용자의 외부 입력으로 HTTP 헤더 요청 방식 받기
            System.out.print("Enter request method (GET/POST): ");
            String method = scanner.nextLine();
            
            // 팩토리 클래스로 요청 핸들러 객체를 생성
            RequestHandler requestHandler = RequestHandlerFactory.getRequestHandler(method, url);
            
            requestHandler.sendRequest(url);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

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