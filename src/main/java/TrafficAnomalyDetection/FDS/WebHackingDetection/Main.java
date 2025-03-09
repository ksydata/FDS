package TrafficAnomalyDetection.FDS.WebHackingDetection;

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
 * Network Miner 툴 활용
 * WireShark의 Statistics-Conversations
 */

public class Main {

	public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            // 외부 입력으로 URL 및 파라미터 받기
            String url = "http://example.com";
            String memberID = "test"; // memberID 값
            String memberPW = "test"; // memberPassword 값

            // GET 방식의 요청 처리
            RequestHandler getRequestHandler = new GetRequestHandler(url);
            
            // URL에 파라미터를 포함하여 GET 요청을 보낼 준비
            String params = "memberID=" + memberID + "&memberPassword=" + memberPW;
            getRequestHandler.sendRequest(params); // GET 방식 요청 실행

            // POST 방식의  요청 처리
            RequestHandler postRequestHandler = new PostRequestHandler(url);
            postRequestHandler.sendRequest(params); // POST 방식 요청 실행
        
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}