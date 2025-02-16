package TrafficAnomalyDetection.FDS.DataAPI;

// Google Analytics API(웹사이트나 앱의 방문자 통계 및 트래픽 데이터를 수집하는 도구)에 접속하기 위한 OAuth 2.0(사용자계정) 인증처리
/*
package TrafficAnomalyDetection.FDS.GoogleAnalyticsData;

// google-api-client: 구글의 다양한 API들과 상호작용할 수 있는 공통 클라이언트 라이브러리
//인증 정보(credentials)는 서버 환경에서만 사용되며, 사용자의 인증 정보와 액세스 토큰을 포함
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extentions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extentions.jetty.auth.oauth2.LocalServerReceiver;

// 
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

import com.google.api.services.analytics.Analytics;
import com.google.api.services.analytics.AnalyticsScopes;

import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

public class oauthAuthenticator {
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	// 비밀키 경로 지정
	private static final String CREDENTIALS_FILE_PATH = "/FDS/target/client_secret_549104259745-h6494ilsb6ld8umg7cjg9hvf536heo9k.apps.googleusercontent.com.json";
	// 사용자의 토큰을 어디에 저장할지 경로 설정
	private static final String APPLICATION_NAME = "Google Analytics Authentication";
  
	// OAuth 2.0 인증 처리
	public static Credential authorize() throws IOException, GeneralSecurityException {
		// client_secrets.json 파일을 프로젝트 경로에 저장 후 로드
		GoogleClientSecrets clientsecrets = GoogleClientSecrets.load(
				JSON_FACTORY, new FileReader(CREDENTIALS_FILE_PATH) );	
		// OAuth 2.0 코드플로우 설정
		GoogleAuthorizationCodeFlow flow = new GoogleAuthorization.Builder(
				GoogleNetHttpTransport.newTrustedTransport(), 
				JSON_FACTORY,
				clientSecrets,
				Collections.singleton(AnalyticsScopes.ANALYTICS_READONLY)
		).build();
	}
}
*/