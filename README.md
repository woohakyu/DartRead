1. http://dart.fss.or.kr 에서 기업재무재표 읽기. (Python의 크롤러 이용)
 1.1 request로 기업정보를 요청
 1.2 bs4를 이용하여 Web에 보이는 차트형식( table, td , ... ) 를 파싱( Parsing )
 1.3 selenium 으로 javascript Call 해결 ( 브라우저엔진은 Chrome )
 
2. 1의 결과를 DB에 입력
 2.1 결과내용을 파일/직접입력 에 대해 결정하기.
   > cvs 파일 이면 그에 상응하는 연결 프로세스 (로직) 추가 개발. (Path 감시 프로그램을 C, Pro*C, BatchShell 중 택1 로 개발)
   > Python에서 OracleDB( 기타DB ) 제어로직 학습 필요.

# Python으로 모두 개발 한다면 좋겠으나 상황에 따라 유연하게 대처 하자. 크롤로(Web읽기)는 꼭Pythond으로
   그외는 추후 고민 하고
  가능한 이른 시일내로 위에 언급된 내용을 개발 할것.
 
 일정: 01/04/2018 - 30/04/2018
   > 약 한달을 개발일정을 놓고 할것, 단. 현재 직장근무및 4월중순 해외여행 계획으로 100% 쉽지 않으리라 본다.
   > 크롤러 부분에 대해서 파일출력(cvs) 까지는 할것.
 
 환경: 집에있는 Centos7 에서 할 예정이며, 회사에서 작업할때를 대비하여 윈도우/리눅스 모두 영향이 없으리라 보이나 
   상호 확인은 필요하며 Python버전은 3.6.2 로 하자( 파이썬책 기준:파이썬으로 배우는 웹크롤러,박정태지음,정보문화사 )
   GitClient는 반드시 필요하지 않으나 윈도우에서는 요구될수 있으니 회사에서는 사용하고 리눅스 환경에서는 터미널로 공유하는 방식으로 하자.

위 내용이 완료된다면 추후 계획.
  > 재무재표를 제외한 공시정보 ( 아마도 여려기업을 대상으로 한다면 매일 발표될것이다. )에 대해 분석을 프로세스 개발 하자.
     쉬운방향을 위해 공시대상목표설정후 작업할것.
  > 언론(신문,SNS,댓글) 목표로 크롤링 할것. 
  > 1순위. 신문뉴스 부터 DB보관 또는 파일로 보관 하고 
     그것에 따라 분석프로세스를 개발이 요구된다.
  > ...


그외 필요한 정보들은 필요할때마다 작성 하자.
