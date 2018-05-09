:- compile('torCheckIPList.pl').
:- multifile rule/3.
:- multifile abducible/2.

rule(r_t_highSkill0(Att),neg(highLevelSkill(Att)),    []).
rule(r_t_highSkill1(Att),highLevelSkill(Att),    	[hijackCorporateClouds(Att)]).
rule(r_t_highSkill2(Att),highLevelSkill(Att),    	[malwareUsedInAttack(M,Att),sophisticatedMalware(M)]).
rule(r_t_highSkill3(Att),neg(highLevelSkill(Att)),	[malwareUsedInAttack(M,Att),neg(notForBlackMarketUse(M))]).
rule(r_t_highSkill4(Att),highLevelSkill(Att),    	[stolenValidSignedCertificates(Att)]).

rule(r_t_highResource0(Att),neg(requireHighResource(Att)),	[neg(highLevelSkill(Att))]).
rule(r_t_highResource1(Att),requireHighResource(Att),		[highLevelSkill(Att)]).
rule(r_t_highResource2(Att),requireHighResource(Att),		[highSecurity(T),target(T,Att)]).
rule(r_t_highResource3(Att),requireHighResource(Att),		[highVolumeAttack(Att),longDurationAttack(Att)]).


rule(r_t_noLocEvidence(X,Att),neg(attackPossibleOrigin(X,Att)),[]).
rule(r_t_srcIP1(X,Att),  attackPossibleOrigin(X,Att),     [malwareUsedInAttack(M,Att),attackSourceIP(IP,M),ipGeoloc(X,IP)]).
rule(r_t_srcIP2(X,Att),  attackPossibleOrigin(X,Att),     [majorityIpOrigin(X,Att)]).
rule(r_t_spoofIP(X,Att), neg(attackPossibleOrigin(X,Att)),[malwareUsedInAttack(M,Att),attackSourceIP(IP,M),spoofedIP(IP,Att),ipGeoloc(X,IP)]).

rule(r_t_IPdomain1(S,M), ccServer(S,M),					[attackSourceIP(IP,M),ipResolution(S,IP,_D)]).
rule(r_t_IPdomain2(S,M), neg(ccServer(S,M)),			[malwareUsedInAttack(M,Att),attackSourceIP(IP,M),ipResolution(S,IP,_D),spoofedIP(IP,Att)]).
rule(r_t_IPdomain3(S,M), neg(ccServer(S,M)),			[attackSourceIP(IP,M),ipResolution(S,IP,D),malwareUsedInAttack(M,Att),attackPeriod(Att,D1),neg(recent(D,D1))]).

rule(r_t_spoofIPtor(IP), spoofedIP(IP,Att), [malwareUsedInAttack(M,Att), attackSourceIP(IP,M), targetServerIP(TargetServerIP,Att), torIP(IP, TargetServerIP)]).
rule(r_t_lang1(X,Att),  attackPossibleOrigin(X,Att),     [sysLanguage(L,Att),firstLanguage(L,X)]).
rule(r_t_lang2(X,Att),  attackPossibleOrigin(X,Att),     [languageInCode(L,Att),firstLanguage(L,X)]).
rule(r_t_infra(X,Att),  attackPossibleOrigin(X,Att),     [infraUsed(Infra,Att),infraRegisteredIn(X,Infra)]).
rule(r_t_domain(X,Att), attackPossibleOrigin(X,Att),     [malwareUsedInAttack(M,Att),ccServer(S,M),domainRegisteredDetails(S,_,Addr),addrInCountry(Addr,X)]).

rule(r_t_recent1(Y), recent([Y,_],[Y,_]), []).
rule(r_t_recent2(Y1,Y2,M1,M2), recent([Y1,M1],[Y2,M2]), [Y1 is Y2 - 1,M1 > M2]).
rule(r_t_recent3(Y1,Y2,M1,M2), recent([Y1,M1],[Y2,M2]), [Y2 is Y1 - 1,M2 > M1]).

rule(r_t_attackOriginDefault(X,Att),neg(attackOrigin(X,Att)),[]).
rule(r_t_attackOrigin(X,Att),attackOrigin(X,Att),             	[attackPossibleOrigin(X,Att)]).
rule(r_t_conflictingOrigin(X,Y,Att),neg(attackOrigin(X,Att)),   [country(X),country(Y),attackPossibleOrigin(X,Att),attackPossibleOrigin(Y,Att),X \= Y]).
rule(r_t_nonOrigin(X,Att),neg(attackOrigin(X,Att)),  			[neg(attackPossibleOrigin(X,Att))]).

rule(r_t_bm(M),notForBlackMarketUse(M),[infectionMethod(usb,M),commandAndControlEasilyFingerprinted(M)]). 

rule(r_t_similarDefault(M1,M2),neg(similar(M1,M2)), []).
rule(r_t_similar(M1,M2),similar(M1,M2),       [similarCCServer(M1,M2),M1 \= M2]).
rule(r_t_simCC1(M1,M2),similarCCServer(M1,M2),[ccServer(S,M1),ccServer(S,M2)]).
rule(r_t_simCC2(M1,M2),similarCCServer(M1,M2),[ccServer(S1,M1),ccServer(S2,M2),S1 \= S2,domainRegisteredDetails(S1,_,A),domainRegisteredDetails(S2,_,A)]).
rule(r_t_simCC3(M1,M2),similarCCServer(M1,M2),[ccServer(S1,M1),ccServer(S2,M2),S1 \= S2,domainRegisteredDetails(S1,Name,_),domainRegisteredDetails(S2,Name,_)]).

rule(r_t_ccServerAddrType(Server,Type),ccServerAddrType(Server,Type),[domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). 
rule(r_t_similar1(M1,M2),similar(M1,M2),[simlarCodeObfuscation(M1,M2)]).
rule(r_t_similar2(M1,M2),similar(M1,M2),[sharedCode(M1,M2)]).
rule(r_t_similar3(M1,M2),similar(M1,M2),[malwareModifiedFrom(M1,M2)]).
rule(r_t_similar4(M1,M2),similar(M1,M2),[M1 \= M2,fileCharaMalware(C1,M1),fileCharaMalware(C2,M2),similarFileChara(C1,C2)]).

rule(r_t_targetted(Att),specificTarget(Att),     [malwareUsedInAttack(M,Att),specificConfigInMalware(M)]).
rule(r_t_zeroday(M),  sophisticatedMalware(M),   [usesZeroDayVulnerabilities(M)]).

rule(r_t_similarFileChara1(C1,C2),similarFileChara(C1,C2),[fileChara(Filename,_,_,_,_,_,C1),fileChara(Filename,_,_,_,_,_,C2)]).
rule(r_t_similarFileChara2(C1,C2),similarFileChara(C1,C2),[fileChara(_,MD5,_,_,_,_,C1),fileChara(_,MD5,_,_,_,_,C2)]).
rule(r_t_similarFileChara3(C1,C2),similarFileChara(C1,C2),[fileChara(_,_,_,_,Desc,_,C1),fileChara(_,_,_,_,Desc,_,C2)]).
rule(r_t_similarFileChara4(C1,C2),similarFileChara(C1,C2),[fileChara(_,_,Size,CompileTime,_,Filetype,C1),fileChara(_,_,Size,CompileTime,_,Filetype,C2)]).

rule(r_t_squid_log(IP),  attackSourceIP(IP,M),   [squid_log(IP,_Port,_ResultCode,M)]).

% pref
rule(p1_t(),prefer(r_t_attackOrigin(X,Att),r_t_attackOriginDefault(X,Att)),[]).
rule(p2a_t(),prefer(r_t_conflictingOrigin(X,_Y,Att),r_t_attackOrigin(X,Att)),[]).
rule(p2b_t(),prefer(r_t_conflictingOrigin(_Y,X,Att),r_t_attackOrigin(X,Att)),[]).
rule(p3_t(),prefer(r_t_nonOrigin(X,Att),r_t_attackOrigin(X,Att)),[]).
rule(p4a_t(),prefer(r_t_srcIP1(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p4b_t(),prefer(r_t_srcIP2(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p5_t(),prefer(r_t_lang1(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p6_t(),prefer(r_t_lang2(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p7_t(),prefer(r_t_infra(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p8_t(),prefer(r_t_domain(X,Att),r_t_noLocEvidence(X,Att)),[]).
rule(p9a_t(),prefer(r_t_spoofIP(X,Att),r_t_srcIP1(X,Att)),[]).
rule(p9b_t(),prefer(r_t_spoofIP(X,Att),r_t_srcIP2(X,Att)),[]).
rule(p10a_t(),prefer(r_t_highSkill1(Att),r_t_highSkill0(Att)),[]).
rule(p10b_t(),prefer(r_t_highSkill2(Att),r_t_highSkill0(Att)),[]).
rule(p10c_t(),prefer(r_t_highSkill4(Att),r_t_highSkill0(Att)),[]).
rule(p11a_t(),prefer(r_t_highSkill3(Att),r_t_highSkill1(Att)),[]).
rule(p11b_t(),prefer(r_t_highSkill3(Att),r_t_highSkill2(Att)),[]).
rule(p11c_t(),prefer(r_t_highSkill3(Att),r_t_highSkill4(Att)),[]).
rule(p12a_t(),prefer(r_t_highResource1(Att),r_t_highResource0(Att)),[]).
rule(p12b_t(),prefer(r_t_highResource2(Att),r_t_highResource0(Att)),[]).
rule(p12c_t(),prefer(r_t_highResource3(Att),r_t_highResource0(Att)),[]).
rule(p13a_t(),prefer(r_t_IPdomain2(S,M),r_t_IPdomain1(S,M)),[]).
rule(p13b_t(),prefer(r_t_IPdomain3(S,M),r_t_IPdomain1(S,M)),[]).

rule(p14a_t(),prefer(r_t_similar(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14b_t(),prefer(r_t_simCC1(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14c_t(),prefer(r_t_simCC2(M1,M2),r_t_similarDefault(M1,M2)),[]).
rule(p14d_t(),prefer(r_t_simCC3(M1,M2),r_t_similarDefault(M1,M2)),[]).



%% TODO: do more stuff with IP?
%% rule(externalIP,isExternalIP(_IP),[]).
%% rule(externalIP1,neg(isExternalIP(IP)),[isInternalIP(IP)]).
%% rule(internalIP1,isInternalIP([192,168,_,_]),[]).
%% rule(internalIP2,isInternalIP([172,N,_,_]),[N>=16,N<32]).
%% rule(internalIP3,isInternalIP([10,_,_,_]),[]).
%% rule(sameIPsubnet,similarIPSubnet([H1,H2,_,_],[H1,H2,_,_]),[]).
%% rule(validIP,validIP([N1,N2,N3,N4]),[N1>=0,N2>=0,N3>=0,N4>=0,N1<256,N2<256,N3<256,N4<256]).

%% rule(spoofedIP1,spoofedIp(IP),[connection(IP,in),isInternalIP(IP),validIP(IP)]).
%% rule(spoofedIP2,spoofedIp(IP),[connection(IP,out),isExternalIP(IP),validIP(IP)]).
%% rule(abnormalIP,abnormalIP(IP),[domainName(IP,Domain),domainCountry(Domain,C1),ipGeoloc(IP,C2),C1 \= C2]).

goal_all(A, X, M, M2, M3, D1, D2, D3, D4, D5) :-
  cleanFile('results.pl'), cleanFile('non_results.pl'),
  writeToFilesAll(requireHighResource(A), requireHighResource(A, D1)),
  writeToFilesAll(attackOrigin(X,A), attackOrigin(X,A,D2)),
  writeToFilesAll(notForBlackMarketUse(M), notForBlackMarketUse(M, D3)),
  writeToFilesAll(specificTarget(A), specificTarget(A, D4)),
  writeToFilesAll(similar(M2, M3), similar(M2, M3, D5)).


requireHighResource(A, D) :- prove([requireHighResource(A)], D).
attackOrigin(X, A, D) :- prove([attackOrigin(X, A)], D).
notForBlackMarketUse(M, D) :- prove([notForBlackMarketUse(M)], D).
similar(M1, M2, D) :- prove([similar(M1, M2)], D).
specificTarget(A, D) :- prove([specificTarget(A)], D). % abducible
malwareUsedInAttack(M, Att) :- prove([malwareUsedInAttack(M, Att)], _).