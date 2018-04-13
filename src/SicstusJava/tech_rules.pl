:- compile('utils.pl').
:- multifile rule/3.
:- multifile abducible/2.

% input (bg):
% geolocInCountry/2
% firstLanguage/2

% misc:
% addressType/2 (gMaps integration??)

rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill3, neg(highLevelSkill(Att)), [ neg(notForBlackMarketUse(M)),malwareUsedInAttack(M,Att)]).
rule(highSkill4, highLevelSkill(Att), [stolenValidSignedCertificates(Att)]).

rule(highResource0, neg(requireHighResource(Att)), [neg(highLevelSkill(Att))]).
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(highResource3, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(X, IP), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, neg(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(X, IP), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [sysLanguage(L, Att), firstLanguage(L, X)]).
rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(bm, notForBlackMarketUse(M), [infectionMethod(usb,M),controlAndCommandEasilyFingerprinted(M)]). 

%% rule(similarDefault, neg(similar(_M1, _M2)), []).
rule(similar, similar(M1, M2), [similarCCServer(M1, M2), M1 \= M2]).
rule(simCC1, similarCCServer(M1, M2), [ccServer(S, M1), ccServer(S, M2)]).
%% rule(simCC2, similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), \+ S1 = S2,
  %% ccServerAddrType(S1,T),ccServerAddrType(S2,T)]).
rule(simCC2, similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), S1 \= S2,
  domainRegisteredDetails(S1,_,A), domainRegisteredDetails(S2,_,A)]).
rule(simCC3, similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), S1 \= S2,
  domainRegisteredDetails(S1,Name,_), domainRegisteredDetails(S2,Name,_)]).

rule(ccServerAddrType, ccServerAddrType(Server, Type),
  [domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). 
%TODO can link to googlemaps?
rule(similar1, similar(M1, M2), [simlarCodeObfuscation(M1, M2)]).
rule(similar2, similar(M1, M2), [sharedCode(M1, M2)]).
rule(similar3, similar(M1, M2), [malwareModifiedFrom(M1, M2)]).
rule(similar4, similar(M1, M2), [M1 \= M2, fileCharaMalware(C1, M1), fileCharaMalware(C2,M2), similarFileChara(C1, C2)]).

rule(targetted, specificTarget(Att), [specificConfigInMalware(M),malwareUsedInAttack(M,Att)]).
rule(zeroday, sophisticatedMalware(M), [usesZeroDayVulnerabilities(M)]).

rule(similarFileChara1, similarFileChara(C1, C2), [fileChara(Filename,_,_,_,_,_,C1), fileChara(Filename,_,_,_,_,_,C2)]).
rule(similarFileChara2, similarFileChara(C1, C2), [fileChara(_,MD5,_,_,_,_,C1), fileChara(_,MD5,_,_,_,_,C2)]).
rule(similarFileChara3, similarFileChara(C1, C2), [fileChara(_,_,_,_,Desc,_,C1), fileChara(_,_,_,_,Desc,_,C2)]).
rule(similarFileChara4, similarFileChara(C1, C2), [fileChara(_,_,Size,CompileTime,_,Filetype,C1), fileChara(_,_,Size,CompileTime,_,Filetype,C2)]).


%% TODO: do more stuff with IP
rule(externalIP, isExternalIP(_IP), []).
rule(externalIP1, neg(isExternalIP(IP)), [isInternalIP(IP)]).
rule(internalIP1, isInternalIP([192,168,_,_]), []).
rule(internalIP2, isInternalIP([172,N,_,_]), [N>=16, N<32]).
rule(internalIP3, isInternalIP([10,_,_,_]), []).
rule(sameIPsubnet, similarIPSubnet([H1,H2,_,_],[H1,H2,_,_]), []).
rule(validIP, validIP([N1,N2,N3,N4]), [N1>=0, N2>=0, N3>=0, N4>=0, N1<256, N2<256, N3<256, N4<256]).

%% 
rule(spoofedIp1, spoofedIp(IP), [connection(IP, in), isInternalIP(IP), validIP(IP)]).
rule(spoofedIp2, spoofedIp(IP), [connection(IP, out), isExternalIP(IP), validIP(IP)]).
rule(abnormalIP, abnormalIP(IP), [domainName(IP, Domain), domainCountry(Domain, C1), ipGeoloc(IP, C2), C1 \= C2]).

%% rule(4, isCulprit(X,A1), [similarNature(A1,A2),isCulprit(X,A2)]).
%% rule(8, hasKillSwitch(wannacry), []).
%% rule(9, type(wannacry,ransomware), []).
%% rule(10, propagationMechanism(wannacry,self_propagating), []).
%% rule(11, scale(wannacryattack,large), []).
%% rule(12, exploitVul('EternalBlue'), []).
%% rule(13, vulPatched('EternalBlue'), []).
%% rule(14, vulReleased(14,4,17,'EternalBlue'), []).
%% rule(15, dateOfAttack(12,5,17,wannacryattack), []).
%% rule(16, ccCommunicationChannel(tor), []).



% pref
rule(p1, prefer(spoofedSrcIp,srcIP, [])).
rule(p2, prefer(externalIP1,externalIP, [])).

% output:
% requireHighResource/1
% culpritIsFrom/2 (strat)
%  notForBlackMarketUse/1 (strat)
% similar/2 (strat)

goal(A, X, M, M2, M3, D1, D2, D3, D4, D5) :-
  initFile('tech.pl'), case(A),
  writeToFiles('tech.pl', requireHighResource(A), requireHighResource(A, D1), 'tech_'),
  writeToFiles('tech.pl', culpritIsFrom(X,A), culpritIsFrom(X,A,D2), 'tech_'),
  writeToFilesAbd('tech.pl', notForBlackMarketUse(M), notForBlackMarketUse(M, D3), 'tech_'),
  writeToFilesAbd('tech.pl', specificTarget(A), specificTarget(A, D4), 'tech_'),
  writeToFiles('tech.pl', similar(M3, M2), similar(M3, M2, D5), 'tech_'),
  writeToFiles('tech.pl', similar(M2, M3), similar(M2, M3, D5), 'tech_').


goal_all(A, X, M, M2, M3, D1, D2, D3, D4, D5) :-
  initFile('tech.pl'), cleanFile('results.pl'), cleanFile('non_results.pl'), case(A),
  writeToFilesAll('tech.pl', requireHighResource(A), requireHighResource(A, D1), 'tech_'),
  writeToFilesAll('tech.pl', culpritIsFrom(X,A), culpritIsFrom(X,A,D2), 'tech_'),
  writeToFilesAllAbd('tech.pl', notForBlackMarketUse(M), notForBlackMarketUse(M, D3), 'tech_'),
  writeToFilesAllAbd('tech.pl', specificTarget(A), specificTarget(A, D4), 'tech_'),
  writeToFilesAll('tech.pl', similar(M3, M2), similar(M3, M2, D5), 'tech_'),
  writeToFilesAll('tech.pl', similar(M2, M3), similar(M2, M3, D5), 'tech_').


requireHighResource(A, D) :- visual_prove([requireHighResource(A)], D).
culpritIsFrom(X, A, D) :- visual_prove([culpritIsFrom(X, A)], D).
notForBlackMarketUse(M, D) :- visual_prove([notForBlackMarketUse(M)], D).
similar(M1, M2, D) :- visual_prove([similar(M1, M2)], D).
specificTarget(A, D) :- visual_prove([specificTarget(A)], D). % abducible
malwareUsedInAttack(M, Att) :- visual_prove([malwareUsedInAttack(M, Att)], _).
