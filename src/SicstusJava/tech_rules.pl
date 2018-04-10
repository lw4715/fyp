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

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, neg(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP),
  geolocInCountry(G, X), attackSourceIP(IP, Att)]).
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

%% rule(bg110, fileCharaMalware(wannacry_filechara4,wannacry), []).
%% rule(bg111, fileChara('@WanaDecryptor@exe','7bf2b57f2a205768755c07f238fb32cc','245760','2009-07-1323:19:35Z','Decryptor','EXE',wannacry_filechara4), []).
%% 'Filename', 'MD5 Hash', 'Size (bytes)', 'Compile Time', 'Description', 'Filetype', malware 

rule(similarFileChara1, similarFileChara(C1, C2), [fileChara(Filename,_,_,_,_,_,C1), fileChara(Filename,_,_,_,_,_,C2)]).
rule(similarFileChara2, similarFileChara(C1, C2), [fileChara(_,MD5,_,_,_,_,C1), fileChara(_,MD5,_,_,_,_,C2)]).
rule(similarFileChara3, similarFileChara(C1, C2), [fileChara(_,_,_,_,Desc,_,C1), fileChara(_,_,_,_,Desc,_,C2)]).
rule(similarFileChara4, similarFileChara(C1, C2), [fileChara(_,_,Size,CompileTime,_,Filetype,C1), fileChara(_,_,Size,CompileTime,_,Filetype,C2)]).

% pref
rule(spoofedIp, prefer(spoofedSrcIp,srcIP, [])).

% output:
% requireHighResource/1
% culpritIsFrom/2 (strat)
%  notForBlackMarketUse/1 (strat)
% similar/2 (strat)

writeToFile(X) :-
  open('tech.pl',append, Stream),
  write(Stream, 'rule(t_'), write(Stream, X), write(Stream, ', '),
  write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

goal(A, X, D1, D2, D3, D4, D5) :-
  initFile('tech.pl'), case(A),
  (requireHighResource(A, D1), writeToFile(requireHighResource(A)));
    (\+ (requireHighResource(A, D1)), writeToFile(neg(requireHighResource(A)))), nl,
  (culpritIsFrom(X, A, D2), writeToFile(culpritIsFrom(X, A)));
    (\+ culpritIsFrom(X, A, D2)), nl,
  (malwareUsedInAttack(M, A), notForBlackMarketUse(M, D3), writeToFile( notForBlackMarketUse(M)))
  ; (\+ notForBlackMarketUse(M, D3)), nl,
  (malwareUsedInAttack(M, A), similar(M, M2, D5), writeToFile(similar(M, M2)), writeToFile(similar(M2, M)));
    (\+ (similar(M, M2, D5)), writeToFile(neg(similar(M, M2)))), nl,
  (specificTarget(A, D4), writeToFile(specificConfigInMalware(A))); (\+ specificTarget(A, D4)).

requireHighResource(A, D) :- prove([requireHighResource(A)], D).
%% neg(requireHighResource(A), D) :- prove([neg(requireHighResource(A))], D).
culpritIsFrom(X, A, D) :- prove([culpritIsFrom(X, A)], D).
notForBlackMarketUse(M, D) :- prove([notForBlackMarketUse(M)], D).
similar(M1, M2, D) :- prove([similar(M1, M2)], D).
specificTarget(A, D) :- prove([specificTarget(A)], D). % abducible
malwareUsedInAttack(M, Att) :- prove([malwareUsedInAttack(M, Att)], _).
