:- compile('utils.pl').
:- compile('evidence.pl').
:- multifile rule/3.

% input (bg):
% geolocInCountry/2
% firstLanguage/2

% misc:
% addressType/2 (gMaps integration??)

rule(highSkillDefault, neg(highLevelSkill(_)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill5, neg(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).

rule(highResource0, neg(requireHighResource(Att)), [neg(highLevelSkill(Att))]).
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(highResource3, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, neg(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(bmDefault, forBlackMarketUse(_), []).
rule(bm, neg(forBlackMarketUse(M)), [(infectionMethod(usb,M)),(controlAndCommandEasilyFingerprinted(M))]). %TODO when do we know its not for black market?

rule(similar, similar(M1, M2), [similarCCServer(M1, M2), \+ M1 = M2]). %TODO when do we know if its not similar?
rule(simCC, similarCCServer(M1, M2), [ccServer(S, M1), ccServer(S, M2)]).
rule(simCC(T), similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), ccServerAddrType(S1,T),ccServerAddrType(S2,T), \+ (S1=S2)]).
rule(ccServerAddrType(Type), ccServerAddrType(Server, Type), [domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). %TODO can link to googlemaps?

rule(highSkill6, highLevelSkill(Att), [stolenValidSignedCertificates(Att)]).
% rule(isTargetted, targettedAttack(Att), [customizedCommandsToTarget(T,M),malwareUsedInAttack(M,Att),target(T,Att)]).
rule(targetted, specificTarget(Att), [specificConfigInMalware(M),malwareUsedInAttack(M,Att)]).
rule(zeroday, sophisticatedMalware(M), [usesZeroDayVulnerabilities(M)]).



% pref
rule(spoofedIp, prefer(spoofedSrcIp,srcIP), []).
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(isNotBM, prefer(bm, bmDefault), []).
rule(nafRes, prefer(highResource1, highResource0), []).


% evidences

% output:
% requireHighResource/1
% culpritIsFrom/2 (strat)
% forBlackMarketUse/1 (strat)
% similar/2 (strat)

writeToFile(X, A, N) :-
  open('op.pl',append, Stream), \+ atom(X),
  write(Stream, 'rule(op_Att'), write(Stream, N), write(Stream, ', X ,[]).\n'),
  close(Stream).

writeToFile(X, A, N) :-
  open('tech.pl',append, Stream), atom(X),
  write(Stream, 'rule(t_'), write(Stream, A), write(Stream, N), write(Stream, ', '), write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

% TODO fix neg cases
goal(A, M, X, D1, D2, D3, D4) :-
  initFile('tech.pl'), case(A),
  (requireHighResource(A, D1), writeToFile(requireHighResource(A), A, 1)); (\+ requireHighResource(A, D1), writeToFile('neg(requireHighResource(A))', A, 1)), nl,
  (culpritIsFrom(X, A, D2), writeToFile(culpritIsFrom(X, A), A, 2)); (\+ culpritIsFrom(X, A, D2), writeToFile('neg(culpritIsFrom(X, A))', A, 2)), nl,
  (forBlackMarketUse(M, D3), writeToFile(forBlackMarketUse(M), A, 3)); (\+ forBlackMarketUse(M, D3), writeToFile('neg(forBlackMarketUse(M))', A, 3)), nl,
  (specificTarget(A, D4), writeToFile(specificConfigInMalware(A), A, 4)); (\+ specificTarget(A, D4)), nl,
  (malwareUsedInAttack(M, A), similar(M, M2, D5), writeToFile(similar(M, M2), A, 5)); (\+ similar(M, M2, D5), writeToFile('neg(similar(M, M2))', A, 5)).

requireHighResource(A, D) :- prove([requireHighResource(A)], D).
culpritIsFrom(X, A, D) :- prove([culpritIsFrom(X, A)], D).
forBlackMarketUse(M, D) :- prove([forBlackMarketUse(M)], D).
similar(M1, M2, D) :- prove([similar(M1, M2)], D).
specificTarget(A, D) :- prove([specificTarget(A)], D).
