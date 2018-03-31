:- compile('utils.pl').
:- multifile rule/3.
:- multifile abducible/2.

% input (bg):
% geolocInCountry/2
% firstLanguage/2

% misc:
% addressType/2 (gMaps integration??)

% rule(highSkillDefault, neg(highLevelSkill(_)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill5, neg(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).

rule(highResource0, neg(requireHighResource(Att)), [neg(highLevelSkill(Att))]).
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(highResource3, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).

% rule(culpritOriginDefault, neg(culpritIsFrom(_X, _Att)), []).
rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, neg(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP),
  geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(bmDefault, forBlackMarketUse(_M), []).
rule(bm, neg(forBlackMarketUse(M)), [(infectionMethod(usb,M)),(controlAndCommandEasilyFingerprinted(M))]). %TODO when do we know its not for black market?

rule(similarDefault, neg(similar(_M1, _M2)), []).
rule(similar, similar(M1, M2), [similarCCServer(M1, M2), \+ M1 = M2]).
rule(simCC, similarCCServer(M1, M2), [ccServer(S, M1), ccServer(S, M2)]).
rule(simCC(T), similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2),
  ccServerAddrType(S1,T),ccServerAddrType(S2,T), \+ (S1=S2)]).
rule(ccServerAddrType(Type), ccServerAddrType(Server, Type),
  [domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). %TODO can link to googlemaps?
rule(similar1, similar(M1, M2), [simlarCodeObfuscation(M1, M2)]).
rule(similar2, similar(M1, M2), [sharedCode(M1, M2)]).
rule(similar3, similar(M1, M2), [malwareModifiedFrom(M1, M2)]).

rule(highSkill6, highLevelSkill(Att), [stolenValidSignedCertificates(Att)]).
rule(targetted, specificTarget(Att), [specificConfigInMalware(M),malwareUsedInAttack(M,Att)]).
rule(zeroday, sophisticatedMalware(M), [usesZeroDayVulnerabilities(M)]).

abducible(specificTarget, []).

% pref
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(isNotBM, prefer(bm, bmDefault), []).
% rule(nafRes, prefer(highResource1, highResource0), []).
% rule(nafSim, prefer(similar, similarDefault), []).
% rule(nafSim1, prefer(similar1, similarDefault), []).
% rule(nafSim2, prefer(similar2, similarDefault), []).
% rule(nafSim3, prefer(similar3, similarDefault), []).

rule(spoofedIp, prefer(spoofedSrcIp,srcIP), []).

% evidences

% output:
% requireHighResource/1
% culpritIsFrom/2 (strat)
% forBlackMarketUse/1 (strat)
% similar/2 (strat)

writeToFile(X, A, N) :-
  open('tech.pl',append, Stream),
  write(Stream, 'rule(t_'), write(Stream, A), write(Stream, N), write(Stream, ', '),
  write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

goal(A, X, D1, D2, D3, D4, D5) :-
  initFile('tech.pl'), case(A),
  (requireHighResource(A, D1), writeToFile(requireHighResource(A), A, 1));
    (\+ (requireHighResource(A, D1)), writeToFile(neg(requireHighResource(A)), A, 1)), nl,
  (culpritIsFrom(X, A, D2), writeToFile(culpritIsFrom(X, A), A, 2));
    (\+ (culpritIsFrom(X, A, D2)), writeToFile(neg(culpritIsFrom(X, A)), A, 2)), nl,
  (malwareUsedInAttack(M, A), forBlackMarketUse(M, D3), writeToFile(forBlackMarketUse(M), A, 3));
    (\+ (forBlackMarketUse(M, D3)), writeToFile(neg(forBlackMarketUse(M)), A, 3)), nl,
  (malwareUsedInAttack(M, A), similar(M, M2, D5), writeToFile(similar(M, M2), A, 5));
    (\+ (similar(M, M2, D5)), writeToFile(neg(similar(M, M2)), A, 5)), nl,
  (specificTarget(A, D4), writeToFile(specificConfigInMalware(A), A, 4)); (\+ specificTarget(A, D4)).

requireHighResource(A, D) :- prove([requireHighResource(A)], D).
neg(requireHighResource(A), D) :- prove([neg(requireHighResource(A))], D).
culpritIsFrom(X, A, D) :- prove([culpritIsFrom(X, A)], D).
forBlackMarketUse(M, D) :- prove([forBlackMarketUse(M)], D).
similar(M1, M2, D) :- prove([similar(M1, M2)], D).
specificTarget(A, D) :- prove([specificTarget(A)], D). % abducible
malwareUsedInAttack(M, Att) :- prove([malwareUsedInAttack(M, Att)], _).
