:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

% ex 3 - Gauss (US bank hack)
rule(t1, culpritIsFrom(X, Att), [majorityIpOrigin(X, Att)]).
rule(t2, not(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(t3, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(t4, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(t5, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(t6, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).
rule(t7, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(t8, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),malwareUsedInAttack(M2,A2),isCulprit(X,A2),\+(forBlackMarketUse(M1)),\+(forBlackMarketUse(M2))]).
rule(t9, not(forBlackMarketUse(M)), []).
rule(t10, forBlackMarketUse(M), [not(infectionMethod(usb,M)),not(controlAndCommandEasilyFingerprinted(M))]).
rule(t11, not(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).

rule(o1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(o2, hasCapability(_, Att), [not(requireHighResource(Att))]).
rule(o3, hasCapability(C, Att), [requireHighResource(Att), hasResources(C)]).
rule(o4, hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(o5, hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).
rule(o6, hasMotive(C, Att), [hasEconomicMotive(C, Industry), industry(Industry, T), target(T, Att)]).
rule(o7, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(o8, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).
rule(o9(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(o10(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

rule(s1, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(s2, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(s3, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(s4, not(isCulprit(C,Att)), [culpritIsFrom(C,Att),nothasCapability(C,Att)]).
rule(s5, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).
rule(s6, not(isCulprit(C,Att)), [not(highLevelSkill(Att)),isCountry(C)]).
rule(s7, hasResources(X), [isCulprit(X, _)]).

rule(c, not(isCulprit(X,Att)), [isCulprit(Y,Att), not(X==Y)]).

% preferences
rule(p0, prefer(s2,s1), []).
rule(p1, prefer(t2,t1), []).
% ex2
rule(p2, prefer(s4,s3), []).
rule(p3, prefer(s5,s4), []).
% ex3
rule(p4, prefer(t8, s4), []).
rule(p5, prefer(t10, t9), []).

% evidences
rule(f1, sophisticatedMalware(gauss), []).
rule(f2, malwareUsedInAttack(gauss,attack), []).
rule(f3, similar(gauss,stuxnet), []).
rule(f4, malwareUsedInAttack(stuxnet,stuxnetattack), []).
rule(f5, isCulprit(israel,stuxnetattack), []).
rule(f6, isCulprit(us,stuxnetattack), []).
rule(f7, target(middleEast,attack), []).
rule(f8, target(israel,attack), []).
rule(f9, target(lebanon,attack), []).
rule(f10, target(palestine,attack), []).
rule(f11, target(iran,stuxnetattack), []).
rule(f12, infectionMethod(usb,gauss), []).
rule(f13, controlAndCommandEasilyFingerprinted(gauss), []).
rule(f14, hasPoliticalMotive(us,iran), []).
rule(f15, hasPoliticalMotive(israel,iran), []).
