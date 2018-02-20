:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

% ex 3 - Gauss 
% Tech
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, not(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(similarMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),malwareUsedInAttack(M2,A2),isCulprit(X,A2),not(forBlackMarketUse(M1)),not(forBlackMarketUse(M2))]).
rule(bmDefault, not(forBlackMarketUse(M)), []).
rule(bm, forBlackMarketUse(M), [\+(infectionMethod(usb,M)),\+(controlAndCommandEasilyFingerprinted(M))]). %TODO
rule(highSkill5, not(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).

% Op
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(noCapbabilityRequired, hasCapability(_, Att), [\+(requireHighResource(Att))]).
rule(hasCapability, hasCapability(C, Att), [requireHighResource(Att), hasResources(C)]).
rule(pMotive, hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(pMotive(C,T), hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).

rule(ecMotive(C,T), hasMotive(C, Att), [hasEconomicMotive(C, T), industry(T), target(T, Att)]).
rule(highResource2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(highResource3, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).
rule(social1(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(social2(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

% Strategic
rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).

rule(hasMotiveAndLoc, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(noCap, not(isCulprit(C,Att)), [culpritIsFrom(C,Att),\+(hasCapability(C,Att))]).
rule(social3, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).

rule(weakAttack, not(isCulprit(C,Att)), [\+(highLevelSkill(Att)),isCountry(C)]).
rule(hasPrecedenceOfAttack, hasResources(X), [isCulprit(X, _)]).

% preferences
rule(p0, prefer(hasMotiveAndCap,claimedResponsibility), []).
rule(p1, prefer(spoofedSrcIp,srcIP), []).
% ex2
rule(p2, prefer(hasMotiveAndLoc,claimedResponsibility), []).
rule(p3, prefer(noCap,hasMotiveAndLoc), []).
rule(p4, prefer(social3,noCap), []).
% ex3
rule(p5, prefer(similarMalware, noCap), []).
rule(p6, prefer(bm, bmDefault), []).

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
