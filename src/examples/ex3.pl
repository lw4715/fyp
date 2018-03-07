:- compile('utils.pl').

% ex 3 - Gauss
% Tech
rule(highSkillDefault, neg(highLevelSkill(_)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, neg(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(similarMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),malwareUsedInAttack(M2,A2),isCulprit(X,A2),neg(forBlackMarketUse(M1)),neg(forBlackMarketUse(M2))]).
rule(bmDefault, neg(forBlackMarketUse(_)), []).
rule(bm, forBlackMarketUse(M), [\+(infectionMethod(usb,M)),\+(controlAndCommandEasilyFingerprinted(M))]). %TODO when do we know its not for black market?
rule(highSkill5, neg(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).
rule(isTargetted, targettedAttack(Att), [customizedCommandsToTarget(T,M),malwareUsedInAttack(M,Att),target(T,Att)]).
rule(ccServerAddrType(Type), ccServerAddrType(M, Type), [ccServer(Server,M),domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). %TODO can link to googlemaps?
%rule(similarMalware1(T), similar(M1, M2), [ccServerAddrType(M1,T),ccServerAddrType(M2,T),(M1\==M2)]). %TODO when do we know if its not similar?

% Op
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource0, neg(requireHighResource(Att)), [neg(highLevelSkill(Att))]).
rule(hasCapability, hasCapability(_, _), []).
rule(noCapability, neg(hasCapability(X, Att)), [requireHighResource(Att), neg(hasResources(X))]).
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
rule(noCap, neg(isCulprit(C,Att)), [culpritIsFrom(C,Att),neg(hasCapability(C,Att))]).
rule(social3, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).

rule(weakAttack, neg(isCulprit(C,Att)), [\+(highLevelSkill(Att)),isCountry(C)]).
rule(hasPrecedenceOfAttack, hasResources(X), [isCulprit(X, _)]).

% preferences
rule(p0, prefer(hasMotiveAndCap,claimedResponsibility), []).
rule(spoofedIp, prefer(spoofedSrcIp,srcIP), []).
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(nafRes, prefer(highResource1, highResource0), []).
rule(nafCap, prefer(noCapability, hasCapability), []).

% ex2
rule(p1, prefer(hasMotiveAndLoc,claimedResponsibility), []).
rule(p2, prefer(noCap,hasMotiveAndLoc), []).
rule(p3, prefer(social3,noCap), []).
% ex3
rule(p4, prefer(similarMalware, noCap), []).
rule(isBM, prefer(bm, bmDefault), []).

% evidences
rule(f0, similar(gauss, flame), []).
rule(f1, sophisticatedMalware(gauss), []).
rule(f2, malwareUsedInAttack(gauss,attack), []).
rule(f4, malwareUsedInAttack(flame,flameattack), []).
rule(f6, isCulprit(equationGroup,flameattack), []).
rule(f7, target(middleEast,attack), []).
rule(f8, target(israel,attack), []).
rule(f9, target(lebanon,attack), []).
rule(f10, target(palestine,attack), []).
rule(f11, target(middleeast,flameattack), []).
rule(f12, infectionMethod(usb,gauss), []).
rule(f13, controlAndCommandEasilyFingerprinted(gauss), []).
rule(f14, hasPoliticalMotive(us,iran), []).
rule(f15, hasPoliticalMotive(israel,iran), []).
rule(f16, ccServer(gowin7, gauss), []).
rule(f17, ccServer(secuurity, gauss), []).
rule(f18, domainRegisteredDetails(gowin7, "adolph dybevek", "prinsen gate 6"), []).
rule(f19, domainRegisteredDetails(secuurity, "adolph dybevek", "prinsen gate 6"), []).
rule(f20, addressType("prinsen gate 6", hotel), []).
rule(f21, ccServer(gowin7, flame), []).
rule(f22, ccServer(secuurity, flame), []).
