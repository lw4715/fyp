:- compile('utils.pl').

% output:
% hasResources/1
% requireHighResource/1
% culpritIsFrom/2 (strat)
% forBlackMarketUse/1 (strat)

% input (bg):
% ipGeoloc/2
% geolocInCountry/2
% firstLanguage/2

% misc:
% addressType/2 (gMaps integration??)

rule(highSkillDefault, not(highLevelSkill(_)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(highSkill5, not(highLevelSkill(Att)), [forBlackMarketUse(M),malwareUsedInAttack(M,Att)]).

rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource0, not(requireHighResource(Att)), [not(highLevelSkill(Att))]).
rule(highResource2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(highResource3, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, not(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(lang2, culpritIsFrom(X,Att), [languageInCode(L,Att),firstLanguage(L,X)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(bmDefault, not(forBlackMarketUse(_)), []).
rule(bm, forBlackMarketUse(M), [\+(infectionMethod(usb,M)),\+(controlAndCommandEasilyFingerprinted(M))]). %TODO when do we know its not for black market?

rule(similarMalware1(T), similar(M1, M2), [ccServerAddrType(M1,T),ccServerAddrType(M2,T),(M1\==M2)]). %TODO when do we know if its not similar?
rule(ccServerAddrType(Type), ccServerAddrType(M, Type), [ccServer(Server,M),domainRegisteredDetails(Server,_,Addr),addressType(Addr,Type)]). %TODO can link to googlemaps?

% rule(isTargetted, targettedAttack(Att), [customizedCommandsToTarget(T,M),malwareUsedInAttack(M,Att),target(T,Att)]).

% pref
rule(spoofedIp, prefer(spoofedSrcIp,srcIP), []).
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(isBM, prefer(bm, bmDefault), []).
rule(nafRes, prefer(highResource1, highResource0), []).


% evidences
rule(f1, sophisticatedMalware(gauss), []).
rule(f2, malwareUsedInAttack(gauss,attack), []).
rule(f7, target(middleEast,attack), []).
rule(f8, target(israel,attack), []).
rule(f9, target(lebanon,attack), []).
rule(f10, target(palestine,attack), []).
rule(f12, infectionMethod(usb,gauss), []).
rule(f13, controlAndCommandEasilyFingerprinted(gauss), []).
rule(f16, ccServer(gowin7, gauss), []).
rule(f17, ccServer(secuurity, gauss), []).
rule(f18, domainRegisteredDetails(gowin7, "adolph dybevek", "prinsen gate 6"), []).
rule(f19, domainRegisteredDetails(secuurity, "adolph dybevek", "prinsen gate 6"), []).
rule(f20, addressType("prinsen gate 6", hotel), []).
rule(f21, ccServer(gowin7, flame), []).
rule(f22, ccServer(secuurity, flame), []).
