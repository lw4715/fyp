:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

?- set_prolog_flag(toplevel_print_options, [quoted(true), portrayed(true), max_depth(0)]).

% ex 2 - APT1
% Tech
rule(highSkillDefault, not(highLevelSkill(Att)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).

rule(srcIP, culpritIsFrom(X, Att), [ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(spoofedSrcIp, not(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(lang1, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(highSkill3, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill4, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(infra, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).


% Op
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource0, not(requireHighResource(Att)), [not(highLevelSkill(Att))]).
rule(hasCapability, hasCapability(C, Att), []).
rule(noCapability, not(hasCapability(X, Att)), [requireHighResource(Att), not(hasResources(X))]).
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
rule(noCap, not(isCulprit(C,Att)), [culpritIsFrom(C,Att),not(hasCapability(C,Att))]).
rule(social3, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).


% preferences
rule(p0, prefer(hasMotiveAndCap,claimedResponsibility), []).
rule(p1, prefer(spoofedSrcIp,srcIP), []).
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(nafRes, prefer(highResource1, highResource0), []).
rule(nafCap, prefer(noCapability, hasCapability), []).
% ex2
rule(p2, prefer(hasMotiveAndLoc,claimedResponsibility), []).
rule(p3, prefer(noCap,hasMotiveAndLoc), []).
rule(p4, prefer(social3,noCap), []).


% evidences
rule(f1, majorityIpOrigin(china,attack), []).
rule(f2, sysLanguage(chinese,attack), []).
rule(f3, firstLanguage(chinese,china), []).
rule(f4, infraRegisteredIn(china,infra), []).
rule(f5, infraUsed(infra,attack), []).
rule(f6, hasEconomicMotive(china,infocomm), []).
rule(f7, industry(infocomm,victim), []).
rule(f8, target(victim,attack), []).
rule(f9, largeNumberOfVictims(attack), []).
rule(f10, highVolumeAttack(attack), []).
rule(f11, longDurationAttack(attack), []).
rule(f12, geolocatedInGovFacility(superhard,china), []).
rule(f13, publicCommentsRelatedToGov(dota,china), []).
rule(f14, identifiedIndividualInAttack(superhard,attack), []).
rule(f15, identifiedIndividualInAttack(dota,attack), []).
