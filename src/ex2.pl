:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

% ex 2 - APT1
rule(t1, culpritIsFrom(X, Att), [majorityIpOrigin(X, Att)]).
rule(t2, not(culpritIsFrom(X, Att)), [spoofedIp(IP), ipGeoloc(G, IP), geolocInCountry(G, X), attackSourceIP(IP, Att)]).
rule(t3, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(t4, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(t5, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).
rule(t6(X), culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(o1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(o2, hasCapability(_, Att), [not(requireHighResource(Att))]).
rule(o3(C), hasCapability(C, Att), [requireHighResource(Att), hasResources(C)]).
rule(o4(C), hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(o5(C,T), hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).
rule(o6(C), hasMotive(C, Att), [hasEconomicMotive(C, Industry), industry(Industry, T), target(T, Att)]).
rule(o7, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(o8, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).
rule(o9(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(o10(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

rule(s1, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(s2, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(s3, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(s4, not(isCulprit(C,Att)), [culpritIsFrom(C,Att),nothasCapability(C,Att)]).
rule(s5, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).


rule(c, not(isCulprit(X,Att)), [isCulprit(Y,Att), not(X==Y)]).

% preferences
rule(p0, prefer(s2,s1), []).
rule(p1, prefer(t2,t1), []).
% ex2
rule(p2, prefer(s4,s3), []).
rule(p3, prefer(s5,s4), []).


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
