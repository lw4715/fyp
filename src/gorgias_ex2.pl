:- compile('/homes/lw4715/Computing/FYP/fyp/src/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/fyp/src/gorgias-src-0.6d/ext/lpwnf.pl').
% ex 2 - US bank hack
% tech
% highLevelSkill(Att) :- hijackCorporateClouds(Att). %T1
% highLevelSkill(Att) :- sophisticatedMalware(M), malwareUsedInAttack(M, Att). % T2
% ex2
rule(t1, culpritIsFrom(X, Att), [majorityIpOrigin(X, Att)]).
rule(t2, not(culpritIsFrom(X, Att)), [spoofedIp(Att), ipOrigin(X, Att)]).
rule(t3, culpritIsFrom(X, Att), [firstLanguage(L, X), sysLanguage(L, Att)]).
rule(t4, culpritIsFrom(X, Att), [infraRegisteredIn(X, Infra), infraUsed(Infra, Att)]).

rule(o1, hasMotive(C, Att), [hasEconomicMotive(C, Industry), industry(Industry, T), target(T, Att)]).
rule(o2, requireHighResource(Att), [highSecurity(T), target(T, Att)]).
rule(o3, requireHighResource(Att), [largeNumberOfVictims(Att)]).
rule(o4, requireHighResource(Att), [highVolumeAttack(Att),longDurationAttack(Att)]).
rule(o5, governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(o6, governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).



rule(s1, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(s2, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).

rule(s3, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(s4, not(isCulprit(C,Att)), [culpritIsFrom(C,Att),nothasCapability(C,Att)]).
rule(s5, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).


rule(c, not(isCulprit(X,Att)), [isCulprit(Y,Att), not(X==Y)]).
%%%%


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
