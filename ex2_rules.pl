% ex 2 - US bank hack

% tech
highLevelSkill(Att) :- hijackCorporateClouds(Att). %T1
highLevelSkill(Att) :- sophisticatedMalware(M), malwareUsedInAttack(M, Att). % T2
% ex2
culpritIsFrom(X, Att) :- majorityIpOrigin(X, Att). %T3
not culpritIsFrom(X, Att) :- spoofedIp(Att), ipOrigin(X, Att). %T4
culpritIsFrom(X, Att) :- firstLanguage(L, X), sysLanguage(L, Att). %T5
culpritIsFrom(X, Att) :- infraRegisteredIn(China, Infra), infraUsed(Infra, Att). %T6

% op
requireHighResource(Att) :- highLevelSkill(Att). % O1
hasCapability(C, Att) :- not requireHighResource(Att). % O2
hasCapability(C, Att) :- requireHighResource(Att), hasResources(C). % O3
hasMotive(C, Att) :- hasPoliticalMotive(C, T), target(C, Att). % O4
hasPoliticalMotive(C, T) :- imposedSanctions(T, C). %O5
% ex2
hasMotive(C, Att) :- hasEconomicMotive(C, Industry), industry(Industry, T), target(T, Att). %O6
requireHighResource(Att) :- highSecurity(T), target(T, Att). %O7
requireHighResource(Att) :- largeNumberOfVictims(Att). %O8
requireHighResource(Att) :- highVolumeAttack(Att), longDurationAttack(Att). %O9
governmentLinked(P, C) :- geolocatedInGovFacility(P, C). %O10
governmentLinked(P, C) :- publicCommentsRelatedToGov(P, C). %O11


% strategic
isCulprit(G, Att) :- claimedResponsibility(G, Att). % S1
isCulprit(C, Att) :- hasMotive(C, Att), hasCapability(C, Att).% S2
% ex2
isCulprit(C, Att) :- hasMotive(C, Att), culpritIsFrom(C, Att). %S3
not isCulprit(C, Att) :- culpritIsFrom(C, Att), not hasCapability(C, Att). %S4
isCulprit(C, Att) :- governmentLinked(P, C), identifiedIndividualInAttack(P, Att). %S5

% constraints
:- isCulprit(X, Att), isCulprit(Y, Att), X != Y.


% preferences
prefer(S2, S1). % S2 > S1
prefer(T4, T3).
% ex2
prefer(S4, S3).
prefer(S5, S4).

% evidences
majorityIpOrigin(china, attack).

sysLanguage(chinese, attack).
firstLanguage(chinese, china).

infraRegisteredIn(china, infra).
infraUsed(infra, attack).

hasEconomicMotive(china, infocomm).
industry(infocomm, victim).
target(victim, attack).

largeNumberOfVictims(attack).

highVolumeAttack(attack).
longDurationAttack(attack).

geolocatedInGovFacility(superhard, china).
publicCommentsRelatedToGov(dota, china).
identifiedIndividualInAttack(superhard, attack).
identifiedIndividualInAttack(dota, attack).

