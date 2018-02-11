% ex 1 - US bank hack

% tech
highLevelSkill(Att) :- hijackCorporateClouds(Att). %T1
highLevelSkill(Att) :- sophisticatedMalware(M), malwareUsedInAttack(M, Att). % T2


% op
requireHighResource(Att) :- highLevelSkill(Att). % O1
hasCapability(C, Att) :- not requireHighResource(Att). % O2
hasCapability(C, Att) :- requireHighResource(Att), hasResources(C). % O3
hasMotive(C, Att) :- hasPoliticalMotive(C, T), target(C, Att). % O4
hasPoliticalMotive(C, T) :- imposedSanctions(T, C). %O5

% strategic
isCulprit(G, Att) :- claimedResponsibility(G, Att). % S1
isCulprit(C, Att) :- hasMotive(C, Att), hasCapability(C, Att).% S2

% constraints
:- isCulprit(X, Att), isCulprit(Y, Att), X != Y.


% preferences
prefer(S2, S1). % S2 > S1

% evidences
hasResources(iran).
target(us).
imposedSanctions(us, iran).
hijackCorporateClouds(attack).
sophisticatedMalware(itsoknoproblem).
malwareUsedInAttack(itsoknoproblem, attack).

