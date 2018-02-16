:- compile('/homes/lw4715/Computing/FYP/fyp/src/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/fyp/src/gorgias-src-0.6d/ext/lpwnf.pl').
% ex 1 - US bank hack

% tech
rule(t1(Att), highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(t2(Att), highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).

% op
rule(o1(Att), requireHighResource(Att), [highLevelSkill(Att)]).
rule(o2(Att), hasCapability(_, Att), [not(requireHighResource(Att))]).
rule(o3(C, Att), hasCapability(C, Att), [requireHighResource(Att), hasResources(C)]).
rule(o4(Att), hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(o5(C, T), hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).

% strategic
rule(s1(G, Att), isCulprit(G, Att), [claimedResponsibility(G, Att)]).
rule(s2(C, Att), isCulprit(C, Att), [hasMotive(C, Att), hasCapability(C, Att)]).


% preferences
rule(p1(Att), prefer(s2(Att), s1(Att)), []).

% evidences
rule(f1, hasResources(iran), []).
rule(f2, target(us, attack), []).
rule(f3, imposedSanctions(us, iran), []).
rule(f4, hijackCorporateClouds(attack), []).
rule(f5, sophisticatedMalware(itsoknoproblem), []).
rule(f6, malwareUsedInAttack(itsoknoproblem, attack), []).

