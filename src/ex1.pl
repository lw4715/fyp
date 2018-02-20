:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

?- set_prolog_flag(toplevel_print_options, [quoted(true), portrayed(true), max_depth(0)]).

% ex 1 - US bank hack

% Tech
rule(highSkillDefault, not(highLevelSkill(Att)), []).
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [sophisticatedMalware(M), malwareUsedInAttack(M, Att)]).

% Op
rule(highResource1, requireHighResource(Att), [highLevelSkill(Att)]).
rule(highResource0, not(requireHighResource(Att)), [not(highLevelSkill(Att))]).
rule(hasCapability, hasCapability(C, Att), []).
rule(noCapability, not(hasCapability(X, Att)), [requireHighResource(Att), not(hasResources(X))]).
rule(pMotive, hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(pMotive(C,T), hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).

% Strategic
rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).

% preferences
rule(p0, prefer(hasMotiveAndCap,claimedResponsibility), []).
rule(p1, prefer(spoofedSrcIp,srcIP), []).
rule(nafSkill1, prefer(highSkill1, highSkillDefault), []).
rule(nafSkill2, prefer(highSkill2, highSkillDefault), []).
rule(nafRes, prefer(highResource1, highResource0), []).
rule(nafCap, prefer(noCapability, hasCapability), []).


% evidences
rule(f1, hasResources(iran), []).
rule(f2, target(us, attack), []).
rule(f3, imposedSanctions(us, iran), []).
rule(f4, hijackCorporateClouds(attack), []).
rule(f5, sophisticatedMalware(itsoknoproblem), []).
rule(f6, malwareUsedInAttack(itsoknoproblem, attack), []).

