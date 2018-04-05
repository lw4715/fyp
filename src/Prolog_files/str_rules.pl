:- use_module(library(timeout)).
:- compile('utils.pl').
:- compile('../SicstusJava/op.pl').
:- compile('../SicstusJava/tech.pl').
:- multifile rule/3.

% input (from op/tech):
% hasCapability/2
% hasMotive/2
% governmentLinked/2
% forBlackMarketUse/1 (tech)
% culpritIsFrom/2 (tech)

% input (evidence):
% claimedResponsibility/2
% identifiedIndividualInAttack/2
% malwareUsedInAttack/2 (current)
% target/2

% input (bg):
% isCountry
% isCulprit/2 (past attacks)
% malwareUsedInAttack/2 (past)


rule(similarMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),
  malwareUsedInAttack(M2,A2),isCulprit(X,A2),neg(forBlackMarketUse(M1)),neg(forBlackMarketUse(M2))]).
rule(linkedMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),
  malwareLinkedTo(M2,X),neg(forBlackMarketUse(M1)),neg(forBlackMarketUse(M2))]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).
rule(grpPastTargets, hasMotive(Group, Att), [prominentGroup(Group), pastTargets(Group, Ts),
  target(T, Att), member(T, Ts)]).

rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasPrecedence(C,A2), \+ (Att = A2)]).
rule(hasMotiveAndLoc, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(noCap, neg(isCulprit(C,Att)), [culpritIsFrom(C,Att),neg(hasCapability(C,Att))]).
rule(social3, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).

rule(weakAttack, neg(isCulprit(C,Att)), [\+(highLevelSkill(Att)),isCountry(C)]).
rule(hasPrecedenceOfAttack, hasPrecedence(X, A), [isCulprit(X, A)]).
rule(countryHasMotive, isCulprit(C, Att), [isCulprit(Group, Att), country(Group, C), 
  hasMotive(C, Att)]).

% pref
rule(p0, prefer(hasMotiveAndCap,claimedResp), []).
rule(p1, prefer(hasMotiveAndLoc,claimedResponsibility), []).
rule(p2, prefer(noCap,hasMotiveAndLoc), []).
rule(p3, prefer(social3,noCap), []).
rule(p4, prefer(similarMalware, noCap), []).
rule(p5, prefer(linkedMalware, noCap), []).

writeToFile(X, A, D) :-
  open('output.pl',append, Stream), case(A),
  write(Stream, A), write(Stream, ":"), write(Stream, X), write(Stream, ', derivation: '), write(Stream, D), write(Stream, '\n'),
  close(Stream).

goal(A, X, D) :- prove([isCulprit(X, A)], D), writeToFile(X, A, D).
goal_with_timeout(A, X, D, Result) :- time_out(goal(A, X, D), 2000, Result).
