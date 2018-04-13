:- compile('utils.pl').
:- compile('op.pl').
:- compile('tech.pl').
:- multifile rule/3.
:- multifile abducible/2.

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


rule(similarMalware, isCulprit(X, A1), 
	[similar(M1,M2),malwareUsedInAttack(M1,A1),malwareUsedInAttack(M2,A2),
	isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
rule(linkedMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).
rule(grpPastTargets, hasMotive(Group, Att), [prominentGroup(Group), pastTargets(Group, Ts),
  target(T, Att), member(T, Ts)]).


rule(hasPrecedenceOfAttack, hasPrecedence(X, A), [isCulprit(X, A)]).
rule(countryHasMotive, isCulprit(C, Att), [isCulprit(Group, Att), country(Group, C), 
  hasMotive(C, Att)]).

rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(hasMotiveAndCap1, isCulprit(C,Att), [hasMotive(C,Att),hasPrecedence(C,A2), \+ (Att = A2)]).
rule(hasMotiveAndLoc, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(hasLoc, isCulprit(C,Att), [culpritIsFrom(C,Att)]).
rule(social, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).


rule(noCap, neg(isCulprit(C,Att)), [culpritIsFrom(C,Att),neg(hasCapability(C,Att))]).
rule(weakAttack, neg(isCulprit(C,Att)), [neg(requireHighResource(Att)),isCountry(C)]).
rule(notAttackItself, neg(isCulprit(C,Att)), [target(C,Att)]). % Purposely leave out for now
rule(lowGciTier, neg(isCulprit(C,Att)), [gci_tier(C,initiating)]).

abducible(notForBlackMarketUse(_), []).
abducible(hasCapability(_,_), []).

% pref
rule(p0, prefer(hasMotiveAndCap,claimedResp), []).
rule(p0, prefer(hasMotiveAndCap1,claimedResp), []).
rule(p1, prefer(hasMotiveAndLoc,claimedResp), []).
rule(p2, prefer(noCap,hasMotiveAndLoc), []).
rule(p2, prefer(noCap,hasLoc), []).
rule(p3, prefer(social,noCap), []).
rule(p4, prefer(similarMalware, noCap), []).
rule(p5, prefer(linkedMalware, noCap), []).

goal(A, X, D) :- visual_prove([isCulprit(X, A)], D).
goal_with_timeout(A, X, D, Result) :- time_out(goal(A, X, D), 1500, Result).
