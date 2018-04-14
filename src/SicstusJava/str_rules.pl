:- compile('utils.pl').
%% :- compile('op.pl').
%% :- compile('tech.pl').
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
% country
% isCulprit/2 (past attacks)
% malwareUsedInAttack/2 (past)


rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(countryHasMotive, isCulprit(C, Att), [country(C), prominentGroup(Group), isCulprit(Group, Att), groupOrigin(Group, C), hasMotive(C, Att)]).
rule(hasMotiveAndLoc, isCulprit(C,Att), [country(C), hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(hasLoc, isCulprit(C,Att), [country(C), culpritIsFrom(C,Att)]).
rule(social, isCulprit(C,Att), [country(C), governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).


rule(noCap, neg(isCulprit(C,Att)), [culpritIsFrom(C,Att),neg(hasCapability(C,Att))]).
rule(weakAttack, neg(isCulprit(C,Att)), [country(C), neg(requireHighResource(Att))]).
rule(notAttackItself, neg(isCulprit(C,Att)), [target(C,Att)]). % Purposely leave out for now
rule(lowGciTier, neg(isCulprit(C,_)), [gci_tier(C,initiating)]).
rule(noMotive, neg(isCulprit(X, Att)), [neg(hasMotive(X,Att))]).

%% rule(similarMalware, isCulprit(X, A1), 
%% 	[malwareUsedInAttack(M1,A1),similar(M1,M2),malwareUsedInAttack(M2,A2),
	%% isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
rule(linkedMalware, isCulprit(X, A1), [malwareUsedInAttack(M1,A1),similar(M1,M2),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).
%% rule(grpPastTargets, hasMotive(Group, Att), [target(T, Att), prominentGroup(Group), pastTargets(Group, Ts), member(T, Ts)]). %WEAK RULE

abducible(notForBlackMarketUse(_), []).
abducible(hasCapability(_,_), []).

% pref
rule(p0, prefer(hasMotiveAndCap,claimedResp), []).
%% rule(p1, prefer(hasMotiveAndCap1,claimedResp), []).
rule(p2, prefer(hasMotiveAndLoc,claimedResp), []).
rule(p3, prefer(noCap,hasMotiveAndLoc), []).
rule(p4, prefer(noCap,hasLoc), []).
rule(p5, prefer(social,noCap), []).
rule(p6, prefer(similarMalware, noCap), []).
rule(p7, prefer(linkedMalware, noCap), []).
rule(p8, prefer(noMotive, grpPastTargets), []).

goal(A, X, D) :- visual_prove([isCulprit(X, A)], D).
goal_with_timeout(A, X, D, Result) :- time_out(goal(A, X, D), 1500, Result).
