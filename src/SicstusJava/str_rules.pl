:- compile('utils.pl').
:- multifile rule/3.
:- multifile abducible/2.
%% :- multifile conflict/2.

% input (evidence):
% claimedResponsibility/2
% identifiedIndividualInAttack/2
% malwareUsedInAttack/2 (current)
% target/2

% input (bg):
% country
% isCulprit/2 (past attacks)
% malwareUsedInAttack/2 (past)

abducible(notForBlackMarketUse(_), []).
abducible(hasCapability(_,_), []).

rule(notTargetted, neg(specificTarget(Att)),[target(T1, Att), target(T2, Att), T1 \= T2]).


rule(culprit(claimedResp,X,Att), 		isCulprit(X,Att,1),	[claimedResponsibility(X,Att)]).
rule(culprit(motiveAndCapability,C,Att),isCulprit(C,Att,3), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(culprit(motive,C,Att), 			isCulprit(C, Att,N),[country(C), prominentGroup(Group), isCulprit(Group, Att, N1), groupOrigin(Group, C), hasMotive(C, Att), N is N1 + 2]).
rule(culprit(motiveAndLocation,C,Att), 	isCulprit(C,Att,N), [country(C), hasMotive(C,Att),culpritIsFrom(C,Att,L), reliability(L,N)]).
rule(culprit(loc,C,Att),	 			isCulprit(C,Att,N),	[country(C), culpritIsFrom(C,Att,L), reliability(L,N)]).
rule(culprit(social,C,Att), 			isCulprit(C,Att,2), [country(C), governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).
rule(culprit(linkedMalware,X,A1),	 	isCulprit(X, A1, N),[malwareUsedInAttack(M1,A1),similar(M1,M2),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2), reliability(similarMalware,N)]).


rule(emptyHasCap, 	hasCapability([], _Att), 	[]).
rule(allHasCap, 	hasCapability([X|L], Att), 	[hasCapability(X,Att), hasCapability(L,Att)]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).

rule(notCulprit(noCapability,Att), 	neg(isCulprit(C,Att,2)), 	[culpritIsFrom(C,Att,_L),neg(hasCapability(C,Att))]).
rule(notCulprit(weakAttack,Att), 	neg(isCulprit(C,Att,2)),	[country(C), neg(requireHighResource(Att))]).
rule(notCulprit(targetItself,Att), 	neg(isCulprit(C,Att,1)),	[target(C,Att)]). % Purposely leave out for now
rule(notCulprit(lowGciTier,Att), 	neg(isCulprit(C,Att,2)),		[gci_tier(C,initiating)]).
rule(notCulprit(noMotive,Att), 		neg(isCulprit(X,Att,3)),	[neg(hasMotive(X,Att))]).
rule(notCulprit(oneCulprit,Att), 	neg(isCulprit(X,Att,_)), 	[isCulprit(Y,Att,_), X \= Y]).


%% rule(similarMalware, isCulprit(X, A1), 
%% 	[malwareUsedInAttack(M1,A1),similar(M1,M2),malwareUsedInAttack(M2,A2),
	%% isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
%% rule(grpPastTargets, hasMotive(Group, Att), [target(T, Att), prominentGroup(Group), pastTargets(Group, Ts), member(T, Ts)]). %WEAK RULE


% pref
%% conflict(notCulprit(oneCulprit,_), culprit(_,_,_)).

rule(p0, prefer(culprit(motiveAndCapability,_,_), culprit(claimedResp,_,_)), []).
rule(p1, prefer(culprit(motiveAndLocation,_,_), culprit(claimedResp,_,_)), []).
rule(p2, prefer(culprit(motive,_,_), culprit(claimedResp,_,_)), []).
rule(p3, prefer(culprit(social,_,_), culprit(claimedResp,_,_)), []).
rule(p4, prefer(culprit(linkedMalware,_,_), culprit(claimedResp,_,_)), []).

rule(p5, prefer(notCulprit(noCapability,_),culprit(motiveAndLocation,_,_)), []).
rule(p6, prefer(notCulprit(noCapability,_),culprit(loc,_,_)), []).

rule(p7, prefer(culprit(social,_,_),notCulprit(noCapability,_)), []).
rule(p9, prefer(culprit(linkedMalware,_,_), notCulprit(noCapability,_)), []).
%% rule(p8, prefer(similarMalware, noCap(_Att)), []).
%% rule(p8, prefer(noMotive(Att), grpPastTargets), []).

%% rule(p10, prefer(notCulprit(targetItself,Att), claimedResp(X,Att)), [specificTarget(Att)]).
rule(p11, prefer(notCulprit(targetItself,Att), culprit(_,_,Att)), [specificTarget(Att)]).
rule(p12, prefer(notCulprit(oneCulprit,_), culprit(_,_,_)), []).

%% rule(p16, prefer(oneCulprit(Y,X,Att), claimedResp(X,Att)),	[]).
%% rule(p16, prefer(oneCulprit(Y,X,Att), claimedResp(X,Att)),	[]).



goal(A, X, N, D) :- visual_prove([isCulprit(X, A, N)], D).
goal_with_timeout(A, X, N, D, Result) :- time_out(goal(A, X, N, D), 3000, Result).
