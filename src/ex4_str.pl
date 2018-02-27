:- compile('utils.pl').
:- compile('background.pl').
:- compile('op.pl').
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


rule(similarMalware, isCulprit(X, A1), [similar(M1,M2),malwareUsedInAttack(M1,A1),malwareUsedInAttack(M2,A2),isCulprit(X,A2),neg(forBlackMarketUse(M1)),neg(forBlackMarketUse(M2))]).
rule(claimedResp, isCulprit(G,Att), [claimedResponsibility(G,Att)]).
rule(hasMotiveAndCap, isCulprit(C,Att), [hasMotive(C,Att),hasCapability(C,Att)]).

rule(hasMotiveAndLoc, isCulprit(C,Att), [hasMotive(C,Att),culpritIsFrom(C,Att)]).
rule(noCap, neg(isCulprit(C,Att)), [culpritIsFrom(C,Att),neg(hasCapability(C,Att))]).
rule(social3, isCulprit(C,Att), [governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).

rule(weakAttack, neg(isCulprit(C,Att)), [\+(highLevelSkill(Att)),isCountry(C)]).
rule(hasPrecedenceOfAttack, hasResources(X), [isCulprit(X, _)]).

% pref
rule(p0, prefer(hasMotiveAndCap,claimedResp), []).
rule(p1, prefer(hasMotiveAndLoc,claimedResponsibility), []).
rule(p2, prefer(noCap,hasMotiveAndLoc), []).
rule(p3, prefer(social3,noCap), []).
rule(p4, prefer(similarMalware, noCap), []).

% evidences
%% rule(f6, isCulprit(equationGroup,flameattack), []).
%% rule(f11, target(middleeast,flameattack), []).
%% rule(f4, malwareUsedInAttack(flame,flameattack), []).

goal(X, D) :- prove([isCulprit(X, attack)], D).