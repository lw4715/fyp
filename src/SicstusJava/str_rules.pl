:- compile('utils.pl').
:- multifile rule/3.
:- multifile abducible/2.

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
%% abducible(hasCapability(_,_), []).

rule(social1(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(social2(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

rule(emptyHasCap, 	hasCapability([], _Att), 	[]).
rule(allHaveCap, 	hasCapability([X|L], Att), 	[\+ is_list(X), is_list(L), hasCapability(X,Att), hasCapability(L,Att)]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).

rule(claimedResp(X,Att), 		isCulprit(X,Att),	[claimedResponsibility(X,Att)]).
rule(noHistory(X,Att),        neg(isCulprit(X,Att)),[claimedResponsibility(X,Att), noPriorHistory(X)]).

rule(motiveAndCapability(C,Att),isCulprit(C,Att),   [hasMotive(C,Att),hasCapability(C,Att)]).
rule(motive(C,Att), 			isCulprit(C,Att),   [country(C), prominentGroup(Group), isCulprit(Group, Att), groupOrigin(Group, C), hasMotive(C, Att)]).
rule(motiveAndLocation(C,Att), 	isCulprit(C,Att),   [country(C), hasMotive(C,Att),attackOrigin(C,Att)]).
rule(loc(C,Att),	 			isCulprit(C,Att),	[country(C), attackOrigin(C,Att)]).
rule(social(C,Att), 			isCulprit(C,Att),   [country(C), governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).
rule(linkedMalware(X,A1),	 	isCulprit(X,A1),    [malwareUsedInAttack(M1,A1),similar(M1,M2),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
rule(linkedMalware(X,A1),       isCulprit(X,A1),    [malwareUsedInAttack(M1,A1),similar(M2,M1),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).

%% culprit not from, notculprit rule, add pref
%% make example case with spoof ip, use tor
%% more negation rules
%% pref of pref
%% mixed version of score and pref
%% add base rule: no info means not culprit

%% GUI: analyst add rules and preferences

rule(noEvidence(X,Att), 	neg(isCulprit(X,Att)), []).
rule(negAttackOrigin(X,Att),neg(isCulprit(X,Att)), [neg(attackOrigin(X, Att))]).
rule(noCapability(X,Att), 	neg(isCulprit(X,Att)), [neg(hasCapability(X,Att))]).
rule(noMotive(X,Att),       neg(isCulprit(X,Att)), [neg(hasMotive(X,Att))]).
rule(weakAttack(X,Att), 	neg(isCulprit(X,Att)), [hasResources(X), neg(requireHighResource(Att))]).
rule(targetItself(X,Att), 	neg(isCulprit(X,Att)), [target(X,Att)]).
rule(targetItself(X,Att),   neg(isCulprit(X,Att)), [targetCountry(X,Att)]).
rule(lowGciTier(X,Att), 	neg(isCulprit(X,Att)), [gci_tier(X,initiating)]).

%% rule(oneCulprit(X,Att), 	neg(isCulprit(X,Att,_)), [isCulprit(Y,Att,_), X \= Y]).


%% rule(similarMalware, isCulprit(X, A1), 
%% 	[malwareUsedInAttack(M1,A1),similar(M1,M2),malwareUsedInAttack(M2,A2),
	%% isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
%% rule(grpPastTargets, hasMotive(Group, Att), [target(T, Att), prominentGroup(Group), pastTargets(Group, Ts), member(T, Ts)]). %WEAK RULE


% pref
rule(p0a, prefer(claimedResp(X,A),noEvidence(X,A)), []). %With any evidence, we prefer to attribute the culprit accordingly
rule(p0b, prefer(motiveAndCapability(X,A),noEvidence(X,A)), []).
rule(p0c, prefer(motive(X,A),noEvidence(X,A)), []).
rule(p0d, prefer(motiveAndLocation(X,A),noEvidence(X,A)), []).
rule(p0e, prefer(loc(X,A),noEvidence(X,A)), []).
rule(p0f, prefer(social(X,A),noEvidence(X,A)), []).
rule(p0g, prefer(linkedMalware(X,A),noEvidence(X,A)), []).

rule(p1, prefer(motiveAndCapability(X,A), claimedResp(Y,A)), [X\=Y]).   
rule(p2, prefer(motiveAndLocation(X,A), claimedResp(Y,A)), [X\=Y]). 
rule(p3, prefer(motive(X,A),        claimedResp(Y,A)), [X\=Y]). 
rule(p4, prefer(social(X,A),        claimedResp(Y,A)), [X\=Y]). 
rule(p5, prefer(linkedMalware(X,A), claimedResp(Y,A)), [X\=Y]). %group claiming responsibility might just be facade e.g. guardians of peace sonyhack

rule(p6, prefer(noCapability(X,A),  claimedResp(X,A)),[]). % hacker group might claim responsibility for attack backed by nation state
rule(p7, prefer(noHistory(X,A),  claimedResp(X,A)),[]). % hacker group might claim responsibility for attack backed by nation state

%% rule(p7, prefer(noCapability(X,A),  motive(X,A)), []).    
rule(p8, prefer(noCapability(X,A),  motiveAndLocation(X,A)), []).    
rule(p9, prefer(noCapability(X,A),  loc(X,A)), []).  
rule(p10, prefer(noCapability(X,A), social(X,A)),[]). % social evidences e.g. twitter posts/ emails can be easily forged
rule(p12, prefer(noCapability(X,A), linkedMalware(X,A)), []).
rule(p13, prefer(lowGciTier(X,A),   linkedMalware(X,A)), []).  

rule(p18, prefer(linkedMalware(X,A), negAttackOrigin(X,A)), []).

rule(p19, prefer(negAttackOrigin(X,A),  motive(X,A)), []).
rule(p20, prefer(weakAttack(X,A),       motive(X,A)), []).

rule(p36a, prefer(targetItself(X,Att), claimedResp(X,Att)),         [specificTarget(Att)]).
rule(p36b, prefer(targetItself(X,Att), motiveAndCapability(X,Att)), [specificTarget(Att)]).
rule(p36c, prefer(targetItself(X,Att), motive(X,Att)),              [specificTarget(Att)]).
rule(p36d, prefer(targetItself(X,Att), motiveAndLocation(X,Att)),   [specificTarget(Att)]).
rule(p36e, prefer(targetItself(X,Att), loc(X,Att)),                 [specificTarget(Att)]).
rule(p36f, prefer(targetItself(X,Att), social(X,Att)),              [specificTarget(Att)]).
rule(p36g, prefer(targetItself(X,Att), linkedMalware(X,Att)),       [specificTarget(Att)]).

%% YES
%% claimedResp
%% motiveAndCapability
%% motive
%% motiveAndLocation
%% loc
%% social
%% linkedMalware

%% NO
%% noEvidence
%% negAttackOrigin
%% noCapability
%% noMotive
%% weakAttack
%% targetItself
%% lowGciTier
%% oneCulprit

%% rule(p37, prefer(p12, p16), []).
%% rule(p38, prefer(p13, p16), []).
rule(p37, prefer(p8, p2), []).

goal(A, X, D) :- visual_prove([isCulprit(X, A)], D, [failed(true)]).

%% goal_with_timeout(A, X, D, Result) :- time_out(goal(A, X, D), 6000, Result).

