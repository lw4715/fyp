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

rule(notTargetted, neg(specificTarget(Att)),[targetCountry(T1, Att), targetCountry(T2, Att), T1 \= T2]). % more than one country targetted
rule(social1(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(social2(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

rule(emptyHasCap, 	hasCapability([], _Att), 	[]).
rule(allHasCap, 	hasCapability([X|L], Att), 	[\+ is_list(X), is_list(L), hasCapability(X,Att), hasCapability(L,Att)]).
rule(prominentGrpHasCapability, hasCapability(X, _Att), [prominentGroup(X)]).
rule(relatedMalware, malwareLinkedTo(M,X), [malwareUsedInAttack(M,A), isCulprit(X,A)]).

rule(culprit(claimedResp,X,Att), 		isCulprit(X,Att,1),	[claimedResponsibility(X,Att)]).
rule(culprit(motiveAndCapability,C,Att),isCulprit(C,Att,3), [hasMotive(C,Att),hasCapability(C,Att)]).
rule(culprit(motive,C,Att), 			isCulprit(C,Att,N), [country(C), prominentGroup(Group), isCulprit(Group, Att, N1), groupOrigin(Group, C), hasMotive(C, Att), N is N1 + 2]).
rule(culprit(motiveAndLocation,C,Att), 	isCulprit(C,Att,N), [country(C), hasMotive(C,Att),culpritIsFrom(C,Att,L), reliability(L,N)]).
rule(culprit(loc,C,Att),	 			isCulprit(C,Att,N),	[country(C), culpritIsFrom(C,Att,L), reliability(L,N)]).
rule(culprit(social,C,Att), 			isCulprit(C,Att,2), [country(C), governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).
rule(culprit(linkedMalware,X,A1),	 	isCulprit(X,A1, N), [malwareUsedInAttack(M1,A1),similar(M1,M2),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2), reliability(similarMalware,N)]).
rule(culprit(linkedMalware,X,A1),       isCulprit(X,A1, N), [malwareUsedInAttack(M1,A1),similar(M2,M1),
  malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2), reliability(similarMalware,N)]).

%% culprit not from, notculprit rule, add pref
%% make example case with spoof ip, use tor
%% more negation rules
%% pref of pref
%% mixed version of score and pref
%% add base rule: no info means not culprit

%% GUI: analyst add rules and preferences

rule(notCulprit(noEvidence,X,Att), 	neg(isCulprit(X,Att,0)), []).
rule(notCulprit(culpritNotFrom,X,Att),neg(isCulprit(X,Att,N)), [neg(culpritIsFrom(X, Att, L)), reliability(L,N)]).
rule(notCulprit(noCapability,X,Att), 	neg(isCulprit(X,Att,2)), [neg(hasCapability(X,Att))]).
rule(notCulprit(noMotive,X,Att),      neg(isCulprit(X,Att,3)), [neg(hasMotive(X,Att))]).
rule(notCulprit(weakAttack,X,Att), 	neg(isCulprit(X,Att,2)), [hasResources(X), neg(requireHighResource(Att))]).
rule(notCulprit(targetItself,X,Att), 	neg(isCulprit(X,Att,1)), [target(X,Att)]). % Purposely leave out for now
rule(notCulprit(lowGciTier,X,Att), 	neg(isCulprit(X,Att,2)), [gci_tier(X,initiating)]).
%% rule(notCulprit(noLinkToGov,X,Att),   neg(isCulprit(X,Att,2)), [neg(governmentLinked(P,X)),identifiedIndividualInAttack(P,Att)]). % could be individual attack

%% rule(notCulprit(oneCulprit,Att), 	neg(isCulprit(X,Att,_)), [isCulprit(Y,Att,_), X \= Y]).


%% rule(similarMalware, isCulprit(X, A1), 
%% 	[malwareUsedInAttack(M1,A1),similar(M1,M2),malwareUsedInAttack(M2,A2),
	%% isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
%% rule(grpPastTargets, hasMotive(Group, Att), [target(T, Att), prominentGroup(Group), pastTargets(Group, Ts), member(T, Ts)]). %WEAK RULE


% pref
rule(p0, prefer(culprit(_,X,A),notCulprit(noEvidence,X,A)), []). %With any evidence, we prefer to attribute the culprit accordingly
rule(p1, prefer(culprit(motiveAndCapability,X,A), culprit(claimedResp,Y,A)), [X\=Y]).   
rule(p2, prefer(culprit(motiveAndLocation,X,A), culprit(claimedResp,Y,A)), [X\=Y]). 
rule(p3, prefer(culprit(motive,X,A), culprit(claimedResp,Y,A)), [X\=Y]). 
rule(p4, prefer(culprit(social,X,A), culprit(claimedResp,Y,A)), [X\=Y]). 
rule(p5, prefer(culprit(linkedMalware,X,A), culprit(claimedResp,Y,A)), [X\=Y]). %group claiming responsibility might just be facade e.g. guardians of peace sonyhack

rule(p6, prefer(notCulprit(noCapability,X,A), culprit(claimedResp,X,A)),[]). % hacker group might claim responsibility for attack backed by nation state
rule(p7, prefer(notCulprit(noCapability,X,A),culprit(motive,X,A)), []).    
rule(p8, prefer(notCulprit(noCapability,X,A),culprit(motiveAndLocation,X,A)), []).    
rule(p9, prefer(notCulprit(noCapability,X,A),culprit(loc,X,A)), []).  
rule(p10, prefer(notCulprit(noCapability,X,A), culprit(social,X,A)),[]). % social evidences e.g. twitter posts/ emails can be easily forged
rule(p12, prefer(notCulprit(noCapability,X,A), culprit(linkedMalware,X,A)), []).

rule(p13, prefer(notCulprit(lowGciTier,X,A), culprit(linkedMalware,X,A)), []).  
%% rule(p14, prefer(notCulprit(noLinkToGov,X,A), culprit(linkedMalware,X,A)), []).

%% rule(p15, prefer(culprit(claimedResp,X,A), notCulprit(noLinkToGov,X,A)), []).
%% rule(p16, prefer(culprit(linkedMalware,X,A), notCulprit(noLinkToGov,X,A)), []). 
%% rule(p17, prefer(culprit(motiveAndCapability,X,A), notCulprit(noLinkToGov,X,A)), []).

rule(p19, prefer(notCulprit(culpritNotFrom,X,A), culprit(motive,X,A)), []).
rule(p20, prefer(notCulprit(weakAttack,X,A), culprit(motive,X,A)), []).


rule(p36, prefer(notCulprit(targetItself,X,Att), culprit(_,X,Att)), [specificTarget(Att)]). 

rule(p37, prefer(p12, p16), []).
rule(p38, prefer(p13, p16), []).
rule(p37, prefer(p8, p2), []).

goal(A, X, N, D) :- tell('visual.log'),visual_prove([isCulprit(X, A, N)], D), told.
goal_with_timeout(A, X, N, D, Result) :- time_out(goal(A, X, N, D), 3000, Result).
