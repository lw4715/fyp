%% :- compile('utils.pl').
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

abducible(notForBlackMarketUse(_),[]).
%% abducible(hasCapability(_,_),[]).

complement(isCulprit(X,Att),isCulprit(Y,Att)) :- X \= Y.


rule(r_str_social1(P,C),governmentLinked(P,C),[geolocatedInGovFacility(P,C)]).
rule(r_str_social2(P,C),governmentLinked(P,C),[publicCommentsRelatedToGov(P,C)]).

rule(r_str_emptyHasCap(Att),		 	hasCapability([],Att),	[]).
rule(r_str_allHaveCap([X|L],Att),		hasCapability([X|L],Att),	[\+ is_list(X),is_list(L),hasCapability(X,Att),hasCapability(L,Att)]).
rule(r_str_prominentGrpHasCap(X,Att),	hasCapability(X,Att),		[prominentGroup(X)]).

%% rule(r_str_claimedResp(X,Att),		isCulprit(X,Att),	[claimedResponsibility(X,Att)]).
rule(r_str_claimedResp(X,Att),		isCulprit(X,Att),	[existingGroupClaimedResponsibility(X,Att)]).

rule(r_str_motiveAndCapability(C,Att),	isCulprit(C,Att),  [hasMotive(C,Att),hasCapability(C,Att)]).
rule(r_str_motive(C,Att),				isCulprit(C,Att),  [country(C),prominentGroup(Group),isCulprit(Group,Att),groupOrigin(Group,C),hasMotive(C,Att)]).
rule(r_str_motiveAndLocation(C,Att),	isCulprit(C,Att),  [country(C),hasMotive(C,Att),attackOrigin(C,Att)]).
rule(r_str_loc(C,Att),	 				isCulprit(C,Att),  [country(C),attackOrigin(C,Att)]).
rule(r_str_social(C,Att),				isCulprit(C,Att),  [country(C),governmentLinked(P,C),identifiedIndividualInAttack(P,Att)]).
rule(r_str_linkedMalware(X,A1),	 		isCulprit(X,A1),   [malwareUsedInAttack(M1,A1),similar(M1,M2),malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).

%% culprit not from,notculprit rule,add pref
%% make example case with spoof ip,use tor
%% more negation rules
%% pref of pref
%% mixed version of score and pref
%% add base rule: no info means not culprit

%% GUI: analyst add rules and preferences
rule(r_str_noEvidence(X,Att),	neg(isCulprit(X,Att)),[]).
rule(r_str_noHistory(X,Att),     neg(isCulprit(X,Att)),[neg(existingGroupClaimedResponsibility(X,Att))]).
rule(r_str_negAttackOrigin(X,Att),neg(isCulprit(X,Att)),[neg(attackOrigin(X,Att))]).
rule(r_str_noCapability(X,Att),	neg(isCulprit(X,Att)),[neg(hasCapability(X,Att))]).
rule(r_str_noMotive(X,Att),      neg(isCulprit(X,Att)),[neg(hasMotive(X,Att))]).
rule(r_str_weakAttack(X,Att),	neg(isCulprit(X,Att)),[hasResources(X),neg(requireHighResource(Att))]).
rule(r_str_targetItself1(X,Att),	neg(isCulprit(X,Att)),[target(X,Att)]).
rule(r_str_targetItself2(X,Att),  neg(isCulprit(X,Att)),[targetCountry(X,Att)]).
rule(r_str_lowGciTier(X,Att),	neg(isCulprit(X,Att)),[gci_tier(X,initiating)]).

%% rule(r_str_oneCulprit(X,Att),	neg(isCulprit(X,Att,_)),[isCulprit(Y,Att,_),X \= Y]).


%% rule(r_str_similarMalware,isCulprit(X,A1),
%% 	[malwareUsedInAttack(M1,A1),similar(M1,M2),malwareUsedInAttack(M2,A2),
	%% isCulprit(X,A2),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).
%% rule(r_str_grpPastTargets,hasMotive(Group,Att),[target(T,Att),prominentGroup(Group),pastTargets(Group,Ts),member(T,Ts)]). %WEAK RULE


% pref
rule(p0a(),prefer(r_str_claimedResp(X,A),r_str_noEvidence(X,A)),[]). %With any evidence,we prefer to attribute the culprit accordingly
rule(p0b(),prefer(r_str_motiveAndCapability(X,A),r_str_noEvidence(X,A)),[]).
rule(p0c(),prefer(r_str_motive(X,A),r_str_noEvidence(X,A)),[]).
rule(p0d(),prefer(r_str_motiveAndLocation(X,A),r_str_noEvidence(X,A)),[]).
rule(p0e(),prefer(r_str_loc(X,A),r_str_noEvidence(X,A)),[]).
rule(p0f(),prefer(r_str_social(X,A),r_str_noEvidence(X,A)),[]).
rule(p0g(),prefer(r_str_linkedMalware(X,A),r_str_noEvidence(X,A)),[]).

rule(p1a(),prefer(r_str_motiveAndCapability(_X,A),r_str_claimedResp(_Y,A)),[]).   
rule(p1b(),prefer(r_str_motiveAndLocation(_X,A),r_str_claimedResp(_Y,A)),[]). 
rule(p1c(),prefer(r_str_motive(_X,A),       r_str_claimedResp(_Y,A)),[]). 
rule(p1d(),prefer(r_str_social(_X,A),       r_str_claimedResp(_Y,A)),[]). 
rule(p1e(),prefer(r_str_linkedMalware(_X,A),r_str_claimedResp(_Y,A)),[]). %group claiming responsibility might just be facade e.g. guardians of peace sonyhack
%% rule(p1f(),prefer(r_str_noHistory(X,A),r_str_claimedResp(X,A)),[]).   

rule(p6(),prefer(r_str_noCapability(X,A), r_str_claimedResp(X,A)),[]). % hacker group might claim responsibility for attack backed by nation state

rule(p8(),prefer(r_str_noCapability(X,A), r_str_motive(X,A)),[]).    
rule(p9(),prefer(r_str_noCapability(X,A), r_str_motiveAndLocation(X,A)),[]).    
rule(p10(),prefer(r_str_noCapability(X,A), r_str_loc(X,A)),[]).  
rule(p11(),prefer(r_str_noCapability(X,A),r_str_social(X,A)),[]). % social evidences e.g. twitter posts/ emails can be easily forged
rule(p12(),prefer(r_str_noCapability(X,A),r_str_linkedMalware(X,A)),[]).
rule(p13(),prefer(r_str_lowGciTier(X,A),  r_str_linkedMalware(X,A)),[]).  

rule(p18(),prefer(r_str_linkedMalware(X,A),r_str_negAttackOrigin(X,A)),[]).

rule(p19(),prefer(r_str_negAttackOrigin(X,A), r_str_motive(X,A)),[]).
rule(p20(),prefer(r_str_weakAttack(X,A),      r_str_motive(X,A)),[]).

rule(p21a(),prefer(r_str_targetItself1(X,Att),r_str_claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p21b(),prefer(r_str_targetItself1(X,Att),r_str_motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p21c(),prefer(r_str_targetItself1(X,Att),r_str_motive(X,Att)),             [specificTarget(Att)]).
rule(p21d(),prefer(r_str_targetItself1(X,Att),r_str_motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p21e(),prefer(r_str_targetItself1(X,Att),r_str_loc(X,Att)),                [specificTarget(Att)]).
rule(p21f(),prefer(r_str_targetItself1(X,Att),r_str_social(X,Att)),             [specificTarget(Att)]).
rule(p21g(),prefer(r_str_targetItself1(X,Att),r_str_linkedMalware(X,Att)),      [specificTarget(Att)]).

rule(p22a(),prefer(r_str_targetItself2(X,Att),r_str_claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p22b(),prefer(r_str_targetItself2(X,Att),r_str_motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p22c(),prefer(r_str_targetItself2(X,Att),r_str_motive(X,Att)),             [specificTarget(Att)]).
rule(p22d(),prefer(r_str_targetItself2(X,Att),r_str_motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p22e(),prefer(r_str_targetItself2(X,Att),r_str_loc(X,Att)),                [specificTarget(Att)]).
rule(p22f(),prefer(r_str_targetItself2(X,Att),r_str_social(X,Att)),             [specificTarget(Att)]).
rule(p22g(),prefer(r_str_targetItself2(X,Att),r_str_linkedMalware(X,Att)),      [specificTarget(Att)]).


rule(p22a(),prefer(r_str_linkedMalware(X,A),r_str_noHistory(X,A)),[]).
rule(p22c(),prefer(r_str_linkedMalware(X,A),r_str_noMotive(X,A)),[]).
rule(p22d(),prefer(r_str_linkedMalware(X,A),r_str_weakAttack(X,A)),[]).

%% rule(r_str_p30,prefer(p8,p2),[]).

goal(A,X,D) :- visual_prove([isCulprit(X,A)],D,[failed(true)]).
neg_goal(A,X,D) :- prove([neg(isCulprit(X,A))],D).

