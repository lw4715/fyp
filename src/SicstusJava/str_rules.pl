:- multifile rule/3.
:- multifile abducible/2.

%% input
%% tech:
%% notForBlackMarketUse 
%% similar
%% requireHighResource

%% bg:
%% prominentGroup
%% country
%% isCulprit
%% groupOrigin
%% malwareLinkedTo
%% gci_tier

%% evidence:
%% attackOrigin
%% identifiedIndividualInAttack
%% malwareUsedInAttack
%% target
%% targetCountry

%% op:
%% existingGroupClaimedResponsibility
%% hasMotive
%% hasCapability
%% hasResources



abducible(notForBlackMarketUse(_),[]).

complement(isCulprit(X,Att),isCulprit(Y,Att)) :- X \= Y.

rule(r_str_emptyHasCap(Att),            hasCapability([],Att),  []).
rule(r_str_allHaveCap([X|L],Att),       hasCapability([X|L],Att),   [\+ is_list(X),is_list(L),hasCapability(X,Att),hasCapability(L,Att)]).
rule(r_str_prominentGrpHasCap(X,Att),   hasCapability(X,Att),       [prominentGroup(X)]).

rule(r_str__claimedResp(X,Att),         isCulprit(X,Att),   [existingGroupClaimedResponsibility(X,Att)]).

rule(r_str__motiveAndCapability(C,Att), isCulprit(C,Att),   [hasMotive(C,Att),hasCapability(C,Att)]).
rule(r_str__motive(C,Att),              isCulprit(C,Att),   [prominentGroup(Group),groupOrigin(Group,C),country(C),isCulprit(Group,Att),hasMotive(C,Att)]).
rule(r_str__motiveAndLocation(C,Att),   isCulprit(C,Att),   [hasMotive(C,Att),attackOrigin(C,Att),country(C)]).
rule(r_str__loc(C,Att),                 isCulprit(C,Att),   [attackOrigin(C,Att),country(C)]).
rule(r_str__social(C,Att),              isCulprit(C,Att),   [governmentLinked(P,C),country(C),identifiedIndividualInAttack(P,Att)]).
rule(r_str__linkedMalware(X,A1),        isCulprit(X,A1),    [malwareUsedInAttack(M1,A1),similar(M1,M2),malwareLinkedTo(M2,X),notForBlackMarketUse(M1),notForBlackMarketUse(M2)]).

%% GUI: analyst add rules and preferences
rule(r_str__noEvidence(X,Att),          neg(isCulprit(X,Att)),[]).
rule(r_str__noHistory(X,Att),           neg(isCulprit(X,Att)),[neg(existingGroupClaimedResponsibility(X,Att))]).
rule(r_str__negAttackOrigin(X,Att),     neg(isCulprit(X,Att)),[neg(attackOrigin(X,Att))]).
rule(r_str__noCapability(X,Att),        neg(isCulprit(X,Att)),[neg(hasCapability(X,Att))]).
rule(r_str__noMotive(X,Att),            neg(isCulprit(X,Att)),[neg(hasMotive(X,Att))]).
rule(r_str__weakAttack(X,Att),          neg(isCulprit(X,Att)),[hasResources(X),neg(requireHighResource(Att))]).
rule(r_str__targetItself1(X,Att),       neg(isCulprit(X,Att)),[target(X,Att)]).
rule(r_str__targetItself2(X,Att),       neg(isCulprit(X,Att)),[targetCountry(X,Att)]).
%% rule(r_str__lowGciTier(X,Att),          neg(isCulprit(X,Att)),[hasNoResources(X)]).
%% rule(r_str_oneCulprit(X,Att),    neg(isCulprit(X,Att,_)),[isCulprit(Y,Att,_),X \= Y]).


%% rule(r_str_grpPastTargets,hasMotive(Group,Att),[target(T,Att),prominentGroup(Group),pastTargets(Group,Ts),member(T,Ts)]). %WEAK RULE


% pref
rule(p0a(),prefer(r_str__claimedResp(X,A),r_str__noEvidence(X,A)),[]). %With any evidence,we prefer to attribute the culprit accordingly
rule(p0b(),prefer(r_str__motiveAndCapability(X,A),r_str__noEvidence(X,A)),[]).
rule(p0c(),prefer(r_str__motive(X,A),r_str__noEvidence(X,A)),[]).
rule(p0d(),prefer(r_str__motiveAndLocation(X,A),r_str__noEvidence(X,A)),[]).
rule(p0e(),prefer(r_str__loc(X,A),r_str__noEvidence(X,A)),[]).
rule(p0f(),prefer(r_str__social(X,A),r_str__noEvidence(X,A)),[]).
rule(p0g(),prefer(r_str__linkedMalware(X,A),r_str__noEvidence(X,A)),[]).

rule(p1a(),prefer(r_str__motiveAndCapability(_X,A),r_str__claimedResp(_Y,A)),[]).   
rule(p1b(),prefer(r_str__motiveAndLocation(_X,A),r_str__claimedResp(_Y,A)),[]). 
rule(p1c(),prefer(r_str__motive(_X,A),       r_str__claimedResp(_Y,A)),[]). 
rule(p1d(),prefer(r_str__social(_X,A),       r_str__claimedResp(_Y,A)),[]). 
rule(p1e(),prefer(r_str__linkedMalware(_X,A),r_str__claimedResp(_Y,A)),[]). %group claiming responsibility might just be facade e.g. guardians of peace sonyhack

rule(p6(),prefer(r_str__noCapability(X,A), r_str__claimedResp(X,A)),[]). % hacker group might claim responsibility for attack backed by nation state
rule(p8(),prefer(r_str__noCapability(X,A), r_str__motive(X,A)),[]).    
rule(p9(),prefer(r_str__noCapability(X,A), r_str__motiveAndLocation(X,A)),[]).    
rule(p10(),prefer(r_str__noCapability(X,A), r_str__loc(X,A)),[]).  
rule(p11(),prefer(r_str__noCapability(X,A),r_str__social(X,A)),[]). % social evidences e.g. twitter posts/ emails can be easily forged
rule(p12(),prefer(r_str__noCapability(X,A),r_str__linkedMalware(X,A)),[]).
%% rule(p13(),prefer(r_str__lowGciTier(X,A),  r_str__linkedMalware(X,A)),[]).  

rule(p18(),prefer(r_str__linkedMalware(X,A),r_str__negAttackOrigin(X,A)),[]).

rule(p19(),prefer(r_str__negAttackOrigin(X,A), r_str__motive(X,A)),[]).
rule(p20(),prefer(r_str__weakAttack(X,A),      r_str__motive(X,A)),[]).

rule(p21a(),prefer(r_str__targetItself1(X,Att),r_str__claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p21b(),prefer(r_str__targetItself1(X,Att),r_str__motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p21c(),prefer(r_str__targetItself1(X,Att),r_str__motive(X,Att)),             [specificTarget(Att)]).
rule(p21d(),prefer(r_str__targetItself1(X,Att),r_str__motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p21e(),prefer(r_str__targetItself1(X,Att),r_str__loc(X,Att)),                [specificTarget(Att)]).
rule(p21f(),prefer(r_str__targetItself1(X,Att),r_str__social(X,Att)),             [specificTarget(Att)]).
rule(p21g(),prefer(r_str__targetItself1(X,Att),r_str__linkedMalware(X,Att)),      [specificTarget(Att)]).

rule(p22a(),prefer(r_str__targetItself2(X,Att),r_str__claimedResp(X,Att)),        [specificTarget(Att)]).
rule(p22b(),prefer(r_str__targetItself2(X,Att),r_str__motiveAndCapability(X,Att)),[specificTarget(Att)]).
rule(p22c(),prefer(r_str__targetItself2(X,Att),r_str__motive(X,Att)),             [specificTarget(Att)]).
rule(p22d(),prefer(r_str__targetItself2(X,Att),r_str__motiveAndLocation(X,Att)),  [specificTarget(Att)]).
rule(p22e(),prefer(r_str__targetItself2(X,Att),r_str__loc(X,Att)),                [specificTarget(Att)]).
rule(p22f(),prefer(r_str__targetItself2(X,Att),r_str__social(X,Att)),             [specificTarget(Att)]).
rule(p22g(),prefer(r_str__targetItself2(X,Att),r_str__linkedMalware(X,Att)),      [specificTarget(Att)]).


rule(p23a(),prefer(r_str__linkedMalware(X,A),r_str__noHistory(X,A)),[]).
rule(p23c(),prefer(r_str__linkedMalware(X,A),r_str__noMotive(X,A)),[]).
rule(p23d(),prefer(r_str__linkedMalware(X,A),r_str__weakAttack(X,A)),[]).

%% rule(r_str_p30,prefer(p8,p2),[]).

goal(A,X,D) :- visual_prove([isCulprit(X,A)],D,[]).
neg_goal(A,X,D) :- prove([neg(isCulprit(X,A))],D).

goal_all(A,X,D) :-
  writeToFilesPos(isCulprit(X,A), isCulprit(X,A,D)).

isCulprit(X,A,D) :- prove([isCulprit(X,A)],D).


