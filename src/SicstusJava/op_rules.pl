%% :- compile('utils.pl').
%% :- compile('tech.pl').
:- multifile rule/3.
:- multifile abducible/2.

% input from tech:
% hasResources/1
% requireHighResource/1

% input (evidence):
% hasPoliticalMotive/3
% target/2
% imposedSanctions/2
% hasEconomicMotive/2
% highSecurity/1
% geolocatedInGovFacility/2
% publicCommentsRelatedToGov/2

% input (background):
% industry/1
abducible(specificTarget(_Att),[]).

rule(r_op_hasResources1(X),hasResources(X),[gci_tier(X,leading)]).
rule(r_op_hasResources2(X),hasResources(X),[cybersuperpower(X)]).

% more than one country targetted
rule(r_op_notTargetted(Att),neg(specificTarget(Att)),[targetCountry(T1,Att),targetCountry(T2,Att),T1 \= T2]). 

rule(r_op_hasCapability1(X,Att),hasCapability(X,Att),[neg(requireHighResource(Att))]).
rule(r_op_hasCapability2(X,Att),hasCapability(X,Att),[requireHighResource(Att),hasResources(X)]).
rule(r_op_noCapability(X,Att),neg(hasCapability(X,Att)),[requireHighResource(Att),neg(hasResources(X))]).

rule(r_op_ecMotive(C,T),	hasMotive(C,Att),		 [industry(T),target(T,Att),hasEconomicMotive(C,T),specificTarget(Att)]).
rule(r_op_pMotive(C,T),   	hasMotive(C,Att),		 [targetCountry(T,Att),attackPeriod(Att,Date1),hasPoliticalMotive(C,T,Date2),dateApplicable(Date1,Date2),specificTarget(Att)]).
rule(r_op_pMotive1(C,T,Date),hasPoliticalMotive(C,T,Date),[imposedSanctions(T,C,Date)]).
rule(r_op_conflict(X,T),	hasMotive(X,Att),		 [targetCountry(T,Att),attackPeriod(Att,Date1),news(News,T,Date2),dateApplicable(Date1,Date2),causeOfConflict(X,T,News),specificTarget(Att)]).
rule(r_op_conflict1(X,T),  hasMotive(X,Att),		 [target(T,Att),attackPeriod(Att,Date1),news(News,T,Date2),dateApplicable(Date1,Date2),causeOfConflict(X,T,News),specificTarget(Att)]).
rule(r_op_geopolitics1(C,T),	hasMotive(C,Att),	 [target(T,Att),country(T),country(C),poorRelation(C,T)]).
rule(r_op_geopolitics2(C,T),	hasMotive(C,Att),	 [target(T,Att),country(T),country(C),poorRelation(T,C)]).
rule(r_op_nonGeopolitics1(C,T),neg(hasMotive(C,Att)),[target(T,Att),country(T),country(C),goodRelation(C,T)]).
rule(r_op_nonGeopolitics2(C,T),neg(hasMotive(C,Att)),[target(T,Att),country(T),country(C),goodRelation(T,C)]).

%% Y2 M2 is before Y1 M1 but recent enough (within 2 years)
rule(r_op_date(ongoing),dateApplicable(_,ongoing),[]).
rule(r_op_date1(Y,M),dateApplicable([Y,M],[Y,M]),[]).
rule(r_op_date2(Y,M1,M2),dateApplicable([Y,M1],[Y,M2]),[M2 < M1]).
rule(r_op_date3(Y1,Y2),dateApplicable([Y1,_],[Y2,_]),[Y2 < Y1,Y2 > (Y1 - 3)]).


% prefer
rule(p1a_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p1b_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p2a_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p2b_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p3a_op(),prefer(r_op_conflict1(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p3b_op(),prefer(r_op_conflict1(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p4a_op(),prefer(r_op_pMotive(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p4b_op(),prefer(r_op_pMotive(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p4c_op(),prefer(r_op_pMotive1(C,T,_D),r_op_nonGeopolitics1(C,T)),[]).
rule(p4d_op(),prefer(r_op_pMotive1(C,T,_D),r_op_nonGeopolitics2(C,T)),[]).