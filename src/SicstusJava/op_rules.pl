:- compile('utils.pl').
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
abducible(specificTarget(_Att), []).

rule(hasResources1, hasResources(X), [gci_tier(X,leading)]).
rule(hasResources2, hasResources(X), [cybersuperpower(X)]).

% more than one country targetted
rule(notTargetted, neg(specificTarget(Att)),[targetCountry(T1, Att), targetCountry(T2, Att), T1 \= T2]). 

rule(hasCapability1, hasCapability(_X, Att), [neg(requireHighResource(Att))]).
rule(hasCapability2, hasCapability(X, Att), [requireHighResource(Att), hasResources(X)]).
rule(noCapability, neg(hasCapability(X, Att)), [requireHighResource(Att), neg(hasResources(X))]).

rule(ecMotive(C,T), 	hasMotive(C, Att), 		[industry(T), target(T, Att), hasEconomicMotive(C, T), specificTarget(Att)]).
rule(pMotive(C,T),    	hasMotive(C, Att), 		[targetCountry(T, Att), attackPeriod(Att, Date1), hasPoliticalMotive(C, T, Date2), 
	dateApplicable(Date1, Date2), specificTarget(Att)]).
rule(pMotive(C,T,Date), hasPoliticalMotive(C, T, Date), [imposedSanctions(T, C, Date)]).
rule(conflict(X,T), 	hasMotive(X, Att), 		[targetCountry(T, Att), attackPeriod(Att, Date1),
  news(News, T, Date2), dateApplicable(Date1,Date2), causeOfConflict(X, T, News), specificTarget(Att)]).
rule(conflict1(X,T),   hasMotive(X, Att), 		[target(T, Att), attackPeriod(Att, Date1),
  news(News, T, Date2), dateApplicable(Date1,Date2), causeOfConflict(X, T, News), specificTarget(Att)]).
rule(geopolitics(C,T), 	hasMotive(C, Att), 		[target(T, Att), country(T), country(C), poorRelation(C,T)]).
rule(geopolitics(C,T), 	hasMotive(C, Att), 		[target(T, Att), country(T), country(C), poorRelation(T,C)]).
rule(geopolitics1(C,T), neg(hasMotive(C, Att)), [target(T, Att), country(T), country(C), goodRelation(C,T)]).
rule(geopolitics1(C,T), neg(hasMotive(C, Att)), [target(T, Att), country(T), country(C), goodRelation(T,C)]).

%% Y2 M2 is before Y1 M1 but recent enough (within 2 years)
rule(date, dateApplicable(_,ongoing), []).
rule(date1, dateApplicable([Y,M|_], [Y,M|_]), []).
rule(date2, dateApplicable([Y,M1|_],[Y,M2|_]), [M2 < M1]).
rule(date3, dateApplicable([Y1,_|_],[Y2,_|_]), [Y2 < Y1, Y2 > (Y1 - 3)]).


% prefer
rule(p1_op, prefer(ecMotive(C,T), geopolitics1(C,T)), []).
rule(p2_op, prefer(conflict(C,T), geopolitics1(C,T)), []).
rule(p3_op, prefer(conflict1(C,T), geopolitics1(C,T)), []).
rule(p4_op, prefer(pMotive(C,T), geopolitics1(C,T)), []).


% output:
%% hasCapability(X,A)
%% hasMotive(X,A)

goal(A, X, X1, D0, D1) :-
  initFile('op.pl'), case(A),
  writeToFiles('op.pl', hasCapability(X,A), hasCapability(X,A,D0), 'op_'),
  writeToFiles('op.pl', hasMotive(X1,A), hasMotive(X1,A,D1), 'op_').

goal_all(A, X, X1, D0, D1) :-
  initFile('op.pl'), case(A),
  writeToFilesAll('op.pl', hasCapability(X,A), hasCapability(X,A,D0), 'op_'),
  writeToFilesAll('op.pl', hasMotive(X1,A), hasMotive(X1,A,D1), 'op_').

hasCapability(X,A,D0) :- prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- prove([hasMotive(X,A)], D1).
