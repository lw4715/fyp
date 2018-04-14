:- compile('utils.pl').
%% :- compile('tech.pl').
:- multifile rule/3.
:- multifile abducible/2.

% input from tech:
% hasResources/1
% requireHighResource/1

% input (evidence):
% hasPoliticalMotive/2
% target/2
% imposedSanctions/2
% hasEconomicMotive/2
% highSecurity/1
% geolocatedInGovFacility/2
% publicCommentsRelatedToGov/2

% input (background):
% industry/1

rule(hasResources1, hasResources(X), [gci_tier(X,leading)]).
rule(hasResources2, hasResources(X), [cybersuperpower(X)]).
%% rule(hasResources2, hasResources(X), [gci_tier(X,maturing)]).

rule(hasCapability1, hasCapability(_X, Att), [neg(requireHighResource(Att))]).
rule(hasCapability2, hasCapability(X, Att), [requireHighResource(Att), hasResources(X)]).
rule(noCapability, neg(hasCapability(X, Att)), [requireHighResource(Att), neg(hasResources(X))]).

rule(ecMotive(C,T), hasMotive(C, Att), [industry(T), target(T, Att), hasEconomicMotive(C, T), specificTarget(Att)]).
rule(pMotive,       hasMotive(C, Att), [target(T, Att), hasPoliticalMotive(C, T), specificTarget(Att)]).
rule(pMotive(C,T),  hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).
rule(conflict,      hasMotive(X, Att), [target(T, Att), attackYear(Att, Y),
  recentNewsInYear(News, T, Y), causeOfConflict(X, T, News), specificTarget(Att)]).

rule(social1(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(social2(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

abducible(specificTarget(_Att), []).

% prefer
% rule(nafCap, prefer(hasCapability1, noCapability), []).
% rule(nafCap1, prefer(hasCapability2, noCapability), []).
% rule(nafMot, prefer(ecMotive, motiveDefault), []).
% rule(nafMot1, prefer(pMotive, motiveDefault), []).
% rule(nafMot2, prefer(pMotive(C,T), motiveDefault), []).
% rule(nafMot3, prefer(conflict, motiveDefault), []).


% output:
%% hasCapability(X,A)
%% hasMotive(X,A)
%% governmentLinked(P,X)

goal(A, X, P, D0, D1, D2) :-
  initFile('op.pl'), case(A),
  writeToFiles('op.pl', hasCapability(X,A), hasCapability(X,A,D0), 'op_'),
  writeToFiles('op.pl', hasMotive(X1,A), hasMotive(X1,A,D1), 'op_'),
  writeToFilesAbd('op.pl', governmentLinked(P,X2), governmentLinked(P,X2,D2), 'op_').

goal_all(A, X, P, D0, D1, D2) :-
  initFile('op.pl'), case(A),
  writeToFilesAll('op.pl', hasCapability(X,A), hasCapability(X,A,D0), 'op_'),
  writeToFilesAll('op.pl', hasMotive(X,A), hasMotive(X,A,D1), 'op_'),
  writeToFilesAllAbd('op.pl', governmentLinked(P,X), governmentLinked(P,X,D2), 'op_').

hasCapability(X,A,D0) :- prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- prove([hasMotive(X,A)], D1).
governmentLinked(P,X,D2) :- prove([governmentLinked(P,X)], D2).
