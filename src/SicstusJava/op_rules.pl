:- compile('utils.pl').
:- compile('tech.pl').
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

rule(hasResources, hasResources(X), [gci_tier(X,leading)]).

rule(hasCapability1, hasCapability(_X, Att), [neg(requireHighResource(Att))]).
rule(hasCapability2, hasCapability(X, Att), [requireHighResource(Att), hasResources(X)]).
rule(noCapability, neg(hasCapability(X, Att)), [requireHighResource(Att), neg(hasResources(X))]).

rule(ecMotive(C,T), hasMotive(C, Att), [hasEconomicMotive(C, T), industry(T),
  target(T, Att), specificTarget(Att)]).
rule(pMotive,       hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att), specificTarget(Att)]).
rule(pMotive(C,T),  hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).
rule(conflict,      hasMotive(X, Att), [attackYear(Att, Y), target(T, Att),
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
  writeToFiles('op.pl', hasMotive(X,A), hasMotive(X,A,D1), 'op_'),
  writeToFiles('op.pl', governmentLinked(P,X), governmentLinked(P,X,D2), 'op_').

goal_all(A, X, P, D0, D1, D2) :-
  initFile('op.pl'), case(A),
  writeToFilesAll('op.pl', hasCapability(X,A), hasCapability(X,A,D0), 'op_'),
  writeToFilesAll('op.pl', hasMotive(X,A), hasMotive(X,A,D1), 'op_'),
  writeToFilesAll('op.pl', governmentLinked(P,X), governmentLinked(P,X,D2), 'op_').

hasCapability(X,A,D0) :- visual_prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- visual_prove([hasMotive(X,A)], D1).
governmentLinked(P,X,D2) :- visual_prove([governmentLinked(P,X)], D2).
