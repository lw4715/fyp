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

% evidences
%% rule(f6, target(iran,attack), []).
%% rule(f8, recentNewsInYear(nuclearProgram,iran, 2010), []).
%% rule(f9, countriesAgainstTargetForReason([usa, israel], iran, nuclearProgram), []).
%% rule(f10, attackYear(attack, 2010), []).


% output:
%% hasCapability(X,A)
%% hasMotive(X,A)
%% governmentLinked(P,X)
writeToFile(X) :-
  open('op.pl',append, Stream),
  write(Stream, 'rule(op_'), write(Stream, X), write(Stream, ', '),
  write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

goal(A, X, D0, D1, D2) :-
  initFile('op.pl'), case(A),
  (hasCapability(X,A,D0), writeToFile(hasCapability(X,A));
    \+ (hasCapability(X,A,D0)), writeToFile(neg(hasCapability(X,A)))), nl,
  (hasMotive(X,A,D1), writeToFile(hasMotive(X,A));
    \+ (hasMotive(X,A,D1)), writeToFile(neg(hasMotive(X,A)))), nl,
	(governmentLinked(P,X,D2), writeToFile(governmentLinked(P,X));
    \+ (governmentLinked(P,X,D2))).

hasCapability(X,A,D0) :- prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- prove([hasMotive(X,A)], D1).
governmentLinked(P,X,D2) :- prove([governmentLinked(P,X)], D2).
