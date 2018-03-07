:- compile('utils.pl').
:- compile('tech.pl').
:- multifile rule/3.

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

rule(noCapability, neg(hasCapability(_, _)), []).
rule(hasCapability1, hasCapability(X, Att), [neg(requireHighResource(Att))]).
rule(hasCapability2, hasCapability(X, Att), [requireHighResource(Att), hasResources(X)]).
rule(ecMotive(C,T), hasMotive(C, Att), [hasEconomicMotive(C, T), industry(T), target(T, Att)]).
rule(pMotive, hasMotive(C, Att), [hasPoliticalMotive(C, T), target(T, Att)]).
rule(pMotive(C,T), hasPoliticalMotive(C, T), [imposedSanctions(T, C)]).
rule(social1(P,C), governmentLinked(P,C), [geolocatedInGovFacility(P,C)]).
rule(social2(P,C), governmentLinked(P,C), [publicCommentsRelatedToGov(P,C)]).

rule(sabotage(R), hasMotive(C, Att), [target(T, Att), attackYear(Att, Y), recentNewsInYear(R, T, Y), countriesAgainstTargetForReason(C, T, R)]).

% prefer
rule(nafCap, prefer(hasCapability1, noCapability), []).
rule(nafCap, prefer(hasCapability2, noCapability), []).

% evidences
%% rule(f6, target(iran,attack), []).
%% rule(f8, recentNewsInYear(nuclearProgram,iran, 2010), []).
%% rule(f9, countriesAgainstTargetForReason([usa, israel], iran, nuclearProgram), []).
%% rule(f10, attackYear(attack, 2010), []).


% output:
%% hasCapability(X,A)
%% hasMotive(X,A)
%% governmentLinked(P,X)
writeToFile(X, N) :-
  open('op.pl',append, Stream),
  write(Stream, 'rule(t'), write(Stream, N), write(Stream, ', '), write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

hasCapability(X,A,D0) :- prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- prove([hasMotive(X,A)], D1).
governmentLinked(P,X,D2) :- prove([governmentLinked(P,X)], D2).

goal(A, M, X, D0, D1, D2) :-
  (hasCapability(X,A,D0), writeToFile(hasCapability(X,A), 0); \+ hasCapability(X,A,D0), write(neg(hasCapability(X,A)))), nl,
  (hasMotive(X,A,D1), writeToFile(hasMotive(X,A), 1); \+ hasMotive(X,A,D1), write(neg(hasMotive(X,A)))), nl,
  (governmentLinked(P,X,D2), writeToFile(governmentLinked(P,X), 2); \+ governmentLinked(P,X,D2), write(neg(governmentLinked(P,X)))), nl.
