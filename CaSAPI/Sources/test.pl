myRule(not(isCulprit(c)), []).
myRule(isCulprit(c), [ipFrom(c)]).
myRule(not(isCulprit(c)), [ipFrom(c), ipSpoofed]).

myAss([ipFrom(uk), ipSpoofed]).

toBeProved([not(isCulprit(uk))]).

contrary(not(X), X) :- !.
contrary(X, not(X)).
