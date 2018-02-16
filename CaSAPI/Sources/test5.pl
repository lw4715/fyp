myRule(p,[b]).
myRule(p,[a]).

myAss([a,b]).

toBeProved([p]).

contrary(not(X),X) :- !.
contrary(X,not(X)).
