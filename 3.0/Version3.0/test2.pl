myRule(p,[a]).
myRule(not(a),[b]).
myRule(not(a),[r]).
myRule(r,[b]).
myRule(not(b),[]).

myAss([a,b]).

toBeProved([p]).

contrary(not(X),X) :- !.
contrary(X,not(X)).

