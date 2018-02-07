% Logic Programming example of an Odd-Loop %

myRule(p,[not(q)]).
myRule(q,[not(r)]).
myRule(r,[not(s)]).
myRule(s,[not(q)]).

myAss([not(p),not(q),not(r),not(s)]).   

toBeProved([p]).

contrary(not(X),X) :- !.
contrary(X,not(X)).
