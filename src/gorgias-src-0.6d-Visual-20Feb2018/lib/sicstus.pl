
:- use_module(library(lists)).

:- use_module(library(ordsets)).

union(Set1, Set2, Result) :- ord_union(Set1,Set2,Result).

intersection(Set1, Set2, Result) :- ord_intersection(Set1, Set2, Result).

difference(Set1, Set2, Result) :- ord_subtract(Set1, Set2, Result).

forall(A, B) :-
        \+((
            A,
            \+B
            )).


writeln(X) :-
	write(X),
	write('\n').
