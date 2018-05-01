/* -------------------------------------------------------------
 * Gorgias -- Extensible Argumentation Framework with Abduction.
 * -------------------------------------------------------------
 * Neophytos Demetriou (nkd@cs.ucy.ac.cy)
 * Antonis Kakas (antonis@cs.ucy.ac.cy)
 */ 


:- compile('prolog_detect').

:- prolog(sicstus) -> compile(sicstus);true.

:- compile('resolver').

:- multifile complement/2, rule/3, abducible/2.

:- dynamic rule/3, abducible/2, with_abduction/1.

:- assert(with_abduction(_)).

:- compile('visualization').  %% nbassili

/*

exception_rule(Sig, Head, Body) :-
	assert(rule(Sig, Head, Body)),
	assert(rule(pr(Sig, OtherSig), prefer(Sig, OtherSig), []) :- conflict(Sig, OtherSig)).

*/


/* Check consistency in an argument */
isconsistent(Argument) :-
	isconsistent(Argument, Argument).

/* Check consistency between two arguments */
isconsistent(Arg1, Arg2) :-
	findall(Sig2, (member(Sig1, Arg1), conflict(Sig1, Sig2), member(Sig2, Arg2)), []).

conflict(ass(L), ass(NL)) :-
	complement(L,NL).
conflict(Sig1, Sig2) :-
	rule(Sig1, Head1, _),
	rule(Sig2, Head2, _),
	complement(Head1, Head2).


% The following predicate *only* denotes that the literals are in conflict. For
% example, the complement of prefer(Sig1,Sig2) is neg(prefer(Sig1,Sig2)).

complement(prefer(Sig1, Sig2), prefer(Sig2, Sig1)):- !.
complement(neg(L), L):- !.
complement(L, neg(L)).


my_findall(Var,Goal,Bag) :-
	bagof(Var,Goal,Bag),
	!.
my_findall(_,_,[]).

%%%%%

prove(Query, Delta) :-
	resolve(Query, Delta0),             % resolve using "vanilla" interpreter
	isconsistent(Delta0),
	extend(Delta0, [], Delta).


extend([], DeltaAcc, DeltaAcc).
extend(Delta0, DeltaAcc, Delta) :-
	isconsistent(Delta0),
	findall(AttackNode, (attacks(_, 'A', Delta0, AttackNode)), AttackNodes),
	union(Delta0, DeltaAcc, NewDeltaAcc),
	counterattack(AttackNodes, NewDeltaAcc, Delta).


counterattack([], DeltaThis, DeltaThis).
counterattack([AttackNode|Rest], DeltaThis, Delta) :-
	counterattackone(AttackNode, DeltaThis, NewDeltaThis),
	counterattack(Rest, NewDeltaThis, Delta).


counterattackone([], DeltaThis, DeltaThis).
counterattackone(AttackNode, DeltaThis, Delta) :-
	%write('Attack:'), writeln(AttackNode),
	findall(DefenceNode, (attacks(_, 'D', AttackNode, DefenceNode), isconsistent(DeltaThis, DefenceNode)), DefenceNodes),
	%length(DefenceNodes,L),
	%(L > 1 -> (write('DefenceNodes:'), writeln(DefenceNodes));true),
	member(DefenceNode, DefenceNodes),
	%write('Defence:'), writeln(DefenceNode),
	counterattackoneaux(DefenceNode, DeltaThis, Delta).




/* Check if we have already "seen" DefenceNode. */
counterattackoneaux(DefenceNode, DeltaThis, DeltaThis) :- 
	intersection(DefenceNode, DeltaThis, DefenceNode),
	!.
/* Otherwise, argue in favor of DefenceNode. */
counterattackoneaux(DefenceNode, DeltaThis, Delta) :- 
	extend(DefenceNode, DeltaThis, Delta).



pretty([]).
pretty([X|Xs]) :-
	writeln(X),
	pretty(Xs).


gorgias__prove(Query) :-
	is_list(Query), !,
	prove(Query,_).

gorgias__prove(Query) :-
	prove([Query],_).

gorgias__prove_one(Query, Delta) :-
	is_list(Query), !,
	prove(Query,Delta).

gorgias__prove(Query,Delta) :-
	prove([Query],Delta).

