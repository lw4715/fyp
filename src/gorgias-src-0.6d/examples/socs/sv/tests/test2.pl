:- compile('../sv').

:- multifile action/4, goal/3, failed/1, abducible/2, rule/3, complement/2.


computee :: {

     super(computee_basic) &

     attributes([timepoint(1)]) &

     history(0,step('INIT',[]))

}.

title('TEST 2').
comment('Goal Decision').

rule(gd(G), gd(G), []) :-
	isgoal(G),
	\+ goal(G,_,_).       %% not already in the state, G is of the form goal(G,PG,T)


complement(gd(X),gd(Y)) :-
	isgoal(X),
	isgoal(Y),
        X \= Y.


isgoal(hotel_payment).
isgoal(mkloan).


abducible(out_of_cash, []).
abducible(neg(out_of_cash), []).

rule(prefer(gd(G1),gd(G2)), prefer(gd(G1),gd(G2)), WHEN) :-
	G1 = mkloan,
	G2 = hotel_payment,
	WHEN = [out_of_credit].

rule(prefer(gd(G1),gd(G2)), prefer(gd(G1),gd(G2)), WHEN) :-
	G1 = hotel_payment,
	G2 = mkloan,
	WHEN = [neg(out_of_cash)].

/********
rule(prefer(PREF1,PREF2), prefer(PREF1,PREF2), WHEN) :-
	G1 = mkloan,
	G2 = hotel_payment,
	PREF1 = prefer(gd(G1),gd(G2)),
	PREF2 = prefer(gd(G2),gd(G1)),
	WHEN = [out_of_credit].
**********/


rule(f1, out_of_credit, []).

:- start.

:- computee::do(step('GI', [])).
