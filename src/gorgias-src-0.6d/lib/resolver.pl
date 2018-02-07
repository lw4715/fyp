

resolve(Goals, Resolvent) :-
    resolve(Goals, [], Resolvent).

resolve([], Acc, Acc) :- !.

resolve([Goal|Rest], Acc, Resolvent) :-
        resolveone(Goal, Acc, GoalResolvent),
        resolve(Rest, GoalResolvent, RestResolvent),
        union(GoalResolvent, RestResolvent, Resolvent).


resolveone(Goal, Resolvent) :-
	resolveone(Goal, [], Resolvent).


/* FIX ME: Temporarily ignore self-reference. Improve self-reference handling
           in two cases: (a) loops (b) reuse of rules 

resolveone(Head, Acc, Acc) :-
	rule(Sig, Head, _),
	member(Sig, Acc), !.
*/


resolveone(Head, Acc, Resolvent) :-
	
	rule(Sig, Head, Body),

	resolve(Body, [Sig|Acc], Resolvent).

resolveone(Goal, Acc, Acc) :-
        predicate_property(Goal, built_in),
        Goal.


resolveone(Head, Acc, [ass(Head)|Acc]) :-
	with_abduction(Head),
	abducible(Head, []).



