

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

%% nbassili - moved first with cut
resolveone(Goal, Acc, Acc) :-
        predicate_property(Goal, built_in), !,
        Goal.


resolveone(Head, Acc, Resolvent) :-
	%% nbassili
	
	( (rule(Sig, Head, Body),

	   resolve(Body, [Sig|Acc], Resolvent)) *-> 
	   
	   	true ; 
	   	
	   	(once( with_abduction(Head) ),
		 abducible(Head, []),
		 Resolvent = [ass(Head)|Acc]
		)
    	).

/*

resolveone(Head, Acc, Resolvent) :-
	%% nbassili
	%not(abducible(Head, [])), !,
	
	rule(Sig, Head, Body),

	resolve(Body, [Sig|Acc], Resolvent).
	
	%% nbassili - cuts abducible if the defeasible fact is proven by a rule. 
	%(abducible(Head, []) -> !; true).
resolveone(Head, Acc, [ass(Head)|Acc]) :-
	not( (rule(Sig, Head, Body), resolve(Body, [Sig|Acc], _Resolvent)) ),

	%with_abduction(Head),
	%% nbassili - when multiple policies exists this fact is loaded many times!
	once( with_abduction(Head) ),
	abducible(Head, []).

*/


