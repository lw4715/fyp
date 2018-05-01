:- dynamic allowed_resolution/1.

allowed_resolution(['RES','NAF','ABD','BUILT_IN']).

set_back_to_default_allowed_resolution :-
	retractall(allowed_resolution(_)),
	assert(allowed_resolution(['RES','NAF','ABD','BUILT_IN'])).

%%%

g_resolve(Goals,Resolvent) :-
	resolve_with(['RES','NAF','ABD','BUILT_IN'], Goals, [], Resolvent).

g_resolve_check(Goals, Resolvent) :-
	resolve_with(['RES','NAF','BUILT_IN'], Goals, [], Resolvent).

%%% Internal Stuff -- Note that allowed_resolution/1 is dynamic.

resolve(Goals, Resolvent) :-
    allowed_resolution(Allowed),
    resolve_with(Allowed, Goals, [], Resolvent).

resolve_with(_, [], Acc, Acc) :- !.

resolve_with(Allowed, [Goal|Rest], Acc, Resolvent) :-
        resolveone(Allowed, Goal, Acc, GoalResolvent),
        resolve_with(Allowed, Rest, GoalResolvent, RestResolvent),
        union(GoalResolvent, RestResolvent, Resolvent).


resolveone(Goal, Resolvent) :-
	allowed_resolution(Allowed),
	resolveone(Allowed, Goal, [], Resolvent).


/* FIX ME: Temporarily ignore self-reference. Improve self-reference handling
           in two cases: (a) loops (b) reuse of rules 

resolveone(Head, Acc, Acc) :-
	rule(Sig, Head, _),
	member(Sig, Acc), !.
*/


resolveone(Allowed, g_check(Goal), _, _) :-
	
	member('RES', Allowed), !,
	    
	prove_with(['RES','NAF','BUILT_IN'], [Goal], _).

resolveone(Allowed, Goal, Acc, Resolvent) :-
	
	member('RES', Allowed),

	rule(Label, Goal, Body),

	resolve_with(Allowed, Body, [Label|Acc], Resolvent).



resolveone(Allowed, Goal, Acc, Acc) :-
	
	member('BUILT_IN', Allowed),

        predicate_property(Goal, built_in),
        Goal.



resolveone(Allowed, Goal, Acc, Resolvent) :-

	member('ABD', Allowed),

	abducible(Goal, Conditions),

	resolve_with(Allowed, Conditions, [ass(Goal)|Acc],Resolvent).


resolveone(Allowed, Goal, Acc, [naf_ass(Literal)|Acc]) :-

	member('NAF', Allowed),

	Goal = naf(Literal).



