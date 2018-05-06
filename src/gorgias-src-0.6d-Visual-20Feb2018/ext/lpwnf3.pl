% attacks(?QH, ?LT, +Argument, ?CounterArgument)

attacks(QH, LT, Argument, CounterArgument) :-

	member(Culprit, Argument),

	attacks0(QH, LT, Culprit, Argument, CounterArgument).

attacks0('NOT', _, nott(SigHP),A, CA) :-

	rule(SigHOP, prefer(CC,SigHP), BodyHOP),

	member(CC, A), !,

	resolve(BodyHOP, ResolventHOP),

	union([nott(SigHOP)],[SigHOP|ResolventHOP],CA).


attacks0('NOT', _, nott(SigHP),_, CA) :-


	rule(SigHOP, prefer(CC,SigHP), BodyHOP),

	resolve(BodyHOP, ResolventHOP),

	rule(CC, _, BodyCC),

	resolve(BodyCC,ResolventCC),

	union([nott(SigHOP),CC|ResolventCC],[SigHOP|ResolventHOP],CA).


/*
 * not(prefer(Culprit,CC)) -- suspended  argument check, required for higher-order priorities
 *
 */
attacks0('DYN_GEQ', _, Culprit, _, CA) :-

	%% FIX ME: Add check so that Culprit is not a preference rule

	conflict(Culprit, CC),

	find_pref_rule(SigHP, prefer(CC, Culprit), BodyHP),

	resolve(BodyHP, ResolventHP),

	rule(CC, _, BodyCC),

	resolve(BodyCC, ResolventCC),

	union([nott(SigHP), CC|ResolventCC], [SigHP|ResolventHP], CA).



%%% For Abducibles


attacks0('ASS', 'D', ass(L), _, CA) :-

	complement(L, NL),

	abducible(NL, _),

	CA = [ass(NL)].


attacks0('GEN', _, ass(L), _, CA) :-

	complement(L, NL),

	rule(Sig, NL, Body),

	resolve(Body, Resolvent),

	CA = [Sig|Resolvent].

/*
attacks0('DYN_EQ', 'D', Culprit, A, CA) :-

	conflict(Culprit, CC),

	rule(CC, _, BodyCC),

	resolve(BodyCC, ResolventCC),

	findall(Label, (member(Label,A),rule(Label,prefer(Culprit,CC),_)), []),

	union([CC|ResolventCC], [ass(neg(prefer(Culprit,CC)))], CA).

*/

find_pref_rule(Rule, prefer(Rule1, Rule2), Body) :-
	rule(Rule, prefer(Rule1, Rule2), Body).
find_pref_rule(_Rule, prefer(Rule1, Rule2), []) :-
	nonvar(Rule1), nonvar(Rule2),
	rule(Rule1,_,_), Rule1 =.. [R1|Args], 
	rule(Rule2,_,_), Rule2 =.. [R2|Args], 
	ruleset(RS1, Rules1), member(R1, Rules1),
	ruleset(RS2, Rules2), member(R2, Rules2),
	ruleset_pref(RS1,RS2).

