:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').

rule(f1, bird(tweety), []).
rule(f2, penguin(tweety), []).

rule(r1(X), fly(X), [bird(X)]).
rule(r2(X), neg(fly(X)), [penguin(X)]).

rule(r3(X), prefer(r2(X), r1(X)), []).



start :-
	writeln('======================================================'),
	writeln('The Tweety Problem'),
	writeln('======================================================'),
	test1,
	writeln('------------------------------------------------------'),
	test2.

test1 :-
	Query = [fly(tweety)],
	writeln('Test 1'),
	writeln(''),
	writeln('  Query:'),
	pretty(Query),
	prove(Query,Delta),
	writeln('  Delta:'),
	pretty(Delta).

test1.

test2 :-
	Query = [neg(fly(tweety))],
	writeln('Test 2'),
	writeln(''),
	writeln('  Query:'),
	pretty(Query),
	prove(Query,Delta),
	writeln('  Delta:'),
	pretty(Delta).
