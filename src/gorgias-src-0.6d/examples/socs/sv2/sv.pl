:- compile('../../../lib/gorgias2').
:- compile('../../../ext/lpwnf2').
:- compile('./lib/ct').


:- multifile rule/3, complement/2, self__history/2.

:- dynamic test__case_current/1.

:- multifile test__heading/1, test__comment/1, test__comment/2.

test__case_current(0).

start :-
	test__heading,
	self__pretty_state,
        writeln('-------------------------------------------------------------------------------'),
	self__profile_reset(punctual),
	test__current_profile,
	self__profile_reset(focused),
	test__current_profile,
	self__profile_reset(impatient),
	test__current_profile,
	self__profile_reset(careful),
	test__current_profile,
	self__profile_reset(cautious),
	test__current_profile,
	self__profile_reset,
        writeln('-------------------------------------------------------------------------------'),
	test__case_incr.

nonstop :-
	test__heading,
	self__pretty_state,
        writeln('-------------------------------------------------------------------------------'),
	self__next(Step),
	self__commit(Step),
        writeln('-------------------------------------------------------------------------------'),
	test__case_incr,
	continue.


continue :-
	check_inbox,
	writeln('Enter q to quit any other char to continue.'),
	read(X),
	(X='q' -> halt ; nonstop).


check_inbox :-
	test__case_current(N),
	(inbox(N,Obs) -> (self__commit(step('PO',Obs)), test__case_incr) ; true).

test__heading :-
	test__case_current(Screen),
	write('\n\n\n'),
	format('~`=t~79|~n',[]),
	format('~`*t SCREEN ~w ~`*t~79|~n', [Screen]),
	format('~`-t~79|~n',[]),
	test__comment(Comment),
	format('~w ~80t\n',[Comment]).


test__comment(Comment) :-
	test__case_current(N),
	test__comment(N, Comment).

test__case_incr :-
	test__case_current(N0),
	retractall(test__case_current(_)),
	N1 is N0 + 1,
	assert(test__case_current(N1)).

test__current_profile :-
	!,	
	findall(X, self__next(X), Xs).

print_all_next_transitions(_,[]).
print_all_next_transitions(Acc,[X|Xs]) :-
	\+ member(X, Acc), !,
	write('   --> Next Transition... '), 
	writeln(X),
	print_all_next_transitions([X|Acc], Xs).
print_all_next_transitions(Acc,[X|Xs]) :-
	print_all_next_transitions([X|Acc], Xs).



self__pretty_state :-
	format('\n~`vt STATE ~`vt~79|~n', []),
	findall(history(T,Step), self__history(T,Step), History),
	writeln(''),
	writeln('HISTORY'),
	writeln(''),
	pretty_history(History),
	findall(G, self__goal(G,_,_), Goals),
	writeln(''),
	writeln('GOALS'),
	writeln(''),
	pretty_all(Goals),
	findall(Op, self__action(Op,_,_,_), Actions),
	writeln(''),
	writeln('ACTIONS'),
	writeln(''),
	pretty_all(Actions),
	writeln(''),
	writeln('KB 0'),
	pretty_kb_0.

pretty_kb_0 :-
	forall(kb_0__observed(X,Y), (write('    -> '), writeln(obs(X,Y)))),
	forall(kb_0__observed(U,V,W), (write('    -> '), writeln(obs(U,V,W)))),
	forall(kb_0__executed(A),  (write('    -> '), writeln(executed(A)))).

pretty_all([]) :- writeln('   ---').
pretty_all([X|Xs]) :-
	write('   --> '),
	writeln(X),
	pretty_all(Xs).
	


pretty_history([]).
pretty_history([history(T,step(NAME,INPUT))| Rest]) :-
	write('   --> '),
	write(T), 
	write(': '), 
	writeln(step(NAME,INPUT)),
	pretty_history(Rest).

print_results(Capability, Results) :-
	writeln(Capability),
	print_results_aux([], Results).

print_results_aux(_, []).
print_results_aux(Acc, [result(R,Delta)|Rs]) :-
	\+ member(R,Acc), !,
	print_one_result(R,Delta),
	print_results_aux([R|Acc],Rs).
print_results_aux(Acc, [_|Rs]) :-
	print_results_aux(Acc,Rs).


print_one_result(R,Delta) :-
	write('   --> '),
	write(R),
	write(' if '),
	findall(Assumption, member(ass(Assumption),Delta), Assumptions),
	print_assumptions([], Assumptions),
	writeln('').


print_assumptions(_, []).
print_assumptions(Acc, [A|As]) :-
	\+ member(A,As), !,
	write(A),
	write(' '),
	print_assumptions([A|Acc],As).

print_assumptions(Acc, [_|As]) :-
	print_assumptions(Acc, As).
