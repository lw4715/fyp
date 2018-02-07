:- compile('../../../lib/gorgias2').
:- compile('../../../ext/lpwnf2').
:- compile('./lib/computee').
:- compile('./lib/ct').

%%:- compile('./kb/gd').
%%:- compile('./kb/plan').
%%:- compile('./kb/tr').
%%:- compile('./kb/react').

:- multifile rule/3, complement/2.


start :-
	title(Title),
	comment(Comment),
        writeln('==============================================================================='),
        writeln(Title),
        writeln('-------------------------------------------------------------------------------'),
	writeln(Comment),
        writeln('==============================================================================='),
        pretty_state,
	reset_profile,
	computee::assert(profile('PUNCTUAL')),
	test_current_profile,
	reset_profile,
	computee::assert(profile('FOCUSED')),
	test_current_profile,
	reset_profile,
	computee::assert(profile('IMPATIENT')),
	test_current_profile,
	reset_profile,
	computee::assert(profile('CAREFUL')),
	test_current_profile,
	reset_profile,
	computee::assert(profile('CAUTIOUS')),
	test_current_profile,
	reset_profile,
        writeln('-------------------------------------------------------------------------------').

test_current_profile :-
	findall(Profile, computee::profile(Profile), Profiles),
	!,
	write('PROFILE = '),
	writeln(Profiles),
	writeln(''),
	findall(X, computee::next(X), Xs),
	print_all_next_transitions([],Xs).

print_all_next_transitions(_,[]).
print_all_next_transitions(Acc,[X|Xs]) :-
	\+ member(X, Acc), !,
	write('   --> Next Transition... '), 
	writeln(X),
	print_all_next_transitions([X|Acc], Xs).
print_all_next_transitions(Acc,[X|Xs]) :-
	print_all_next_transitions([X|Acc], Xs).


reset_profile :-
	writeln(''),
	computee::retractall(profile(_)).



pretty_state :-
	findall(history(T,Step), computee::history(T,Step), History),
	writeln(''),
	writeln('HISTORY'),
	writeln(''),
	pretty_history(History),
	findall(G, goal(G,_,_), Goals),
	writeln(''),
	writeln('GOALS'),
	writeln(''),
	pretty_all(Goals),
	findall(Op, action(Op,_,_,_), Actions),
	writeln(''),
	writeln('ACTIONS'),
	writeln(''),
	pretty_all(Actions).

pretty_all([]).
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
