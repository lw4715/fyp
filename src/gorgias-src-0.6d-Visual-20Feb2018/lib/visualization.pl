/* ----------------------------------------------
 * Visualization of Gorgias arguments           
 * ----------------------------------------------
 * Nick Bassiliades (nbassili@csd.auth.gr)   
 * Antonis Kakas (antonis@cs.ucy.ac.cy)
 *
 */


%% nbassili
%% returns the Delta and pretty prints the tree (backtrackable)
visual_prove(Goal,Delta) :-
	visual_prove(Goal,Delta,[]).
/*
visual_prove(Goal,Delta,Options) :-
	member(failed(true),Options), !,
	prove_with_tree(Goal,Delta,Tree),
	( Delta == 'FAIL' ->
		(write('---------------'), nl,
		 write('FAILED ARGUMENT'), nl,
		 write('---------------'), nl,
		 pretty_print(Tree), nl,
		 fail
		);
		(write('--------------------'), nl,
		 write('SUCCESSFULL ARGUMENT'), nl,
		 write('--------------------'), nl,
		 pretty_print(Tree), nl
		)
	).*/
visual_prove(Goal,Delta,Options) :-
	member(failed(true),Options), !,
	prove_with_tree(Goal,Delta,Tree),
	nl, pretty_print(Tree), nl.
visual_prove(Goal,Delta,_Options) :-
	prove_with_tree(Goal,Delta,Tree),
	nl,
	( Delta == 'FAIL' ->
		 fail;
		 pretty_print(Tree)
	), 
	nl.

visual_prove_string(Goal,String) :-
	visual_prove_string(Goal,String,[]).


visual_prove_string(Goal,AllString,Options) :-
	member(failed(true),Options), !,
	findall(String,
		(prove_with_tree(Goal,Delta,Tree),
		 pretty_string(Tree,MString),
		 ( Delta == 'FAIL' ->
			LString='---------------\nFAILED ARGUMENT\n---------------\n';
			(string_arg_label(Delta,DeltaS),
			atomic_list_concat(['--------------------\nSUCCESSFULL ARGUMENT\n','Delta=',DeltaS,'\n','--------------------\n'],LString))),
		 atom_concat(LString,MString,String)),
		ListOfStrings),
	atomic_list_concat(ListOfStrings,'\n',AllString).
visual_prove_string(Goal,AllString,_Options) :-
	findall(String,
		(prove_with_tree(Goal,Delta,Tree),
		 pretty_string(Tree,MString),
		 ( Delta == 'FAIL' ->
			fail;
			(string_arg_label(Delta,DeltaS),
			atomic_list_concat(['--------------------\n','Delta=',DeltaS,'\n','--------------------\n'],LString))),
		 atom_concat(LString,MString,String)),
		ListOfStrings),
	atomic_list_concat(ListOfStrings,'\n',AllString).


%% nbassili
%% Pretty prints all alternative Deltas and corresponding trees
visual_prove_all(Goal) :-
	visual_prove_all(Goal,[]).

visual_prove_all(Goal,Options) :-
	member(failed(true),Options), !,
	findall(Delta-Tree,prove_with_tree(Goal,Delta,Tree),List),
	print_list(List).
visual_prove_all(Goal,_Options) :-
	findall(Delta-Tree,(prove_with_tree(Goal,Delta,Tree),Delta \== 'FAIL'),List),
	print_list(List).

prove_with_tree(Query, Delta, Tree) :-
	prove_wTree(Query, Delta2, Tree),
	delete(Delta2,nott(_),Delta1),
	(contains_var('{NO DEFENSE}', Tree) ->
	 Delta = 'FAIL';
	 Delta = Delta1).

%% nbassili
%% Returns also the decision tree
prove_wTree(Query, Delta, Delta0-Tree) :-
	resolve(Query, Delta0),             % resolve using "vanilla" interpreter
	isconsistent(Delta0),
	extend_wTree(Delta0, [], Delta, Tree).

%% nbassili
%% Returns also the decision tree
extend_wTree([], DeltaAcc, DeltaAcc, []).
extend_wTree(Delta0, DeltaAcc, Delta, Tree) :-
	isconsistent(Delta0),
	findall(AttackNode, (attacks(_, 'A', Delta0, AttackNode)), AttackNodes),
	union(Delta0, DeltaAcc, NewDeltaAcc),
	counterattack_wTree(AttackNodes, NewDeltaAcc, Delta, Tree).
	%((DeltaAcc \= [], Tree = []) -> ReturnTree = []; ReturnTree = NewDeltaAcc-Tree),
	%write('ReturnTree : '), writeln(ReturnTree), nl.

%% nbassili
%% Returns also the decision tree
counterattack_wTree([], DeltaThis, DeltaThis,[]).
counterattack_wTree([AttackNode|Rest], DeltaThis, Delta, [AttackNode-[IncTree]|Tree]) :-
	%write('--------------------------------------'), nl,
	%write('Attack:'), writeln(AttackNode),
	counterattackone_wTree(AttackNode, DeltaThis, NewDeltaThis, IncTree),
	%write('IncTree:'), writeln(IncTree),
	counterattack_wTree(Rest, NewDeltaThis, Delta, Tree).


%% nbassili
%% Returns also the decision tree
counterattackone_wTree([], DeltaThis, DeltaThis, []).
counterattackone_wTree(AttackNode, DeltaThis, DeltaThis, '{NO DEFENSE}'-[]) :-
	findall(DefenceNode, (attacks(_, 'D', AttackNode, DefenceNode), isconsistent(DeltaThis, DefenceNode)), []), !.
counterattackone_wTree(AttackNode, DeltaThis, Delta, DefenceNode-Tree) :-
	findall(DefenceNode, (attacks(_, 'D', AttackNode, DefenceNode), isconsistent(DeltaThis, DefenceNode)), DefenceNodes),
	%% nbassili - DefenceNodes contains duplicates - probably need to check attacks/4
	%% actually when the FIX ME problem in attacks/4 was fixed, then there is no need for removing duplicates
	%% remove_duplicates(DefenceNodes1,DefenceNodes),
	member(DefenceNode, DefenceNodes), 
	%(DefenceNodes\==[_] -> (write('DefenceNodes:'), writeln(DefenceNodes));true),
	%write('Defence:'), writeln(DefenceNode),
	counterattackoneaux_wTree(DefenceNode, DeltaThis, Delta, Tree).


%% nbassili
%% Returns also the decision tree
/* Check if we have already "seen" DefenceNode. */
counterattackoneaux_wTree(DefenceNode, DeltaThis, DeltaThis,[]) :- 
	intersection(DefenceNode, DeltaThis, DefenceNode), 
	!.
/* Otherwise, argue in favor of DefenceNode. */
counterattackoneaux_wTree(DefenceNode, DeltaThis, Delta, Tree) :- 
	extend_wTree(DefenceNode, DeltaThis, Delta, Tree).



%% Pretty prints a list with alternative deltas and trees
print_list([]).
print_list([Delta-Tree|Rest]) :-
	write('Delta: '), 
	write_arg_label(Delta), nl,
	writeln('Tree: '), 
	pretty_print(Tree),
	nl,
	print_list(Rest).


%% nbassili
%% Pretty prints the decision tree

pretty_print( Tree ) :-
    Level = 0, 
    pp_tree( [], Level, Tree ).

pp_tree( _,_, [] ) :- !.
pp_tree( Order, Level, Label-[] ) :- !, % Print a leaf.
    print_label( Order, Level, Level, Label ).
pp_tree( Order, Level, Label-[[]] ) :- !, % Print a leaf.
    print_label( Order, Level, Level, Label ).
pp_tree( Order, Level, Label-SubTrees ) :- !,
    SubTrees = [_|_], 
    print_label( Order, Level, Level, Label ), 
    NewLevel is Level + 1, 
    pp_subtrees( Order, NewLevel, SubTrees ).

pp_subtrees( _, _, [] ).
pp_subtrees( Order, Level, [Last] ) :- !,
	append(Order,[last],NewOrder),
	pp_tree( NewOrder, Level, Last ).
pp_subtrees( Order, Level, [Next|Rest] ) :- !,
	append(Order,[norm],NewOrder),
    	pp_tree( NewOrder, Level, Next ), 
    	pp_subtrees( Order, Level, Rest ).

% print_label( Order, TempLevel, OrigLevel, Label )
print_label( [], 0, _, Label ) :- !,
	write_arg_label( Label ), 
	write('  {DEFENSE}'),  %% needs to be extended to all odd levels
	nl.
print_label( [_], 1, OrigLevel, Label ) :- !,
	write('|___'),
	write_arg_label( Label ), 
	( (0 =:= OrigLevel mod 2, Label\== '{NO DEFENSE}') -> 
		write('  {DEFENSE}');
		true
	),
	nl.
print_label( [Order|Rest], Level, OrigLevel, Label ) :- !,
	draw_lines(Order),
	NextLevel is Level - 1,
	print_label(Rest, NextLevel, OrigLevel, Label).

draw_lines(norm) :- 
	write('|   ').
draw_lines(last) :- 
	write('    ').

write_arg_label(L) :-
	is_list(L), !,
	write('['),
	write_arg_label_aux(L),
	write(']').
write_arg_label(S) :- 
	write(S).

write_arg_label_aux([]).
write_arg_label_aux([H]) :- !,
	write(H).
write_arg_label_aux([nott(_)|T]) :- !,
	write_arg_label_aux(T).
write_arg_label_aux([H|T]) :- !,
	write(H), write(', '),
	write_arg_label_aux(T).


pretty_string(Tree, String) :-
    Level = 0, 
    ps_tree( [], Level, Tree, String ).

ps_tree( _,_, [], '' ) :- !.
ps_tree( Order, Level, Label-[], String) :- !, % Print a leaf.
    string_label( Order, Level, Level, Label, String ).
ps_tree( Order, Level, Label-[[]], String ) :- !, % Print a leaf.
    string_label( Order, Level, Level, Label, String ).
ps_tree( Order, Level, Label-SubTrees, String ) :- !,
    SubTrees = [_|_], 
    string_label( Order, Level, Level, Label, S1 ), 
    NewLevel is Level + 1, 
    ps_subtrees( Order, NewLevel, SubTrees, S2 ),
    atomic_concat(S1,S2,String).

ps_subtrees( _, _, [], '' ).
ps_subtrees( Order, Level, [Last], String ) :- !,
	append(Order,[last],NewOrder),
	ps_tree( NewOrder, Level, Last, String ).
ps_subtrees( Order, Level, [Next|Rest], String ) :- !,
	append(Order,[norm],NewOrder),
    	ps_tree( NewOrder, Level, Next, S1 ), 
    	ps_subtrees( Order, Level, Rest, S2 ),
    	atomic_concat(S1,S2,String).

% string_label( Order, TempLevel, OrigLevel, Label )
string_label( [], 0, _, Label, String ) :- !,
	string_arg_label( Label, String1 ),
	atom_concat(String1,"  {DEFENSE}\n",String).
string_label( [_], 1, OrigLevel, Label, String ) :- !,
	string_arg_label( Label, String1 ), 
	( (0 =:= OrigLevel mod 2, Label\== '{NO DEFENSE}') -> 
		DfnsStr = '  {DEFENSE}';
		DfnsStr = ''
	),
	atomic_list_concat(['|___',String1,DfnsStr,"\n"], String).
string_label( [Order|Rest], Level, OrigLevel, Label, String ) :- !,
	string_lines(Order,Str1),
	NextLevel is Level - 1,
	string_label(Rest, NextLevel, OrigLevel, Label, Str2),
	atomic_concat(Str1,Str2,String).

string_lines(norm,'|   ').
string_lines(last,'    ').

string_arg_label(L,String) :-
	is_list(L), !,
	string_arg_label_aux(L,S),
	atomic_list_concat(['[',S,']'],String).
string_arg_label(S,S).

string_arg_label_aux([],'').
string_arg_label_aux([H],H1) :- !,
	term_to_atom(H,H1).
string_arg_label_aux([nott(_)|T],S) :- !,
	string_arg_label_aux(T,S).
string_arg_label_aux([H|T],S) :- !,
	string_arg_label_aux(T,S1),
	term_to_atom(H,H1),
	atomic_list_concat([H1,', ',S1],S).

remove_duplicates([],[]).
remove_duplicates([H|T1],T2) :-
	member(H,T1), !,
	remove_duplicates(T1,T2).
remove_duplicates([H|T1],[H|T2]) :-
	remove_duplicates(T1,T2).
	