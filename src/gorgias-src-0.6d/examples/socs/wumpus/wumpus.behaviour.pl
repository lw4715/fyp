
%%% The behaviour component of the cycle theory


%% Punctual

rule(h_p(tr('AE',As),tr(Z,_)),prefer(tr('AE',As),tr(Z,_)),[h_u_AS(As), As \= []]) :-
	self(profile,punctual),
	transition(Z,_),
	Z \= 'AE'.
rule(h_p(tr('PI',Gs),tr(Z,_)),prefer(tr('PI',Gs),tr(Z,_)),[h_u_GS(Gs), Gs \= []]) :-
	self(profile,punctual),
	transition(Z,_),
	Z \= 'PI'.
rule(h_p(tr('AOI',Fs),tr(Z,_)),prefer(tr('AOI',Fs),tr(Z,_)),[h_u_FS(Fs), Fs \= []]) :-
	self(profile,punctual),
	transition(Z,_),
	Z \= 'AOI'.
rule(h_p(tr('PR',null),tr(Z,_)),prefer(tr('PR',null),tr(Z,_)),[fIxMe,nothing_urgent_or_to_be_sensed]) :-
	self(profile,punctual),
	transition(Z,_),
	Z \= 'PR'.

% Heuristic Selection Functions, currently only singletons, TODO: list of directives

rule(h_u_AS(A), h_u_AS(A), []) :- current(t(T)),todo(happens(Action,TimeOfAction)), A=happens(Action,TimeOfAction).


rule(h_u_FS(F), h_u_FS(F), []) :- todo(holds(F,T1)),current(t(T2)),T2=<T2.
%rule(h_u_GS(G), h_u_GS(holds(G,T)), []) :- todo(add(p_goal(G))),current(t(T)).
%rule(h_u_GS(G), h_u_GS(holds(G,T)), []) :- todo(add(n_goal(G))),current(t(T)).

%rule(nothing, nothing_urgent_or_to_be_sensed, []) :- current(t(T)),\+ todo(happens(A,T)), \+ todo(holds(F,T)).


%% Careful

rule(h_p(tr('PR',null),tr(Z,_)),prefer(tr('PR',null),tr(Z,_)),[timeout]) :-
	self(profile,careful),
	transition(Z,_),
	Z \= 'PR'.

rule(timeout, timeout, []) :-
	current(t(T2)),
	todo(happens(A,T1)),
	T2 > T1.


%% Focused

rule(h_p(tr('AE',As),tr(Z,_)),prefer(tr('AE',As),tr(Z,_)),[h_sp_AS(As), As \= []]) :-
	self(profile,focused),
	transition(Z,_),
	Z \= 'AE'.

rule(h_p(tr('PI',Gs),tr(Z,_)),prefer(tr('PI',Gs),tr(Z,_)),[h_sp_GS(Gs), Gs \= []]) :-
	self(profile,focused),
	transition(Z,_),
	Z \= 'PI'.

%% Cautious

rule(h_p(tr('AE',As),tr(Z,_)),prefer(tr('AE',As),tr(Z,_)),[h_pre_AS(As), As \= []]) :-
	self(profile,cautious),
	transition(Z,_),
	Z \= 'AE'.

rule(h_p(tr('AOI',Fs),tr(Z,_)),prefer(tr('SI',Fs),tr(Z,_)),[h_pre_FS(Fs), Fs \= []]) :-
	self(profile,cautious),
	transition(Z,_),
	Z \= 'AOI'.



%% Impatient

rule(h_p(tr(Z,_),tr('AE',As)),prefer(tr(Z,_),tr('AE',As)),[h_fail_AS(As), As \= []]) :-
	self(profile,impatient),
	transition(Z,_),
	Z='PR'.

rule(h_fail_AS(happens(A,T1)), h_fail_AS(happens(A,T1)), [g_check(failed(A,_,T0))]) :- current(t(T1)), T0 is T1 - 1.


%% Other

/*
rule(h_p(tr('GI',C),tr(Z,_)), prefer(tr('GI',C),tr(Z,_)), []) :-
	my_findall(What,todo(What),[dummy]),
	transition(Z,_),
	Z \= 'GI'.
rule(h_p(tr('AOI',F),tr('AE',A)), prefer(tr('AOI',F),tr('AE',A)), []) :-
	clause(initiates(A,_),Body),
	clause2list(Body,BodyList),
	member(precond(F),BodyList).
	
*/

%%%%%%

/*
rule(h_pre_AS(A), h_pre_AS(A), []) :- 
	clause(initiates(A,_),Body),
	clause2list(Body,BodyList),
	current(t(T)),
	my_findall(holds(C,T),member(precond(C),BodyList),Preconds),
	forall(member(Precond,Preconds), rule(_, Precond, [])).
*/

/*
complement(h_u_AS(A1),h_u_AS(A2)) :-
	todo(happens(A1,_)),
	todo(happens(A2,_)),
	A1 \= A2.


prefer(h_p(h_u_AS(A1),h_u_AS(A2)), prefer(h_u_AS(A1),h_u_AS(A2)), []) :-
	todo(happens(A1,T1)),
	todo(happens(A2,T2)),
	A1 \= A2,
	T1 =< T2.
*/
