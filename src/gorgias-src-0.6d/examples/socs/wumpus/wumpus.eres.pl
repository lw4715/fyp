
:- compile('../../eres/eres2').
:- multifile initiates/2.

rule(initiation(initially,at(self,xy(0,0)),-1),initiation(initially,at(self,xy(0,0)),-1),[]).
rule(initiation(initially,neg(have(gold)),-1),initiation(initially,neg(have(gold)),-1),[]).
rule(initiation(initially,alive(wumpus),-1),initiation(initially,alive(wumpus),-1),[]).
rule(initiation(initially,have(arrow),-1),initiation(initially,have(arrow),-1),[]).
rule(initiation(initially,neg(win),-1),initiation(initially,neg(win),-1),[]).


rule(initiation(walk(Direction), at(self,NewXY), T), initiation(walk(Direction), at(self,NewXY), T), [happens(walk(Direction),T),holds(at(self,XY),T),adj(XY,NewXY,Direction)]) :- isdirection(Direction).


rule(termination(walk(Direction), at(self,XY1), T), termination(walk(Direction), at(self,XY1), T), [happens(walk(Direction),T),holds(at(self,XY2),T),naf(adj(XY1,XY2,Direction))]) :- isdirection(Direction).



rule(failed(walk(Direction),at(self,NewXY),T), failed(walk(Direction),at(self,NewXY),T), [g_check(happens(walk(Direction),T)), holds(percept(bump(Direction)),TNEXT), holds(at(self,XY),T), adj(XY,NewXY,Direction)]) :- TNEXT is T + 1, isdirection(Direction).

rule(failed(walk(Direction),neg(at(self,XY1)),T),failed(walk(Direction),neg(at(self,XY1)),T),[g_check(happens(walk(Direction),T)), holds(percept(bump(Direction)),TNEXT), holds(at(self,XY2),T), naf(adj(XY1,XY2,Direction))]) :- TNEXT is T + 1, isdirection(Direction).







/*
initiates(walk(Direction), at(self, NewXY)) :-
        aux(isdirection(Direction)),
	pre(at(self,xy(X,Y))),
	cmd(adj(xy(X,Y),NewXY,Direction)),
	post(neg(percept(bump(Direction)))).


terminates(walk(Direction), at(self, XY1)) :-
        aux(isdirection(Direction)),
	pre(at(self,XY2)),
	cmd(naf(adj(XY1,XY2,Direction))),
	post(neg(percept(bump(Direction)))).

HERE: 

terminates(walk(Direction), percept(P)) :-
        aux(isdirection(Direction)),
	pre(at(self)),
	pre(percept(P)),
	post(neg(percept(bump(Direction)))).

terminates(shoot(Direction), alive(wumpus)) :-
        aux(isdirection(Direction)),
	pre(have(arrow)),
	post(percept(scream)).

terminates(shoot(Direction), have(arrow)) :-
        aux(isdirection(Direction)),
	pre(have(arrow)),
	post(percept(scream)).

initiates(exit, win) :-
	pre(have(gold)),
	pre(at(self,xy(0,0))).

ramification(neg(at(self,XY1))) :-
	condition(g_check(at(self,XY2))),
	cmd(XY1\=XY2)

ramification(neg(at(self,xy(X1,Y1)))) :-
	condition(g_check(at(self,xy(X2,Y2)))),
	cmd(((plus(Diff,X1,X2);plus(Diff,Y1,Y2)), Abs is abs(Diff), Abs > 2)).


%% grab(Object)


ramification(danger) :-
	alive(wumpus),
	percept(stench).
*/
	
	

%% Auxiliary Predicates

adj(xy(X,Y),xy(NewX,NewY),Direction) :-
	delta(Direction,DX,DY),
	plus(X, DX,NewX),
	plus(Y, DY,NewY).

rule(adj(xy(X,Y),xy(NewX,NewY),Direction), adj(xy(X,Y),xy(NewX,NewY),Direction), [plus(X,DX,NewX), plus(Y,DY,NewY)]) :-
	delta(Direction,DX,DY).

delta(south,1,0).
delta(east,0,1).
delta(north,-1,0).
delta(west,0,-1).


lock(xy(X1,Y),xy(X2,Y), south) :- X1 < X2.
lock(xy(X1,Y),xy(X2,Y), north) :- X2 < X1.
lock(xy(X,Y1),xy(X,Y2), east) :- Y1 < Y2.
lock(xy(X,Y1),xy(X,Y2), west) :- Y2 < Y1.

%% Other auxiliary predicates

clause2list((A,B),L) :- !, clause2list(A,AL), clause2list(B,BL), append(AL,BL,L).
clause2list(A, [A]).

list2clause([],true).
list2clause([A|Bs], (A,B)) :-
	list2clause(Bs,B).

literal2fluent(g_check(L), g_check(F), T) :-
	!,
	literal2fluent(L, F, T).
literal2fluent(neg(L),neg(holds(L,T)), T) :- !.
literal2fluent(L,holds(L,T),T).

%%%%%% Move to ERES or Gorgias


incompatible(at(self,XY), at(self,NewXY)) :- adj(XY,NewXY,_).





%%% Trash

/*
rule(previous(A), previous(A), [A=happens(_,0)]).
rule(previous(A), previous(A), [A=happens(_,T1), T0 is T1 -1, T0 > 0, happens(Action2,T0), previous(happens(Action2,T0))]).

rule(next(A), next(A), [A=happens(_,T)]) :- current(t(T)).
rule(next(A), next(A), [A=happens(_,T0), T1 is T0 +1, T1 < T, happens(Action2,T1), previous(happens(Action2,T1))]).
*/



/* This is not what we really want. This one provides neg(holds(L,T1)) whenever an action that generates it failed. However, holds(L,T1) might be true anyway from previous conclusions.
rule(failed(A,T0), neg(holds(L,T1)), [happens(A,T), neg(holds(Postcond,T1))]) :-
%	istime(T0),
	T1 is T0 + 1,
	clause(initiates(A,L),Body),
	clause2list(Body, BodyList),
	my_findall(F,(member(postcond(C),BodyList),literal2fluent(C,F,T1)), Postconds),
	member(Postcond,Postconds).
*/

	
/*
initiates(shoot(Direction), percept(scream)) :-
	precond(at(percept(stench),XY1)),
	precond(at(percept(stench),XY2)),
%%	aux(current(xy(X,Y))),
	aux(member(X1,[0,1,2,3])),
	aux(member(X2, [0,1,2,3])),
	aux(member(Y1,[0,1,2,3])),
	aux(member(Y2, [0,1,2,3])),
	aux(XY1=xy(X1,Y1)),
	aux(XY2=xy(X2,Y2)),
	aux(adj(XY1, XYW,_)),
	aux(adj(XY2, XYW,_)),
	aux(lock(xy(X,Y),XYW,Direction)).
*/


%%	aux(current(xy(X,Y))),
%%	aux(adj(xy(X,Y),NewXY,Direction)),
%%        cmd(prove_with(['RES','NAF','BUILT_IN'],[holds(at(self,xy(X,Y)),T),ground(XY)],_)),
%%	aux(current(xy(X,Y))).


complement(happens(A1,T),happens(A2,T)) :-
	isaction(A1),
	isaction(A2),
	A1 \= A2.
