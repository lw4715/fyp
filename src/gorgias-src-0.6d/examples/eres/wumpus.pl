
:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').
:- compile('eres2').


rule(i(A,L,T,Preconds,Postconds), initiation(L,T), [happens(A,T)|Ps]) :-
	clause(initiates(A,L),Body),
	clause2list(Body, BodyList),
  	my_findall(Clause, member(aux(Clause),BodyList), AuxiliaryConds),
  	list2clause(AuxiliaryConds,AuxiliaryPredicates),
  	AuxiliaryPredicates,
	my_findall(holds(C,T),member(precond(C),BodyList),Preconds),
	my_findall(holds(C,T),member(postcond(C),BodyList), Postconds),
	union(Preconds,Postconds,Ps).


rule(t(A,L,T,Preconds,Postconds), termination(L,T), [happens(A,T)|Ps]) :-
	clause(terminates(A,L),Body),
	clause2list(Body, BodyList),
  	findall(Clause, member(aux(Clause),BodyList), AuxiliaryConds),
  	list2clause(AuxiliaryConds,AuxiliaryPredicates),
  	AuxiliaryPredicates,
	findall(holds(C,T),member(precond(C),BodyList),Preconds),
	findall(holds(C,T),member(postcond(C),BodyList), Postconds),
	union(Preconds,Postconds,Ps).

%% grab(Object)

initiates(grab(gold), have(gold)) :-
	precond(grab(gold)), 
	precond(percept(glitter)).


%% exit

initiates(exit, win) :-
	precond(have(gold)),
	precond(percept(start)).


%% shoot(Direction)

terminates(shoot(Direction), alive(wumpus)) :-
	precond(have(arrow)),
	postcond(percept(scream)).

%% walk(Direction)

initiates(walk(Direction), at(self, NewXY)) :-
	precond(at(self,xy(X,Y))),
	aux(current(xy(X,Y))),
	aux(adj(xy(X,Y),NewXY,Direction)).
	
terminates(walk(Direction), at(self, xy(X,Y))) :-
	precond(at(self,xy(X,Y))).


adj(xy(X,Y),xy(NewX,NewY),Direction) :-
	delta(Direction,DX,DY),
	NewX is X + DX,
	NewY is Y + DY.

delta(east,1,0).
delta(south,0,1).
delta(west,-1,0).
delta(north,0,-1).



%% Other auxiliary predicates

clause2list((A,B),L) :- !, clause2list(A,AL), clause2list(B,BL), append(AL,BL,L).
clause2list(A, [A]).

list2clause([],true).
list2clause([A|Bs], (A,B)) :-
	list2clause(Bs,B).

my_findall(Var,Goal,Bag) :-
	bagof(Var,Goal,Bag),
	!.
my_findall(_,_,[]).


%%%%%%

current(xy(0,0)).
rule(f0, neg(holds(have(gold),0)), []).
rule(f1, holds(alive(wumpus),0), []).
rule(f2, at(self, xy(X,Y)), []) :- current(xy(X,Y)).
