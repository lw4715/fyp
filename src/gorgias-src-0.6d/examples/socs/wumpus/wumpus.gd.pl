:- multifile isgoal/1.

%% GD

rule(c_GD(G), c_GD(G), []) :- isgoal(G), \+ todo(add(G)).

isgoal(p_goal(at(self,NewXY))) :-
	current(t(T)),
	my_location(XY,T),
	adj(XY,NewXY,_).


/*


isgoal(p_goal(win)).

rule(h_p(c_GD(p_goal(win)),c_GD(G)), prefer(c_GD(p_goal(win)),c_GD(G)), []) :-
	isgoal(G),
	G \= p_goal(win).

rule(h_p(c_GD(p_goal(at(self,XY1))),c_GD(p_goal(at(self,XY2)))), prefer(c_GD(p_goal(at(self,XY1))),c_GD(p_goal(at(self,XY2)))), []) :-
	my_state(location(XY2),_),
	\+ my_state(location(XY1),_).


%% HERE: higher-order priority to capture danger


complement(gd(G1),gd(G2)) :-
	isgoal(G1),
	isgoal(G2),
	G1 \= G2.


*/
