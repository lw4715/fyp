:- multifile rule/3, complement/2.

kb_gd :: {

    super(object) &

    attributes([]) &

    goal(checkoutFromHotel, nil, [T<10])

}.



%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Connect the Goal Decision knowledge base with the argumentation system.
%%
%% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



rule(gd(G), gd(G), []) :- 
	kb_gd :: goal(G, ParentGoal, TCs),
	\+ goal(G, ParentGoal, TCs).

rule(prefer(PREF1,PREF2), prefer(PREF1,PREF2), CONDITIONS) :-
	kb_gd :: rule(prefer(PREF1,PREF2), prefer(PREF1,PREF2), CONDITIONS).


complement(gd(X),gd(Y)) :-
	kb_gd :: goal(X,_,_),
	kb_gd :: goal(Y,_,_),
	X \= Y.


