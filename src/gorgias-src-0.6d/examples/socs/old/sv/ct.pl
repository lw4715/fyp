/*
 * Author: Neophytos Demetriou (nkd@ucy.ac.cy)
 * Date: July 28, 2003 - August 4, 2003
 */

:- multifile rule/3, complement/2.




this :: {
  super(computee_state)
}.




/*
 * Basic part: determines the basic steps of operation by specifying the 
 * allowed unitary cycle-steps from one transition to another.
 */


rule(tr('AE', 'PI', Gs, T), tr('AE', 'PI', Gs, T), []) :- ec('AE','PI', Gs, T).
rule(tr('AE', 'AE', As, T), tr('AE', 'AE', As, T), []) :- ec('AE','AE', As, T).
rule(tr('AE', 'AO', Fs, T), tr('AE', 'AO', Fs, T), []) :- ec('AE','AO', Fs, T).
rule(tr('AE', 'PR', [], T), tr('AE', 'PR', [], T), []) :- ec('AE','PR', [], T).


ec('AE', 'PI', Gs, T) :- c_GS(Gs,T).
ec('AE', 'AE', As, T) :- c_AS(As,T).
ec('AE', 'AO', Fs, T) :- c_FS(Fs,T).
ec('AE', 'PR', [], T).



complement(tr(Prev,Tr1),tr(Prev,Tr2)) :-
	istransition(Prev),
        istransition(Tr1),
        istransition(Tr2),
        Tr1 \= Tr2.





/*
 * Interrupt part: specifies the cycle steps that can follow a PO, i.e. an
 * interrupt with new information. These are viewed as re-initialization steps
 * for the cycle operation.
 */

rule(tr('PO', 'GI', [], T), tr('PO', 'GI', [], T), []) :- ec('PO','GI', [], T).
rule(tr('PO', 'RE', [], T), tr('PO', 'RE', [], T), []) :- ec('PO','RE', [], T).
rule(tr('PO', 'GR', [], T), tr('PO', 'GR', [], T), []) :- ec('PO','GR', [], T).



/*
 * Behaviour part: determines via preference rules on the alternatives given in
 * the basic and interrupt parts the special characteristics of the operation
 * (and thus behaviour) of the computee.
 */


%%% Punctual Profile

rule(prefer(tr(Prev,'PI',Gs,T),tr(Prev,Z,X,T)), prefer(tr(Prev,'PI',Gs,T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	h_u_GS(Gs,T), 
	Gs \= [].
rule(prefer(tr(Prev,'AE',As,T),tr(Prev,Z,X,T)), prefer(tr(Prev,'AE',As,T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	h_u_AS(As,T), 
	As \= [].
rule(prefer(tr(Prev,'AO',Fs,T),tr(Prev,Z,X,T)), prefer(tr(Prev,'AE',Fs,T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	h_u_FS(Fs,T), 
	Fs \= [].
rule(prefer(tr(Prev,'PR',[],T),tr(Prev,Z,X,T)), prefer(tr(Prev,'PR',[],T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	nothing_urgent_or_to_be_sensed(T).


%%% Careful Profile

rule(prefer(tr(Prev,'PR',[],T),tr(Prev,Z,X,T)), prefer(tr(Prev,'PR',[],T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	time_out(T).


time_out(T) :-

	this::KB0::get(observed(something))


	this::get(plans([Plan|_])),
	member(action(_,_,_,TC), Plan),
	%%% HERE %%%
	T > TC. 



%%% Focused Profile

rule(prefer(tr('AE','AE',As,T),tr('AE',Z,X,T)), prefer(tr('AE','AE',As,T),tr('AE',Z,X,T)), []) :- 
	istransition(Z),
	h_sp_AS(As,T),
	As \= [].


%%% Cautious Profile

rule(prefer(tr(Prev,'SI',Fs,T),tr(Prev,'AE',As,T)), prefer(tr(Prev,'SI',Fs,T),tr(Prev,'AE',As,T)), []) :- 
	istransition(Prev),
	pre(As,Fs), 
	Fs \= [].

rule(prefer(tr(Prev,'AE',As,T),tr(Prev,Z,X,T)), prefer(tr(Prev,'AE',As,T),tr(Prev,Z,X,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	h_pre_AS(As,T), 
	As \= [].


%%% Impatient Profile

rule(prefer(tr(Prev,Z,X,T),tr(Prev,'AE',As,T)), prefer(tr(Prev,Z,X,T),tr(Prev,'AE',As,T)), []) :- 
	istransition(Prev),
	istransition(Z),
	Z \= 'AE',
	h_fail_AS(As,T),
	As \= [].


%%% Cross Preferences (page 73)




/*
 * Core Selection Functions
 */

c_AS(As,T) :-
	this::get(plans([Plan|_])),
	findall(A, (member(A,Plan), c_AS_aux(Plan,A,T)), As).

c_AS_aux(Plan, action(_,Goal,Preconditions,TemporalConstraints), T) :-
	this::get(goals(Gs)).
%%%HERE%%%



/*
 * Heuristic Selection Functions
 */ 
	

nothing_urgent_or_to_be_sensed(T) :- 
	h_u_AS(T,As), As = [], 
	h_u_AS(T,Gs), Gs = [],
	h_u_FS(T,Fs), Fs = [].



/*****************************************************************************/



istransition('GI').
istransition('PI').
istransition('RE').
istransition('SI').
istransition('POI').
istransition('AOI').
istransition('AE').
istransition('GR').
istransition('PR').
