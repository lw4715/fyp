% ==================================================================== %
%                          Cycle Theory (Punctual or Timely)           %
% ==================================================================== %
% A cycle theory is viewed as a preference policy that will determine  %
% at each step the preferred next internal transition(s) to be         %
% executed. In effect, this policy ranks the various alternative       %
% transitions of the computee so that the most preferred can be chosen.%
% ==================================================================== %


:- compile('../../lib/gorgias').
:- compile('../../ext/lpwnf').


%abducible(at(tr(TR,A),T),[]) :- istransition(TR),isaction(A), istime(T).
%abducible(at(urgent(A),T),[]) :- isaction(A), istime(T).
%% abducible(ec(_,_,T,A), []) :- isaction(A), istime(T).
%% abducible(time_out(_),[]).
%% abducible(neg(X), []) :- abducible(X, []).



%% Basic Part of the cycle theory starting from a current action execution transition.

rule(r('AE','AE',C,T2), at(tr('AE',C),T2), [pat(tr('AE',C1),T1), ec('AE','AE',C,T2)]) :- istime(T1), T2 is T1 + 1.
%% rule(r('AE','PI',C,T2), at(tr('PI',C),T2), [pat(tr('AE',C1),T1), ec('AE','PI',C,T2)]) :- istime(T1), T2 is T1 + 1.
%% rule(r('AE','AO',C,T2), at(tr('AO',C),T2), [pat(tr('AE',C1),T1), ec('AE','AO',C,T2)]) :- istime(T1), T2 is T1 + 1.
rule(r('AE','PR',C,T2), at(tr('PR',C),T2), [pat(tr('AE',C1),T1), ec('AE','PR',C,T2)]) :- istime(T1), T2 is T1 + 1.


%%%%% Punctual or Timely Behavior

rule(pr1('AE','AE','PR',C), prefer(r('AE','AE',C,T),r('AE','PR',_,T)), [at(urgent(C),T)]) :- self(ID), behavior(ID, punctual).
%% rule(pr2('AE','PI',Z,C), prefer(r('AE','PI',C,T),r('AE',Z,C,T)), [at(urgent(C),T)]) :- self(ID), behavior(ID, punctual).
%% rule(pr3('AE','AO',Z,C), prefer(r('AE','AO',C,T),r('AE',Z,C,T)), [at(urgent(C),T)]) :- self(ID), behavior(ID, punctual).
rule(pr4('AE','PR','AE',C), prefer(r('AE','PR',C,T),r('AE','AE',_,T)), [at(done,T)]) :- self(ID), behavior(ID, punctual).

%%%%% Careful Behavior

rule(pr5(X,'PR',Y,C), prefer(r(X,'PR',C,T),r(X,Y,_,T)), [at(time_out,T)]) :- 
	istransition(X),
	istransition(Y),
	Y \= 'PR',
	self(ID), 
	behavior(ID, careful). 



rule(ec1(C,T), ec('AE','AE',C,T), []).
%% rule(ec2(C,T), ec('AE','PI',C,T), []).
%% rule(ec3(C,T), ec('AE','AO',C,T), []).
rule(ec4(C,T), ec('AE','PR',C,T), []).



rule(s1(T), at(urgent(C),T), [at(in_danger, T), writeln(do(rescue))]).
rule(s2(T), at(urgent(C),T), [at(late, T), writeln(do(shortcut))]).
%rule(s3(T), neg(at(urgent(C),T)), [at(done,T), writeln(do(sleep))]]).


rule(f2, pat(tr('AE',[something_here]),2), []).
rule(f3, at(in_danger,3), []).
rule(f4, pat(tr('AE',[something_here]),4), []).
rule(f5, at(deadline,5), []).
rule(f6, pat(tr('AE',[something_here]),6), []).
rule(f7, at(late,7), []).
rule(f72, at(time_out,7), []).
rule(f8, pat(tr('AE',[something_here]),8), []).
rule(f9, at(done,9), []).




%%%%% Queries:
%% time(prove([at(tr(TR,gardening),1)],D)).
%% 14,869,072 inferences in 11.79 seconds (1261160 Lips)


%rule(f3, time_out(gardening,1), []).
% Queries: time(prove([at(tr(TR,gardening),1)],D).
% 14,019,718 inferences in 10.96 seconds (1279171 Lips)




%%%%% If we want to have a Plan Revision always followed by a Goal Revision 
%% rule(pr('PR','GR',Z,A), prefer(r('PR','GR',A,T),r('PR',Z,A,T)), []) :- istransition(Z).




%%%%% Focused Behavior ???
%% rule(pr('AE','AE',Z,A), prefer(r('AE','AE',A,T),r('AE',Z,A,T)), [same_plan]) :- self(ID), behavior(ID, focused).
%% rule(pr('AE','PI',Z,A), prefer(r('AE','PI',A,T),r('AE',Z,A,T)), [same_plan]) :- self(ID), behavior(ID, focused).





%%%%%
istime(T) :- member(T, [0,1,2,3,4,5,6,7,8,9]).
isaction(A) :- member(A, [gardening, holiday]).
istransition(Z) :- member(Z, ['AE','PI','AO','PR']).



pretty([]).
pretty([X|Xs]) :-
	writeln(X),
	pretty(Xs).



%%
complement(at(tr(Tr1,C),T),at(tr(Tr2,C),T)) :- istransition(Tr1), istransition(Tr2),Tr1 \= Tr2.




%%%

self(ag1).
self(ag2).

behavior(ag1, punctual).
behavior(ag2, careful).
behavior(ag3, focused).
behavior(ag4, impatient).
behavior(ag5, efficient).
behavior(ag6, cautious).
