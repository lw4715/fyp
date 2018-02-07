% =============================================================== %
%			  SELF-REFERENCING RULES EXAMPLE  	  % 
% =============================================================== %
% This example is used to illustrate the behavior of the program  %
% when handling self-referencing rules. 		 	  %
%================================================================ %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, p,              [p]).
rule(r2, neg(p),         [k]).
rule(r3, p,              [q]).
rule(r4, q,              [p]).

rule(pr, prefer(r2, r1), []).
