% =============================================================== %
%	             REOCCURRING GOALS EXAMPLE			  %
% =============================================================== %
% This example is used to illustrate the behaviour of the 	  %
% program when trying to prove reoccurring goals.  		  %
% =============================================================== %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, p, []).
rule(r2, q, []).

rule(r3, neg(p), [q]).
rule(r4, neg(q), [p]).

rule(pr1, prefer(r3,r1), []).
rule(pr2, prefer(r4,r2), []).
