% =============================================================== %
%                  	 ABCD EXAMPLE           		  %
% =============================================================== %
% This example is taken from the paper 'Preferred Answer Sets 	  %
% for Extended Logic Programs' by Gerhard Brewka and Thomas Eiter.%	 
% =============================================================== % 


:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(r1, a,               []).
rule(r2, neg(a),          []).
rule(r3, c,               []).
rule(r4, neg(c),          [b]).
rule(r5, neg(d),          []).
rule(r6, d,               [b]).
rule(r7, b,               [a]).


rule(pr1, prefer(r2, r1), []).
rule(pr2, prefer(r4, r3), []).
rule(pr3, prefer(r6, r5), []).
