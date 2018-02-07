% ==================================================================== %
%	                   PENGUIN EXAMPLE			       %
% ==================================================================== %
% This example is taken from the paper 'Logic Programming without      %
% Negation as Failure' by Yannis Dimopoulos and Antonis Kakas. 	       %
% ==================================================================== %

:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r1(X), fly(X),            [bird(X)]).
rule(r2(X), neg(fly(X)),       [penguin(X)]).
rule(r3(X), penguin(X),        [walkslikepeng(X)]).
rule(r4(X), neg(penguin(X)),   [neg(flatfeet(X))]).
rule(r5(X), bird(X),           [penguin(X)]).

rule(f1, bird(t),              []).
rule(f2, walkslikepeng(t),     []).
rule(f3, neg(flatfeet(t)),     []).


rule(pr1, prefer(r2(_),r1(_)), []).
rule(pr2, prefer(r4(_),r3(_)), []).
