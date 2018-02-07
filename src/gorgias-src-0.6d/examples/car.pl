% =====================================================================	%
%                			CAR EXAMPLE			%
% =====================================================================	%
% This example is taken from the paper 'Preferred Answer Sets for 	%
% Extended Logic Programs' by Gerhard Brewka and Thomas Eiter.	   	%	% ===================================================================== % 


:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').


rule(r1(Car), neg(buy(Car)), [expensive(Car)]).
rule(r2(Car), buy(Car),      [safe(Car)]).
rule(r3(Car), buy(Car),      [nice(Car)]).
rule(r4(Car), buy(Car),      [fast(Car)]).


rule(f1, expensive(chevrolet), []).
rule(f2, safe(chevrolet),      []).
rule(f3, safe(volvo),          []).
rule(f4, nice(porsche),        []).
rule(f5, fast(porsche),        []).


rule(pr1(X), prefer(r1(X),r2(X)), []).
rule(pr2(X), prefer(r1(X),r3(X)), []).
rule(pr2(X), prefer(r1(X),r4(X)), []).
