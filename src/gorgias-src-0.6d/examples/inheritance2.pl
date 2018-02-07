:- compile('../lib/gorgias').
:- compile('../ext/lpwnf').

rule(f1, subclass(a,b), []).
rule(f2, subclass(c,b), []).
rule(f3, subclass(d,c), []).
rule(f5, is_in(x1,a),   []).
rule(f6, is_in(x2,c),   []).
rule(f7, is_in(x3,d),   []).


rule(d1(X), has(X,p),      [is_in(X,b)]).

% Exception

rule(d2(X), neg(has(X,p)), [is_in(X, c)]).
rule(pr1(X),   prefer(d2(X),d1(X)), [is_in(X, c)]).


rule(f4, subclass(d,a), []).
rule(pr2(X),   prefer(d1(X),d2(X)), [is_in(X,a)]).


% General properties of subclass and is_in

rule(r1(C0,C2), subclass(C0,C2), [C0 \= C1, C1 \= C2, C0 \= C2, subclass(C0,C1), subclass(C1,C2)]).
rule(r2(X,C1),  is_in(X,C1),      [subclass(C0,C1), is_in(X,C0)]).


% Closed world assumptions for simple hierarchies

%rule(d3(X,C), neg(is_in(X, C)),   []).
%rule(d4(A,B), neg(subclass(A,B)), []).

