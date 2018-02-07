:- compile('gorgias-src-0.6d/lib/gorgias').
:- compile('gorgias-src-0.6d/ext/lpwnf').

rule(f1, subclass(a,b), []).
rule(f1, subclass(b,c), []).
rule(f1, subclass(c,d), []).
rule(f2, subclass(b,f), []).
rule(f2, subclass(c,b), []).
rule(f2, subclass(b,a), []).
rule(f3, is_in(x1,a),   []).
rule(f4, is_in(x2,c),   []).

rule(closure(X,Y), subsubclass(X,Y), [subclass(X,Y)]).

rule(d1(X), has(X,p),      [is_in(X,b)]).

% Exception

rule(d2(X), neg(has(X,p)), [is_in(X, c)]).
rule(pr1,   prefer(d2(X),d1(X)), []).


% General properties of subclass and is_in

rule(r1(C0,C2), subsubclass(C0,C2), [subclass(C0,C1), subsubclass(C1,C2)]).
rule(r2(X,C1),  is_in(X,C1),      [subclass(C0,C1), is_in(X,C0)]).


% Closed world assumptions for simple hierarchies

rule(d3(X,C), neg(is_in(X, C)),   []).
rule(d4(A,B), neg(subclass(A,B)), []).
