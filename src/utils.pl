:- compile('gorgias-src-0.6d/lib/gorgias.pl').
:- compile('gorgias-src-0.6d/ext/lpwnf.pl').

?- set_prolog_flag(toplevel_print_options, [quoted(true), portrayed(true), max_depth(0)]).

maxRepeated(L, M) :-
    sort(L, S),
    maplist(count(L), S, C),
    keysort(C, [_-M|_Ms]).
count(L, S, I-S) :-
    aggregate(count, member(S, L), C), I is -C.