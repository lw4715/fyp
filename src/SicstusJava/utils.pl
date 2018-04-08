% :- module(abr, [rule/3, prove/2]).
%% :- use_module(double_quotes).
:- compile('../gorgias-src-0.6d/lib/gorgias.pl').
:- compile('../gorgias-src-0.6d/ext/lpwnf.pl').
:- compile('backgroundgorgias.pl').
:- compile('evidence.pl').
:- compile('user_evidence.pl').

?- set_prolog_flag(toplevel_print_options, [quoted(true), portrayed(true), max_depth(0)]).

count(L, S, I-S) :-
    aggregate(count, member(S, L), C), I is -C.

initFile(Filename) :- open(Filename,write, Stream),
  write(Stream, ':- multifile rule/3.\n'),
  close(Stream).
