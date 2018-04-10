:- use_module(library(timeout)).
%% :- use_module(double_quotes).
:- compile('../gorgias-src-0.6d/lib/gorgias.pl').
:- compile('../gorgias-src-0.6d/ext/lpwnf.pl').
:- compile('backgroundgorgias.pl').
:- compile('evidence.pl').
:- compile('user_evidence.pl').

?- set_prolog_flag(toplevel_print_options, [quoted(true), portrayed(true), max_depth(0)]).

count(L, S, I-S) :-
    aggregate(count, member(S, L), C), I is -C.

initFile(Filename) :- open(Filename, write, Stream),
  write(Stream, ':- multifile rule/3.\n'),
  close(Stream).

cleanFile(Filename) :- 
  open(Filename, write, Stream),
  write(Stream, ''),
  close(Stream).

writeResultsToFile(X) :- 
  open('results.pl', append, Stream),
  write(Stream, X), write(Stream, '\n'),
  close(Stream).

writeNonResultsToFile(X) :-
  open('non_results.pl', append, Stream),
  write(Stream, X), write(Stream, '\n'),
  close(Stream).

writeToFile(Filename, X) :-
  open(Filename,append, Stream),
  write(Stream, 'rule(t_'), write(Stream, X), write(Stream, ', '),
  write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

writeToFiles(Filename, X, D) :-
  (D, writeToFile(Filename, X));
    (\+ D, writeToFile(Filename, neg(X))).

writeToFilesAll(Filename, X, D) :-
  (D, writeToFile(Filename, X), writeResultsToFile(X));
    (\+ D, writeToFile(Filename, neg(X)), writeNonResultsToFile(X)).

writeToFilesAbd(Filename, X, D) :-
  (D, writeToFile(Filename, X));
    (\+ D, writeNonResultsToFile(X)).

writeToFilesAllAbd(Filename, X, D) :-
  (D, writeToFile(Filename, X), writeResultsToFile(X));
    (\+ D, writeNonResultsToFile(X)).