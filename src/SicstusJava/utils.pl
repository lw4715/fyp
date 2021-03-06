:- multifile rule/3.
:- compile('../gorgias-src-0.6d-Visual-20Feb2018/lib/gorgias.pl').
:- compile('../gorgias-src-0.6d-Visual-20Feb2018/ext/lpwnf.pl').
:- compile('evidence.pl').
:- compile('bg.pl').
?- set_prolog_flag(answer_write_options,[max_depth(0)]).

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

writeToFile(Filename, X, Prefix) :-
  open(Filename,append, Stream),
  write(Stream, 'rule('), write(Stream, Prefix), write(Stream, X), write(Stream, ', '),
  write(Stream, X), write(Stream, ',[]).\n'),
  close(Stream).

writeToFiles(Filename, X, D, Prefix) :-
  (D, writeToFile(Filename, X, Prefix));
    (\+ D, writeToFile(Filename, neg(X), Prefix)).

writeToFilesAll(X, D) :-
  (D, writeResultsToFile(X), writeNonResultsToFile(neg(X)));
    (\+ D, writeNonResultsToFile(X), writeResultsToFile(neg(X))).

writeToFilesPos(X, D) :-
  (D, writeResultsToFile(X), writeNonResultsToFile(neg(X))); \+ D.
