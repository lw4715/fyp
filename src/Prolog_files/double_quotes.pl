:- module(double_quotes, []).

/** <module> Readable string notation

The ISO Prolog standard defines three meanings for double quoted
strings in Prolog text (double quoted list tokens 6.4.6).  The Prolog
flag double_quotes (7.11.2.5) determines the current meaning.  This
flag affects compilation, read_term/3, and companions - any
conversions from Prolog text to terms.  The possible values are:
chars, codes, atom.

==
   double_quotes     "abc".      "".
  ------------------------------------
       chars        [a,b,c].     [].
       codes       [97,98,99].   [].    % ASCII/Latin/Unicode
       atom           abc.       ''.
==

Once the Prolog text "abc" has been converted to the corresponding
term, the information where the term came from is lost forever.  This
is particularly cumbersome when using DCGs with texts.  Consider with
default settings:

==
?- phrase(("Ja tvoi ",("sluga"|"rabotnik"),"!"), Satz).
Satz = [74,97,32,116,118,111,105,32,115,108,117,103,97,33] ;
Satz = [74,97,32,116,118,111,105,32,114,97,98,111,116,110,105,107,33].
==

Shall Satz be printed as quoted text or not?  It really depends on the
situation.  In the context of clpfd-constraints, an unwanted
conversion is very inconvenient.  The situation is less problematic
when using chars.  Even if we have written a list [a,b,c] on purpose,
"abc" is not too far away - and a bit more compact.

With set_prolog_flag(double_quotes,chars) in the .plrc or pl.ini we
get now:

==
?- phrase(("Ja tvoi ",("sluga"|"rabotnik"),"!"), Satz).
Satz = "Ja tvoi sluga!" ;
Satz = "Ja tvoi rabotnik!".
==

See also http://stackoverflow.com/a/8269897/772868

2010-11-24: Chars in place of codes.
2016-02-29: Adoption for SICStus.

@author Ulrich Neumerkel

*/

:- use_module(library(codesio),[format_to_codes/3]).


:- multifile(user:portray/1).

user:portray(Chars) :-
	portray_chars(Chars),
	!.

portray_chars(Chars) :-
	Chars = [Char|_],
	atom(Char),
	atom_length(Char, 1),
	prolog:'$list_info'(Chars,_,Rest),
	Rest == [],
	ground(Chars),
	current_prolog_flag(double_quotes, chars),
	\+ ( member(NonChar, Chars), \+ ( atom(NonChar), atom_length(NonChar,1) ) ),
	atom_chars(Atom,Chars),
	write_double_quoted_atom(Atom).

write_double_quoted_atom(Atom) :-
	format_to_codes('~q', [Atom], Codes0),
	Codes0 = [Co0|Codes1],
	(	Co0 == 0'\'
	->	phrase(quoted_dbl(Codes1), S)
	;	phrase(unquoted_dbl(Codes0), S)
	),
	format('"~s"',[S]).

unquoted_dbl([]) -->
	[].
unquoted_dbl([C|Cs]) -->
	( {C == (0'\\)} -> [\,\] ; {char_code(Ch,C)}, [Ch] ),
	unquoted_dbl(Cs).

quoted_dbl([0'\']) --> !.
quoted_dbl([0'\\,0'\\|Cs]) --> !,
	[\,\],
	quoted_dbl(Cs).
quoted_dbl([0'\\,0'\']) --> !,
	[\].
quoted_dbl([0'\\,0'\'|Cs]) --> !,
	['\''],
	quoted_dbl(Cs).
quoted_dbl([C|Cs]) -->
	( { C == 0'" } -> [\,'"'] ; {char_code(Ch,C)}, [Ch] ),
	quoted_dbl(Cs).
