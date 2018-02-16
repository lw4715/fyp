:- use_module(library(lists)).
:- use_module(library(system)).
:- use_module(screenWriting).
:- use_module(groundBeliefs).
:- use_module(admissibleBeliefs).
:- use_module(idealBeliefs).


:- dynamic silent/0.
:- sleep(0.1).
:- 	nl, nl,
	write('************************************************************************************'),nl,
	write('***  Welcome to CaSAPI - a Credulous and Sceptical Argumenation system!          ***'),nl,
	write('***                                                                              ***'),nl,
	write('***  Please decide on the type of dispute derivation you want to employ,         ***'),nl,
	write('***  choosing between grounded beliefs (gb), admissible beliefs (ab) or ideal    ***'),nl,
	write('***  beliefs (ib) semantics.  Invoke CaSAPI with run/3 as follows:               ***'),nl,
	write('***                                                                              ***'),nl,
	write('***  run(derivation_type, output_mode, number_of_solutions).                     ***'),nl,
	write('***                                                                              ***'),nl,
	write('***  The second argument determines the output mode: (s)ilent or (n)oisy.        ***'),nl,
	write('***  The third argument indicates whether (1) or (a)ll solutions are required.   ***'),nl,
	write('***                                                                              ***'),nl,
	write('***  For example, type run(ib,n,1) to find ONE solution according to the ideal   ***'),nl,
	write('***  beliefs semantics with detailed output to screen.  Or type run(gb,s,a) to   ***'),nl,
	write('***  find ALL solutions in silent mode (with minimal output to screen) using     ***'),nl,
	write('***  the grounded beliefs semantics.                                             ***'),nl,
	write('***                                                                              ***'),nl,
	write('***  Developed in 2006 by Dorian Gaertner for the ArguGrid project.              ***'),nl,
	write('************************************************************************************'),nl,
	nl.

run(gb,X,Y) :- runGB(X,Y).
run(ab,X,Y) :- runAB(X,Y).
run(ib,X,Y) :- runIB(X,Y).