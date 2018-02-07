:-module(screenWriting,[mnl/0,mwrite/1,mwrite_term/2,writeQuad/4,writeStructQuad/6,writeQuadIB/5,writeQuadList/1]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Assuming that the main file declares a "silent/0" predicate to indicate output mode.    %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

writeQuadIB(A,B,C,D,F) :- mnl, 
	mwrite('Content of this quadruple:'), mnl, 
	mwrite('PropNods: '), mwrite_term(A,[]), mnl, 
	mwrite('OppoNods: '), mwrite_term(B,[]), mnl, 
   	mwrite('DfnceAss: '), mwrite_term(C,[]), mnl, 
   	mwrite('Culprits: '), mwrite_term(D,[]), mnl, 
	mwrite('FailNods: '), mwrite_term(F,[]), mnl, mnl.

writeQuad(A,B,C,D) :- mnl, 
	mwrite('Content of this quadruple:'), mnl,
	mwrite('PropNods: '), mwrite_term(A,[]), mnl,
	mwrite('OppoNods: '), mwrite_term(B,[]), mnl, 
   	mwrite('DfnceAss: '), mwrite_term(C,[]), mnl,
   	mwrite('Culprits: '), mwrite_term(D,[]), mnl, mnl.

writeStructQuad(A,B,C,D,Arg,Rel) :- mnl, 
	mwrite('Content of this quadruple:'), mnl,
	mwrite('PropNodes: '), mwrite_term(A,[]), mnl,
	mwrite('OppoNodes: '), mwrite_term(B,[]), mnl, 
   	mwrite('DefnceAss: '), mwrite_term(C,[]), mnl,
   	mwrite('Culprits : '), mwrite_term(D,[]), mnl, 
   	mwrite('Arguments: '), mwrite_term(Arg,[]), mnl,
   	mwrite('Relations: '), mwrite_term(Rel,[]), mnl, mnl.

writeQuadList([]).
writeQuadList([H|T]) :- mnl, mwrite(' <'), mwrite(H), mwrite('> '), writeQuadList(T).

mwrite(_) :- user:silent, !.												
mwrite(X) :- write(X).

mnl :- user:silent, !.
mnl :- nl.

mwrite_term(_,_) :- user:silent, !.
mwrite_term(X,Y) :- write_term(X,Y).