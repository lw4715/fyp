:-module(admissibleBeliefs,[runAB/2]).

:- use_module(library(lists)).
:- use_module(helperFunctions).
:- use_module(screenWriting).

runAB :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeQuad(P,[],A0,[]), executeAB(P, [], A0, [], 1). 
runABall :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeQuad(P,[],A0,[]), executeABall(P, [], A0, [], 1). 

runAB(s,1) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runAB.
runAB(n,1) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runAB.

runAB(s,a) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runABall.
runAB(n,a) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runABall.

executeAB([],[],A,_,_) :- write('FINISHED, the defence set is: '), write(A), nl, nl.
executeAB(A,B,C,D,N) :- executeOneAB((A,B,C,D),(A2,B2,C2,D2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeQuad(A2,B2,C2,D2), 
					executeAB(A2,B2,C2,D2,N1). 

executeABall([],[],A,_,_) :- write('FINISHED, one defence set is: '), write(A), nl, nl, fail.
executeABall(A,B,C,D,N) :- executeOneAB((A,B,C,D),(A2,B2,C2,D2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeQuad(A2,B2,C2,D2), 
					executeABall(A2,B2,C2,D2,N1). 


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Basically just going though the cases ... AB DISPUTE DERIVATIONS ...                 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Given a list of Propositions, select one and instantiate the second argument 	   	 %%%
%%%   first argument: list of PropNodes													 %%%
%%%   second argument: list of OppNodes													 %%%
%%%   third argument (to be instantiated): Omega										 %%%
%%%   fourth argument (to be inst.): S (only needed if choose from OppNodes, else [])	 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

selFunc([H|_],_,H,[]).
selFunc([],[[O|OT]|_],O,[O|OT]). 
%selFunc([],[],_,_) :- write('Suppose we ve finished ...').

%  Case 1 (i) ... Omega is selected from P and is an assumption ... hence S is empty
executeOneAB((P,O,A,C), (P2,O2,A,C)) :- 	selFunc(P,O,Omega,[]), 
										isAss(Omega), 
										mwrite('CASE 1i'), mnl,
%										contrary(Omega,OmegaBar),
										findall([X], contrary(Omega,X), ListListContraries),
										append(ListListContraries,O,O2),     	% ORDER !!! 
%										append([[OmegaBar]],O,O2),     	 
										select(Omega,P,P2).				

%  Case 1 (ii) ... Omega is selected from P and is NOT an assumption ... hence S is empty
executeOneAB((P,O,A,C), (P2,O,A2,C)) :- 	selFunc(P,O,Omega,[]), 
										\+ isAss(Omega), 
										mwrite('CASE 1ii'), mnl,
										findR(Omega,C,R),
										select(Omega,P,PTemp),
										filterR(R,A,FilteredR),			% NEW !
										append(PTemp,FilteredR,P2),		% CHANGED !
										myAss(Ass),
										intersectLists(Ass,R,InterSected),
 										append(A,InterSected,A2). 

%  Case 2 (i) b) ... S from O and Omega from S ... Omega is assumption ... not in A, but in C.
executeOneAB((P,O,A,C), (P,O2,A,C)) :-	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										\+ member(Omega,A),
										member(Omega,C),
										mwrite('CASE 2ib'), mnl,
										select([S|STail],O,O2).
										
%  Case 2 (i) c) 1) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
executeOneAB((P,O,A,C), (P2,O2,A,C2)) :-	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										\+ member(Omega,A),
										\+ member(Omega,C),
										append(C,[Omega],C2),
										select([S|STail],O,O2),
										
										contrary(Omega,OmegaBar),
										\+ isAss(OmegaBar),
										mwrite('CASE 2ic1'), mnl,
										append(P,[OmegaBar],P2).

%  Case 2 (i) c) 2) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
executeOneAB((P,O,A,C), (P,O2,A2,C2)) :-	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										\+ member(Omega,A),
										\+ member(Omega,C),
										append(C,[Omega],C2),
										select([S|STail],O,O2),
										
										contrary(Omega,OmegaBar),
										isAss(OmegaBar),
										\+ member(OmegaBar,C),   % NEW LINE NOT IN ALGO !!!!
										mwrite('CASE 2ic2'), mnl,
										append(A,[OmegaBar],A2).

%  Case 2 (i) a) ... S from O and Omega from S ... Omega is assumption ... and ignored.
executeOneAB((P,O,A,C), (P,O2,A,C)) :- 	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										mwrite('CASE 2ia'), mnl,
										select([S|STail],O,OTemp),
										select(Omega,[S|STail],STemp),
										append(OTemp,[STemp],O2).

%  Case 2 (ii) ... S from O and Omega from S ... Omega is NOT an assumption
executeOneAB((P,O,A,C), (P,O2,A,C)) :-	selFunc(P,O,Omega,[S|STail]), 
										\+ isAss(Omega),
										mwrite('CASE 2ii'), mnl,
										select([S|STail],O,OTemp),
										constructLastCaseAB([S|STail],Omega,C,OTempRHS), % CHANGED !
										append(OTemp,OTempRHS,O2).


constructLastCaseAB(S,Omega,C,Return) :- findall(X,(myRule(Omega,RHS), 
												intersectLists(C,RHS,[]),
												select(Omega,S,STemp),
												append(STemp,RHS,X), X \== []),Return).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

toBeProved(X) :- user:toBeProved(X).
myAss(X) :- user:myAss(X).
contrary(X,Y) :- user:contrary(X,Y).
myRule(X,Y) :- user:myRule(X,Y).