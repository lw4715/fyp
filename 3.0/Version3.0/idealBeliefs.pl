:-module(idealBeliefs,[runIB/2]).

:- use_module(library(lists)).
:- use_module(helperFunctions).
:- use_module(screenWriting).
:- use_module(failDerivation).

runIB :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeQuadIB(P,[],A0,[],[]), executeIB(P, [], A0, [], [], 1). 
runIBall :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeQuadIB(P,[],A0,[],[]), executeIBall(P, [], A0, [], [], 1). 

runIB(s,1) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runIB.
runIB(n,1) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runIB.

runIB(s,a) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runIBall.
runIB(n,a) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runIBall.

executeIB([],[],A,_,[],_) 	:- 	write('FINISHED, the defence set is: '), write(A), nl, nl.
executeIB(A,B,C,D,F,N) 		:- 	executeOneIB((A,B,C,D,F),(A2,B2,C2,D2,F2)),
								mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
								writeQuadIB(A2,B2,C2,D2,F2), 
								executeIB(A2,B2,C2,D2,F2,N1). 

executeIBall([],[],A,_,[],_) 	:- 	write('FINISHED, one defence set is: '), write(A), nl, nl, fail.
executeIBall(A,B,C,D,F,N) 		:- 	executeOneIB((A,B,C,D,F),(A2,B2,C2,D2,F2)),
								mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
								writeQuadIB(A2,B2,C2,D2,F2), 
								executeIBall(A2,B2,C2,D2,F2,N1). 


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Basically just going though the cases ... IB DISPUTE DERIVATIONS ...                 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

selFuncIB([H|_],_,_,H,[],[]).
selFuncIB([],[[(O,off)|OT]|_],_,O,[(O,off)|OT],[]).
selFuncIB([],[[(O,on)|OT]|STail],F,O2,[(O2,M)|OT2],[]) :-	
													\+ allMarked(OT),
													append(OT,[(O,on)],NewS), 
													selFuncIB([],[NewS|STail],F,O2,[(O2,M)|OT2],[]).

%selFuncIB([],[SinO],[S|_],noOmega,[],S) :- allMarked(SinO).
selFuncIB([],[L|Tail],F,A,B,C)  :- allMarked(L), selFuncIB([],Tail,F,A,B,C).

selFuncIB([],[],[S|_],noOmega,[],S).
%selFuncIB([],[],[],_,_,_) :- write('Suppose we ve finished ...').


%  Case 1 (i) ... Omega is selected from P and is an assumption ... hence S is empty
executeOneIB((P,O,A,C,F), (P2,O2,A,C,F)) :- 	selFuncIB(P,O,F,Omega,[],[]), 
											isAss(Omega), 
											mwrite('CASE 1i'), mnl,
											contrary(Omega,OmegaBar),
											append([[(OmegaBar,off)]],O,O2),     	% off !!! 
											select(Omega,P,P2).				

%  Case 1 (ii) ... Omega is selected from P and is NOT an assumption ... hence S is empty
executeOneIB((P,O,A,C,F), (P2,O,A2,C,F)) :- 	selFuncIB(P,O,F,Omega,[],[]), 
											\+ isAss(Omega), 
											mwrite('CASE 1ii'), mnl,
											findR(Omega,C,R),
											select(Omega,P,PTemp),
											filterR(R,A,FilteredR),			
											append(PTemp,FilteredR,P2),		
											myAss(Ass),
											intersectLists(Ass,R,InterSected),
 											append(A,InterSected,A2). 

%  Case 2 (i) b) ... S from O and Omega from S ... Omega is assumption ... not in A, but in C.
executeOneIB((P,O,A,C,F), (P,O2,A,C,F2)) :-	selFuncIB(P,O,F,Omega,[S|STail],[]),
										isAss(Omega),
										\+ member(Omega,A),
										member(Omega,C),
										mwrite('CASE 2ib'), mnl,
										myIBselect([S|STail],O,O2),
										unmark([S|STail],Res),
										append(F,[Res],F2).
										
%  Case 2 (i) c) 1) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
executeOneIB((P,O,A,C,F), (P2,O2,A,C2,F2)) :-	selFuncIB(P,O,F,Omega,[S|STail],[]),
										isAss(Omega),
										\+ member(Omega,A),
										\+ member(Omega,C),
										contrary(Omega,OmegaBar),
										\+ isAss(OmegaBar),
										mwrite('CASE 2ic1'), mnl,
										myIBselect([S|STail],O,O2),
										append(P,[OmegaBar],P2),
										append(C,[Omega],C2),
										unmark([S|STail],Res),
										append(F,[Res],F2).

%  Case 2 (i) c) 2) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
executeOneIB((P,O,A,C,F), (P,O2,A2,C2,F2)) :-	selFuncIB(P,O,F,Omega,[S|STail],[]),
										isAss(Omega),
										\+ member(Omega,A),
										\+ member(Omega,C),
										contrary(Omega,OmegaBar),
										isAss(OmegaBar),
										mwrite('CASE 2ic2'), mnl,
										myIBselect([S|STail],O,O2),
										append(A,[OmegaBar],A2),
										append(C,[Omega],C2),
										unmark([S|STail],Res),
										append(F,[Res],F2).

%  Case 2 (i) a) ... S from O and Omega from S ... Omega is assumption ... and ignored.
executeOneIB((P,O,A,C,F), (P,O2,A,C,F)) :- 	selFuncIB(P,O,F,Omega,[S|STail],[]),
										isAss(Omega),
										mwrite('CASE 2ia'), mnl,
										myIBselect([S|STail],O,OTemp),
										mark(Omega,[S|STail],Res),
										append(OTemp,[Res],O2).


%  Case 2 (ii) ... S from O and Omega from S ... Omega is NOT an assumption
executeOneIB((P,O,A,C,F), (P,O2,A,C,F2)) :-	selFuncIB(P,O,F,Omega,[S|STail],[]), 
										\+ isAss(Omega),
										mwrite('CASE 2ii'), mnl,
										myIBselect([S|STail],O,OTemp),
										constructLastCaseIBO([S|STail],Omega,C,OTempRHS), % CHANGED !
										append(OTemp,OTempRHS,O2),
										constructLastCaseIBF([S|STail],Omega,C,FTempRHS),
										append(F,FTempRHS,F2).
										
%  Case 3 ... S is selected in F ...
executeOneIB((P,O,A,C,F),(P,O,A,C,F2)) :-	selFuncIB(P,O,F,noOmega,[],S),
										mwrite('CASE 3'), mnl,
										myCallFail(S),
										select(S,F,F2).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
allMarked([]).
allMarked([(_,on)|Tail]) :- allMarked(Tail).


mark(_,[],[]).
mark(Omega,[(Omega,off)|Tail],[(Omega,on)|T2]) :- mark(Omega,Tail,T2). 
mark(Omega,[(Omega,on)|Tail],[(Omega,on)|T2]) :- mark(Omega,Tail,T2). 	
mark(Omega,[(NotOmega,Mark)|Tail],[(NotOmega,Mark)|T2]) :- Omega \== NotOmega, mark(Omega,Tail,T2).	

unmark([],[]).
unmark([(X,on)|Tail],[X|Res]) :- unmark(Tail,Res).
unmark([(X,off)|Tail],[X|Res]) :- unmark(Tail,Res).

turnIntoUnmarkedList([],[]).
turnIntoUnmarkedList([H|T],[(H,off)|Res]) :- turnIntoUnmarkedList(T,Res).


constructLastCaseIBO(S,Omega,C,Return) :- findall(X,(myRule(Omega,RHS), 
												intersectLists(C,RHS,[]),
												turnIntoUnmarkedList(RHS,RHSunmarked),
												select((Omega,_),S,STemp),
												append(STemp,RHSunmarked,X),
												X \== [])    ,Return).

constructLastCaseIBF(S,Omega,C,Return) :- findall(X,(myRule(Omega,RHS), 
												\+ intersectLists(C,RHS,[]),
												select((Omega,_),S,STemp),
												append(STemp,RHS,X), 
												X \== [])    ,Return).


%% [S|STail] no longer in right order to be removed from O to give O2 ... %%%%%
%myIBselect(X,Y,Z) :- 	member(X,Y), select(X,Y,Z),!.
%myIBselect(X,Y,Z) :-	\+ member(X,Y), permutation(X,X2), member(X2,Y), myIBselect(X2,Y,Z),!.
%myIBselect(_,_,_) :- write('BAD THINGS HAVE HAPPENED in myIBselect'), nl.	

% [S|STail] no longer in right order to be removed from O to give O2 ... %%%%%
myIBselect(X,Y,Z) :- 	member(X,Y),select(X,Y,Z).
myIBselect(X,Y,Z) :-	\+ member(X,Y), permutation(X,X2), write('GGG'), member(X2,Y), myIBselect(X2,Y,Z).
%myIBselect(_,_,_) :- write('BAD THINGS HAVE HAPPENED in myIBselect'), nl.	


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

toBeProved(X) :- user:toBeProved(X).
myAss(X) :- user:myAss(X).
contrary(X,Y) :- user:contrary(X,Y).
myRule(X,Y) :- user:myRule(X,Y).