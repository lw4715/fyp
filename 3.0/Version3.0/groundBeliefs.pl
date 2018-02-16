:-module(groundBeliefs,[runGB/2]).

:- use_module(library(lists)).
:- use_module(helperFunctions).
:- use_module(screenWriting).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% The simplest of the three dispute derivations %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

runGB :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '), 
			writeQuad(P,[],A0,[]), executeGB(P, [], A0, [], 1). 
runGBall :-	toBeProved(P), myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '), 
			writeQuad(P,[],A0,[]), executeGBall(P, [], A0, [], 1). 


runGB(s,1) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runGB.
runGB(n,1) :-	nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runGB.

runGB(s,a) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runGBall.
runGB(n,a) :-	nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runGBall.

executeGB([],[],A,_,_) :- write('FINISHED, the defence set is: '), write(A), nl, nl.
executeGB(A,B,C,D,N) :- executeOneGB((A,B,C,D),(A2,B2,C2,D2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeQuad(A2,B2,C2,D2), 
					executeGB(A2,B2,C2,D2,N1). 

executeGBall([],[],A,_,_) :- write('FINISHED, one defence set is: '), write(A), nl, nl, fail.
executeGBall(A,B,C,D,N) :- executeOneGB((A,B,C,D),(A2,B2,C2,D2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeQuad(A2,B2,C2,D2), 
					executeGBall(A2,B2,C2,D2,N1). 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Basically just going though the cases ... GB DISPUTE DERIVATIONS ...                 %%%
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
executeOneGB((P,O,A,C), (P2,O2,A,C)) :- 	selFunc(P,O,Omega,[]), 
										isAss(Omega), 
										mwrite('CASE 1i'), mnl,
%										contrary(Omega,OmegaBar),
										findall([X], contrary(Omega,X), ListListContraries),
										append(ListListContraries,O,O2),     	% ORDER !!! 
%										append([[OmegaBar]],O,O2),     	% ORDER !!! 
										select(Omega,P,P2).				% DUPLICATES ??

%  Case 1 (ii) ... Omega is selected from P and is NOT an assumption ... hence S is empty
executeOneGB((P,O,A,C), (P2,O,A2,C)) :- 	selFunc(P,O,Omega,[]), 
										\+ isAss(Omega), 
										mwrite('CASE 1ii'), mnl,
										findR(Omega,C,R),
										select(Omega,P,PTemp),
										append(PTemp,R,P2),
										myAss(Ass),
										intersectLists(Ass,R,InterSected),
 										append(A,InterSected,A2). 

  
% Case 2 (i) b) ... S from O and Omega from S ... Omega is assumption ... and not in A.
executeOneGB((P,O,A,C), (P2,O2,A2,C2)) :-	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										\+ member(Omega,A),
										mwrite('CASE 2ib'), mnl,
										contrary(Omega,OmegaBar),
%										findall(X, contrary(Omega,X), ListContraries),
										select([S|STail],O,O2),
										append(P,[OmegaBar],P2),
										append(C,[Omega],C2),
										myAss(Ass),
										intersectLists(Ass,[OmegaBar],ATemp),
										append(A,ATemp,A2).

% Case 2 (i) a) ... S from O and Omega from S ... Omega is assumption ... and ignored.
executeOneGB((P,O,A,C), (P,O2,A,C)) :- 	selFunc(P,O,Omega,[S|STail]),
										isAss(Omega),
										mwrite('CASE 2ia'), mnl,
										select([S|STail],O,OTemp),
										select(Omega,[S|STail],STemp),
										append(OTemp,[STemp],O2).


% Case 2 (ii) ... S from O and Omega from S ... Omega is NOT an assumption
executeOneGB((P,O,A,C), (P,O2,A,C)) :-	selFunc(P,O,Omega,[S|STail]), 
										\+ isAss(Omega),
										mwrite('CASE 2ii'), mnl,
										select([S|STail],O,OTemp),
										constructLastCaseGB([S|STail],Omega,OTempRHS),
										append(OTemp,OTempRHS,O2).


constructLastCaseGB(S,Omega,Return) :- findall(X,(myRule(Omega,RHS), 
												select(Omega,S,STemp),
												append(STemp,RHS,X), X \== []),Return).  


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

toBeProved(X) :- user:toBeProved(X).
myAss(X) :- user:myAss(X).
contrary(X,Y) :- user:contrary(X,Y).
myRule(X,Y) :- user:myRule(X,Y).