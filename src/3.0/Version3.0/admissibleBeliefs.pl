:-module(admissibleBeliefs,[runAB/2]).

:- use_module(library(lists)).
:- use_module(helperFunctions).
:- use_module(screenWriting).

runAB :-	toBeProved(P), 
 findall(infoTerm(X, localGoal(X), attacking(nothing)) , member(X,P) , AnnotatedP), 
 user:retractall(argnumber(_)), user:assert(argnumber(0)),
myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeStructQuad(AnnotatedP,[],A0,[],[],[]), executeAB(AnnotatedP, [], A0, [], [], [], 1). 

runABall :-	toBeProved(P), 
 findall(infoTerm(X, localGoal(X), attacking(nothing)) , member(X,P) , AnnotatedP), 
 user:retractall(argnumber(_)), user:assert(argnumber(0)),
myAss(Ass), intersectLists(Ass,P,A0), mwrite('Step 0: '),
			writeStructQuad(AnnotatedP,[],A0,[],[],[]), executeABall(AnnotatedP, [], A0, [], [], [], 1). 

% I need to structure what I place into P initially ... later equally for O ... 
%HERE1: Maybe at this stage: if toBeProved(p), put extraInfo(p,p,_). 1st para is current term, second is localGoal which
% tells us, why we are proving the first one ... 3rd argument is telling us, what this would attack if successful ...

% each term p in P is: infoTerm(p, localGoal(p), attacking(nothing)).
% findall(infoTerm(X, localGoal(X), attacking(nothing)) , member(X,P) , Annotated), 

runAB(s,1) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runAB.
runAB(n,1) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runAB.

runAB(s,a) :- nl, write('Executing in silent mode!'), nl, nl, user:assert(silent), runABall.
runAB(n,a) :- nl, write('Executing in noisy mode!'), nl, nl, user:retractall(silent), runABall.

executeAB([],[],A,_,_,_,_) :- write('FINISHED, the defence set is: '), write(A), nl, nl.
executeAB(A,B,C,D,Arg,Rel,N) :- executeOneAB((A,B,C,D,Arg,Rel),(A2,B2,C2,D2,Arg2,Rel2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeStructQuad(A2,B2,C2,D2,Arg2,Rel2), 
					executeAB(A2,B2,C2,D2,Arg2,Rel2,N1). 

executeABall([],[],A,_,_,_,_) :- write('FINISHED, one defence set is: '), write(A), nl, nl, fail.
executeABall(A,B,C,D,Arg,Rel,N) :- executeOneAB((A,B,C,D,Arg,Rel),(A2,B2,C2,D2,Arg2,Rel2)),
					mwrite('Step '), mwrite(N), mwrite(': '), N1 is N + 1,
					writeStructQuad(A2,B2,C2,D2,Arg2,Rel2), 
					executeABall(A2,B2,C2,D2,Arg2,Rel2,N1). 



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Okay, here we are using two things to determine the case we are in: one is Omega (which really should be Sigma) 
%%% and the second is the structure of the fourth argument.  It holds the set from O from which Omega was chosen. 
%%% If it is empty, we have chosen from P ... and is isAss(Omega) to determine the case (1(i) or 1(ii)).
%%% If it is non-empty, we have chosen from O. If isAss(Omega) is true, we are in case 2(ii) else:
%%% if Omega is not a known culprit, we are in case 2(i)(c), if it is a known culprit, we are in 2(i)(b) ... or
%%% ignore in 2(i)(a).
%%% 
%%% Both of these things were returned by selFunc and that was sub-optimal.  I suggest using a selection "method" which 
%%% determines whether to choose Omega from P or O and subsequently, one of two selection functions chooses the Omega from 
%%% the given set (either P or O) ... call these functions: selectionFromP and selectionFromO.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Simple selection method: choose from P as long as P is non-empty, else from O        %%%
%%% Frist two args: input P and O ... third arg: output binary decision			 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
selectionMethod([_|_],_,selectFromP).
selectionMethod([],_,selectFromO). 



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Patient selection function applicable when one chooses from P			 %%%
%%% First arg: input P ... second arg: output Omega					 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%selectionFromP([H|_],H) 	:- \+ isAss(H).
%selectionFromP([H|T],Omega) 	:- isAss(H), containsNonAss(T), selectionFromP(T,Omega). 
%selectionFromP([H|T],H) 	:- isAss(H), \+ containsNonAss(T).

selectionFromP([infoTerm(H,G,A)|_],H,infoTerm(H,G,A)) 	:- \+ isAss(H).
selectionFromP([infoTerm(H,_,_)|T],Omega,RetTerm) 	:- isAss(H), containsNonAss(T), selectionFromP(T,Omega,RetTerm). 
selectionFromP([infoTerm(H,G,A)|T],H,infoTerm(H,G,A)) 	:- isAss(H), \+ containsNonAss(T).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Patient selection function applicable when one chooses from O			 %%%
%%% First arg: input O ...								 %%% 
%%% second arg: output Omega ... 							 %%%
%%% third arg: output S from which Omega originates					 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
selectionFromO([[infoTerm(O,G,AT)|OT]|_],O,[infoTerm(O,G,AT)|OT], infoTerm(O,G,AT)) 	:- \+isAss(O). 
selectionFromO([[infoTerm(O,_,_)|OT]|Tail],Omega,List,OTerm):- isAss(O), containsNonAss(OT), selectionFromO([OT|Tail],Omega,List,OTerm). 
selectionFromO([Os|Tail],Omega,List,OTerm) 	:- 	\+ containsNonAss(Os), 
						containsElementWithNonAss(Tail), 
						selectionFromO(Tail, Omega, List,OTerm). 
selectionFromO([[infoTerm(O,G,AT)|OT]|Tail],O,[infoTerm(O,G,AT)|OT],infoTerm(O,G,AT)) 	:- isAss(O), \+ containsNonAss(OT), \+ containsElementWithNonAss(Tail). 



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Basically just going though the cases ... AB DISPUTE DERIVATIONS ...                 %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%  Case 1 (i) ... Omega is selected from P and is an assumption ... hence S is empty
executeOneAB((P,O,A,C,Arg,Rel), ([],O2,A,C,Arg2,Rel2)) :- 	 
 					 	selectionMethod(P,O,selectFromP),
						selectionFromP(P,Omega,infoTerm(_,localGoal(G),attacking(AT))),	
						isAss(Omega), 
						mwrite('CASE 1i'), mnl,
						user:retract(argnumber(N)),
						N1 is N + 1,
						user:assert(argnumber(N1)),
						getAssumptionsFromTermList(P,AssList),						
						append(Arg, [argument(N1,AssList,G)] ,Arg2),
					% if attacking is non-empty, add something top Rel.
						constructPossibleAttackRel(AT,N1,Rel,RelT),
					% construct the second half of the Rel2 bit
						construct2ndRelPart(Arg,Omega,RelT,Rel2,N1),
						findall([X], (member(M,AssList),contrary(M,X)), ListListContraries),
						equipNewOsWithExtraInfo(ListListContraries, N1, AnnotatedLLCon),
						append(AnnotatedLLCon,O,O2). 


% this case 1I changed dramatically.  once all elements of P are assumptions, find all contraries of all of them ...

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Problem:  if nothing to retract, we fail here ... maybe need a clone copy of this case with Arg2=Arg		
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Also note, that a and c are assumptions in NewT2, but have no contraries defined for them        %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%  Case 1 (ii) ... Omega is selected from P and is NOT an assumption ... hence S is empty
executeOneAB((P,O,A,C,Arg,Rel), (P2,O,A2,C,Arg2,Rel2)) :- 
 				 	selectionMethod(P,O,selectFromP),
					selectionFromP(P,Omega,PTerm),	
					\+ isAss(Omega), 
					mwrite('CASE 1ii'), mnl,
					findR(Omega,C,R),
	% if R is [] then construct trivial arg from PTerm
					constructTrivialArg(R,PTerm,Arg,Rel,ArgTmp,RelTmp),
	% if R is in Ai then construct non-trivial argument.
					constructNonTrivialArgument(A,R,PTerm,ArgTmp,RelTmp,Arg2,Rel2),
					select(PTerm,P,PTemp),
					filterR(R,A,FilteredR),			% NEW !
					equipNewPsWithExtraInfo(FilteredR,PTerm,AnnotatedFilteredR),
					append(PTemp,AnnotatedFilteredR,P2),		% CHANGED !
					myAss(Ass),
					intersectLists(Ass,FilteredR,InterSected),
 					append(A,InterSected,A2). 
% fileredR works, but the intersectList() takes R rather than filteredR ... check theory ...

%  Case 2 (i) b) ... S from O and Omega from S ... Omega is assumption ... not in A, but in C.
executeOneAB((P,O,A,C,Arg,Rel), (P,O2,A,C,Arg2,Rel2)) :-	
 				 	selectionMethod(P,O,selectFromO),
					selectionFromO(O,Omega,S,infoTerm(_,localGoal(G),attacking(AT))),	
					isAss(Omega),
					\+ member(Omega,A),
					member(Omega,C),
					mwrite('CASE 2ib'), mnl,
					user:retract(argnumber(N)),
					N1 is N + 1,
					user:assert(argnumber(N1)),
					getAssumptionsFromTermList(S,AssList),						
					append(Arg, [argument(N1,AssList,G)] ,Arg2),
					append(Rel,[attacks(N1,AT)],Rel2),
					select(S,O,O2).
			
%  Case 2 (i) c) 1) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
%executeOneAB((P,O,A,C,Arg,Rel), (P2,O2,A,C2,Arg2,Rel2)):-	
%
%					\+ isAss(OmegaBar),
%					mwrite('CASE 2ic1'), mnl,
%					user:retract(argnumber(N)),
%					N1 is N + 1,
%					user:assert(argnumber(N1)),
%					append(Arg, [argument(N1,AssList,G)] ,Arg2),
%					append(Rel, [attacks(N1,AT)], Rel2),
% now append P not only with OmegaBar, but with contraries of other elements in S as well (one at a time / baktrak).
%					append(P,[infoTerm(OmegaBar,localGoal(OmegaBar),attacking(N1))],P2).       
%
%  Case 2 (i) c) 2) ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
%executeOneAB((P,O,A,C,Arg,Rel), (P,O2,A2,C2,Arg2,Rel2)):-	
%
%					isAss(OmegaBar),
%					\+ member(OmegaBar,C),   
%					mwrite('CASE 2ic2'), mnl,
%					user:retract(argnumber(N)),
%					N1 is N + 1,
%					append(Arg, [argument(N1,AssList,G)] ,ArgTmp),
%					append(Rel, [attacks(N1,AT)], RelTmp),
%					noDupAppend(A,[OmegaBar],A2),
%					N2 is N1 + 1,
%					user:assert(argnumber(N2)),
%					append(ArgTmp, [argument(N2,[OmegaBar],OmegaBar)] ,Arg2),
%					append(RelTmp, [attacks(N2,N1)], Rel2).


%  Case 2 (i) c) merged ... S from O and Omega from S ... Omega is assumption ... not in A, not in C.
executeOneAB((P,O,A,C,Arg,Rel), (P2,O2,A,C2,Arg2,Rel2)):-	
 				 	selectionMethod(P,O,selectFromO),
					selectionFromO(O,Omega,S,infoTerm(_,localGoal(G),attacking(AT))),	
					isAss(Omega),
					\+ member(Omega,A),
					\+ member(Omega,C),
					mwrite('CASE 2icM'), mnl,
					append(C,[Omega],C2),
					select(S,O,O2),
					user:retract(argnumber(N)),
					N1 is N + 1,
					user:assert(argnumber(N1)),
					contrary(Omega,OmegaBar),
					append(P,[infoTerm(OmegaBar,localGoal(OmegaBar),attacking(N1))],P2),
					getAssumptionsFromTermList(S,AssList),
					append(Arg, [argument(N1,AssList,G)] ,Arg2),
					append(Rel, [attacks(N1,AT)], Rel2).			
%					noDupAppend(A,[OmegaBar],A2),
%					append(ArgTmp, [argument(N2,[OmegaBar],OmegaBar)] ,Arg2),
%					append(RelTmp, [attacks(N2,N1)], Rel2).


%  Case 2 (i) a) ... S from O and Omega from S ... Omega is assumption ... and ignored.
executeOneAB((P,O,A,C,Arg,Rel), (P,O2,A,C,Arg,Rel)) :- 	
 				 	selectionMethod(P,O,selectFromO),
					selectionFromO(O,Omega,S,_),	
					isAss(Omega),
					mwrite('CASE 2ia'), mnl,
					select(S,O,OTemp),
					select(Omega,S,STemp),
					append(OTemp,[STemp],O2).

%  Case 2 (ii) ... S from O and Omega from S ... Omega is NOT an assumption
executeOneAB((P,O,A,C,Arg,Rel), (P,O2,A,C,Arg2,Rel2)) :-	
 				 	selectionMethod(P,O,selectFromO),
					selectionFromO(O,Omega,S,infoTerm(Bob,localGoal(G),attacking(AT))),	
					\+ isAss(Omega),
					mwrite('CASE 2ii'), mnl,
					select(S,O,OTemp),
					constructLastCaseAB(S,Omega,C,OTempRHS,infoTerm(Bob,localGoal(G),attacking(AT))), % CHANGED !
%HERE: we need to be clever.  when constructing the new O2, copy the localGoal and attackingInfo
					append(OTemp,OTempRHS,O2), %.
% Hmm, the Omega here is really an infoTerm construct ... hence the constryctLastCaseAB does not work ...  
% IMPLEMENT ARG AND REL NOW:
% if an applicable rule is found with R is empty and Omega was the last thing in O/S, then add an argument with [] as LHS 
					case2iiArgRelHelper(Arg,Arg2,Rel,Rel2,Omega,S,infoTerm(Bob,localGoal(G),attacking(AT))).


constructLastCaseAB(S,Omega,C,Return,OTerm) :- findall(X,(myRule(Omega,RHS), 
					intersectLists(C,RHS,[]),
					select(OTerm,S,STemp),   
%normally, things in STemp should be annotated already ... only RHS needs extra annotation.  for now re-annote all.
					equipRHS(RHS,OTerm,AnnotatedRHS),
%					append(STemp,AnnotatedRHS,X), X \== []),Return).   %CHECK WITH FT...
					append(STemp,AnnotatedRHS,X)),Return).


case2iiArgRelHelper(Arg,Arg2,Rel,Rel2,Omega,S,OTerm)	:- 	myRule(Omega,[]), select(OTerm,S,[]), 
							OTerm = infoTerm(_,localGoal(G),attacking(AT)),
							user:retract(argnumber(N)),
							N1 is N + 1,
							user:assert(argnumber(N1)),												append(Arg,[argument(N1,[],G)],Arg2),
							append(Rel,[attacks(N1,AT)],Rel2),!.
case2iiArgRelHelper(Arg,Arg,Rel,Rel,_,_,_).
%case2iiArgRelHelper(Arg,Arg,Rel,Rel,Omega,S,OTerm)	:- myRule(Omega,X), select(OTerm,S,Y), 
	%						write('BOB'),
	%							(X \== [] ; Y \== []), write('SAM') .
%case2iiArgRelHelper(Arg,Arg,Rel,Rel,Omega,_,_)	:- \+ myRule(Omega,_).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

toBeProved(X) :- user:toBeProved(X).
myAss(X) :- user:myAss(X).
myAss(X) :- user:myAsm(X). 
contrary(X,Y) :- user:contrary(X,Y).
myRule(X,Y) :- user:myRule(X,Y).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

containsNonAss(L) :- member(infoTerm(X,_,_),L), \+ isAss(X).

containsElementWithNonAss(L) :- member(X,L), containsNonAss(X).

%equipNewPsWithExtraInfo(FilteredR,PTerm,AnnotatedFilteredR).
equipNewPsWithExtraInfo([],_,[]).
equipNewPsWithExtraInfo([H|T],infoTerm(PT,localGoal(G),attacking(A)),[infoTerm(H,localGoal(G),attacking(A))|Rest]) :- 
			equipNewPsWithExtraInfo(T,infoTerm(PT,localGoal(G),attacking(A)),Rest).

% each element of the first arg is a singleton list
equipNewOsWithExtraInfo([], _, []).
equipNewOsWithExtraInfo([[H]|T], N1, [ [infoTerm(H, localGoal(H), attacking(N1))] |Rest]) :- equipNewOsWithExtraInfo(T, N1, Rest).

equipRHS([],_,[]).
equipRHS([H|T],infoTerm(X,localGoal(G),attacking(AT)), [infoTerm(H,localGoal(G),attacking(AT))|Rest] ) :- equipRHS(T,infoTerm(X,localGoal(G),attacking(AT)),Rest).

getAssumptionsFromTermList([],[]).	
getAssumptionsFromTermList([infoTerm(P,_,_)|T], [ P |Rest])  :- getAssumptionsFromTermList(T,Rest).						
constructTrivialArg([_|_],_,Arg,Rel,Arg,Rel).
constructTrivialArg([],infoTerm(_,localGoal(G),attacking(AT)),Arg,Rel,Arg2,Rel2) :-
	user:retract(argnumber(N)),
	Num is N + 1,
	user:assert(argnumber(Num)), 
	append(Arg,[argument(Num,[],G)],Arg2), append(Rel,[attacks(Num,AT)],Rel2).

%if R is a non-empty sublist of Ai ...
constructNonTrivialArgument(_,[],_,ArgTmp,RelTmp,ArgTmp,RelTmp).
constructNonTrivialArgument(A,R,_,ArgTmp,RelTmp,ArgTmp,RelTmp) :- \+ sublist(R,A).
constructNonTrivialArgument(A,[SomeH|SomeT],infoTerm(_,localGoal(G),attacking(AT)),ArgTmp,RelTmp,Arg2,Rel2) :- 
	sublist([SomeH|SomeT],A), 
	user:retract(argnumber(N)),
	Num is N + 1,
	user:assert(argnumber(Num)), 
	append(ArgTmp,[argument(Num,[SomeH|SomeT],G)],Arg2), append(RelTmp,[attacks(Num,AT)],Rel2).



constructPossibleAttackRel(nothing,_,Rel,Rel).
constructPossibleAttackRel(AT,N1,Rel,Rel2) :- AT \== nothing, append(Rel,[attacks(N1,AT)],Rel2).

construct2ndRelPart(Arg,Omega,RelT,Rel2,New)	:- 	findall(attacks(New,X),
								(member(argument(X,_,Conclu),Arg),
								contrary(Omega,Conclu)
								), RelAdd),
							append(RelT,RelAdd,Rel2).
    


% if OmegaBar is already in A, then do not add it again, but add another trivial argument and attack.
%complexAppend2ic2(A,OmegaBar,ArgTmp,RelTmp,A2,ArgTmp,RelTmp) :- \+ member(OmegaBar,A), append(A,[OmegaBar],A2).
%complexAppend2ic2(A,OmegaBar,ArgTmp,RelTmp,A2,Arg2,Rel2). %,

noDupAppend(A,[OmegaBar],A):- member(OmegaBar,A).
noDupAppend(A,[OmegaBar],A2):- \+ member(OmegaBar,A), append(A,[OmegaBar],A2).
