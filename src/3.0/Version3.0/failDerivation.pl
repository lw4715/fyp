:-module(failDerivation,[myCallFail/1]).

:- use_module(library(lists)).
:- use_module(helperFunctions).
:- use_module(screenWriting).


myCallFail(S) :- 	myAss(Ass), intersectLists(Ass,S,Int), 
					writeQuadList([(S,[],Int,[])]), executeFail([(S,[],Int,[])]),!. 

executeFail([]) 		:- mwrite('Finished FAIL dd ...'), mnl,mnl.
executeFail([LH|LTail])	:- 	selectQuad([LH|LTail],Quad),
							executeOneF([LH|LTail],Quad,L2),
							writeQuadList(L2), 
							executeFail(L2). 


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Basically just going though the cases ... FAIL DISPUTE DERIVATIONS ...               %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

selectQuad([Quad|_],Quad). 
selectQuad([],noQuad) :- write('FINISHED FAIL-dd ... list is empty').

selectFromQuad(([Omega|_],_,_,_),Omega,[]).  % omega chosen from P
selectFromQuad(([],[[Omega|STail]|_],_,_),Omega,[Omega|STail]).
selectFromQuad(([],[[]|_],_,_),noOmega,[]). % :- write('Removing the []-[] case ... noOmega'), nl.


% Case 1a) 		WE DONT HAVE THIS YET, since O is only chosen when P = [] ... hence O = [] fails
executeOneF(List,Quad,LOut) :-		selectFromQuad(Quad,noOmega,[]),
									mwrite('Fail - CASE 1a'), mnl,
									select(Quad,List,LOut).

% Case 1bi)
executeOneF(List,(P,O,A,C),LOut) :-	selectFromQuad((P,O,A,C), Omega, [S|STail]),
									\+ isAss(Omega),
									mwrite('Fail - CASE 1bi'), mnl,
									select((P,O,A,C),List,List2),
										select([S|STail],O,OTemp),
										constructLastCaseOFail([S|STail],Omega,C,OTempRHS), 
										append(OTemp,OTempRHS,O2),
									append(List2,[(P,O2,A,C)],LOut).		

% Case 1biiCase1)
executeOneF(List,(P,O,A,C),LOut) :-	selectFromQuad((P,O,A,C), Omega, [S|STail]),
									isAss(Omega),
									\+ member(Omega,A),
									mwrite('Fail - CASE 1bii1'), mnl,
									select((P,O,A,C),List,List2),
										select([S|STail],O,OTemp),
										select(Omega,[S|STail],STemp),
										append(OTemp,[STemp],O2),																
									append(List2,[(P,O2,A,C)],LwithQ0),
									doWeirdCase(Omega,[S|STail],(P,O,A,C),ReturnQuad),
									append(LwithQ0,[ReturnQuad],LOut).			
									
% Case 1biiCase2)
executeOneF(List,(P,O,A,C),LOut) :-	selectFromQuad((P,O,A,C), Omega, [S|STail]),
									isAss(Omega),
									member(Omega,A),
									mwrite('Fail - CASE 1bii2'), mnl,
									select((P,O,A,C),List,List2),
										select([S|STail],O,OTemp),
										select(Omega,[S|STail],STemp),
										append(OTemp,[STemp],O2),																
									append(List2,[(P,O2,A,C)],LOut).	

% Case 2a)
executeOneF(List,(P,O,A,C),LOut) :- 	selectFromQuad((P,O,A,C), Omega, []),
							isAss(Omega),
							mwrite('Fail - CASE 2a'), mnl,
							select((P,O,A,C),List,List2),
								contrary(Omega,OmegaBar),
								append([[OmegaBar]],O,O2),     	 
								select(Omega,P,P2),
							append(List2,[(P2,O2,A,C)],LOut).

% Case 2b)
executeOneF(List,(P,O,A,C),LOut) :- 	selectFromQuad((P,O,A,C), Omega, []),
							\+ isAss(Omega),
							mwrite('Fail - CASE 2b'), mnl,
							select((P,O,A,C),List,List2),
								generateQuadList((P,O,A,C),Omega,GeneratedQuadList),
							append(List2,GeneratedQuadList,LOut).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

doWeirdCase(Omega,S,(P,O,A,C),(P,O2,A,C)) :- 	member(Omega,C), select(S,O,O2).
doWeirdCase(Omega,S,(P,O,A,C),(P2,O2,A,C2)) :- 	\+ member(Omega,C),
												contrary(Omega,OmegaBar),
												\+ isAss(OmegaBar),
												select(S,O,O2),
												append(P,[OmegaBar],P2),
												append(C,[Omega],C2).
doWeirdCase(Omega,S,(P,O,A,C),(P,O2,A2,C2)) :- 	\+ member(Omega,C),
												contrary(Omega,OmegaBar),
												isAss(OmegaBar),
												select(S,O,O2),
												append(A,[OmegaBar],A2),
												append(C,[Omega],C2).

generateQuadList((P,O,A,C),Omega,Ret) :- findall( (P2,O,A2,C), 
											(	myRule(Omega,R),
												select(Omega,P,PTemp),
												filterR(R,A,FilteredR),			% NEW !
												append(PTemp,FilteredR,P2),		% CHANGED !
												myAss(Ass),
												intersectLists(Ass,R,InterSected),
 												append(A,InterSected,A2)	  ),
											Ret ).

constructLastCaseOFail(S,Omega,C,Return) :- findall(X,(myRule(Omega,RHS), 
												intersectLists(C,RHS,[]),
												select(Omega,S,STemp),
												append(STemp,RHS,X)), Return).
%%%% note, here we do allow for [] to be added as an element of Return ... %%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

toBeProved(X) :- user:toBeProved(X).
myAss(X) :- user:myAss(X).
contrary(X,Y) :- user:contrary(X,Y).
myRule(X,Y) :- user:myRule(X,Y).
