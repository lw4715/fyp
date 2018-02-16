:-module(helperFunctions,[isAss/1,intersectLists/3,myListDiff/3,findR/3,filterR/3]).

:- use_module(library(lists)).

myListDiff([],_,[]). 
myListDiff([H|T],TakeAwayList,Res) :- member(H,TakeAwayList), myListDiff(T,TakeAwayList,Res). 
myListDiff([H|T],TakeAwayList,[H|Res]) :- \+ member(H,TakeAwayList), myListDiff(T,TakeAwayList,Res). 
 
intersectLists([],_,[]).
intersectLists([H|T],L,[H|Temp]) :- member(H,L), intersectLists(T,L,Temp).
intersectLists([H|T],L,Temp) :- \+ member(H,L), intersectLists(T,L,Temp).

isAss(X) :- myAss(A), member(X,A).

findR(Omega,C,R) :- myRule(Omega,R), intersectLists(C,R,[]).

filterR([],_,[]). 
filterR([R|Rs],Ass,Temp) :- member(R,Ass), filterR(Rs,Ass,Temp).
filterR([R|Rs],Ass,[R|Temp]) :- \+ member(R,Ass), filterR(Rs,Ass,Temp).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

myAss(X) :- user:myAss(X).
myRule(X,Y) :- user:myRule(X,Y).