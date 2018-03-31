hasCapability(X,A,D0) :- prove([hasCapability(X,A)], D0).
hasMotive(X,A,D1) :- prove([hasMotive(X,A)], D1).
governmentLinked(P,X,D2) :- prove([governmentLinked(P,X)], D2).

goal(A, M, X, D0, D1, D2) :- 
  (hasCapability(X,A,D0), writeToFile(hasCapability(X,A), 0); \+ hasCapability(X,A,D0), write(neg(hasCapability(X,A)))), nl,
  (hasMotive(X,A,D1), writeToFile(hasMotive(X,A), 1); \+ hasMotive(X,A,D1), write(neg(hasMotive(X,A)))), nl,
  (governmentLinked(P,X,D2), writeToFile(governmentLinked(P,X), 2); \+ governmentLinked(P,X,D2), write(neg(governmentLinked(P,X)))), nl.