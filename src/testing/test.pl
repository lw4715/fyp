pr(X,Y) :-p(X,Y).
pr(X, Z):-  p(X,Y), p(Y,Z).
p(a,b).
p(b,c).
p(c,d).
p(a,s).
