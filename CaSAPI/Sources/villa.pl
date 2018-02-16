myRule(modified(villa),[not(def(r2(villa)))]).
myRule(notmodified(villa),[not(def(r1(villa)))]).
myRule(def(r1(villa)),[not(def(t(villa,villa))),not(def(r2(villa)))]).
myRule(def(r2(villa)),[not(def(r3(villa,villa))),not(def(r1(villa)))]).
myRule(def(t(villa,villa)),[not(def(t((villa,villa),(villa,villa)))),not(def(r3(villa,villa)))]).

myAss([not(def(r1(villa))), not(def(r2(villa))), not(def(r3(villa,villa))), not(def(t(villa,villa))), not(def(t((villa,villa),(villa,villa))))]).

toBeProved([notmodified(villa)]).

contrary(not(X),X) :- !.
contrary(X,not(X)).

resultingDefenseSets([[not(def(r1(villa))),not(def(r3(villa,villa))),not(def(t((villa,villa),(villa,villa))))]]).
