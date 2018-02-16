myRule(punish,[prison]).
myRule(punish,[fine]).
myRule(punish,[service]).
myRule(deter,[prison,a]).
myRule(deter,[fine,a]).
myRule(not(deter),[service,b]).
myRule(rehab,[service,c]).
myRule(not(rehab),[prison,d]).
myRule(protect,[prison]).

myAss(a).
myAss(b).
myAss(c).
myAss(d).
myAss(prison).
myAss(fine).
myAss(service).

toBeProved([punish,deter]).

contrary(a,not(deter)).
contrary(b,deter).
contrary(c,not(rehab)).
contrary(d,rehab).

contrary(prison,fine).
contrary(prison,service).
contrary(fine,prison).
contrary(fine,service).
contrary(service,fine).
contrary(service,prison).

resultingDefenseSets([[prison,a]]).
