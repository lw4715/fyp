myRule(payment,[goodJob]).
myRule(badJob,[tooLateJob]).
myRule(badJob,[incompleteJob]).
myRule(incompleteJob,[delivered, not(accordingToSpec)]).
myRule(accordingToSpec,[reqA,reqB]).
myRule(delivered,[]).
myRule(not(reqB),[]).

myAsm([goodJob,not(accordingToSpec),reqA,reqB]).

toBeProved([payment]).

contrary(goodJob,badJob).
contrary(not(accordingToSpec),accordingToSpec).
contrary(reqA,not(reqA)).
contrary(reqB,not(reqB)).
