%% stuxnet
highLevelSkill(Att) :- stolenValidSignedCertificates(Att).
specificTarget(Att) :- specificConfigInMalware(M), malwareUsedInAttack(M, Att).
sophisticatedMalware(M) :- usesZeroDayVulnerabilities(M).

industry(nuclear, v).
target(v, attack).
infectionMethod(usb, attack).
spreadingMechanism(localNetwork, attack).
stolenValidSignedCertificates(attack).
sophisticated(stuxnet).
target(iran, attack).
usesZeroDayVulnerabilities(stuxnet).

recentNewsInIndustry(nuclear).


