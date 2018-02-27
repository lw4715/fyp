rule(f0, industry(nuclear,v), []).
rule(f1, target(v,attack), []).
rule(f2, infectionMethod(usb,attack), []).
rule(f3, spreadingMechanism(localNetwork,attack), []).
rule(f4, stolenValidSignedCertificates(attack), []).
rule(f6, target(iran,attack), []).
rule(f7, usesZeroDayVulnerabilities(stuxnet), []).
rule(f8, recentNewsInYear(nuclearProgram,iran, 2010), []).
rule(f9, countriesAgainstTargetForReason([usa, israel], iran, nuclearProgram), []).
rule(f10, attackYear(attack, 2010), []).