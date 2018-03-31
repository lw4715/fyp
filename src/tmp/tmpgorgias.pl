rule(0, highLevelSkill(Att), [stolenValidSignedCertificates(Att)]).
rule(1, specificTarget(Att), [specificConfigInMalware(M),malwareUsedInAttack(M,Att)]).
rule(2, sophisticatedMalware(M), [usesZeroDayVulnerabilities(M)]).
